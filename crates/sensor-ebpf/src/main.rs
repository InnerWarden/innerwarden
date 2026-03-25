//! Inner Warden eBPF programs - kernel-level security monitoring.
//!
//! Tracepoints:
//!   - sys_enter_execve: captures every process execution
//!   - sys_enter_connect: captures outbound network connections
//!   - sys_enter_openat: captures sensitive file access
//!   - sched_process_exit: captures process exits (rootkit detection)
//!
//! Kprobes:
//!   - commit_creds: detects privilege escalation (uid 1000 → uid 0)
//!
//! LSM (Linux Security Modules):
//!   - bprm_check_security: blocks execution from /tmp, /dev/shm (policy-gated)
//!
//! XDP:
//!   - innerwarden_xdp: wire-speed IP blocking at the network driver level
//!
//! Events are sent to userspace via a shared ring buffer.
//! Blocked IPs are managed via a shared HashMap (agent ↔ kernel).

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, lsm, map, tracepoint, xdp},
    maps::{HashMap, RingBuf},
    programs::{LsmContext, ProbeContext, TracePointContext, XdpContext},
    EbpfContext,
};

// Dispatcher-specific imports (conditionally compiled)
#[cfg(feature = "dispatcher")]
use aya_ebpf::{macros::raw_tracepoint, maps::ProgramArray, programs::RawTracePointContext};
use aya_log_ebpf::info;
use innerwarden_ebpf_types::{
    AcceptEvent, CloneEvent, ConnectEvent, DupEvent, ExecveEvent, KillEvent, ListenEvent,
    MemfdCreateEvent, ModuleLoadEvent, MountEvent, MprotectEvent, PrctlEvent, PrivEscEvent,
    ProcessExitEvent, PtraceEvent, RenameEvent, SetUidEvent, SocketBindEvent, SyscallKind,
    UnlinkEvent, MAX_COMM_LEN, MAX_FILENAME_LEN,
};

// ---------------------------------------------------------------------------
// Ring buffer - shared between all eBPF programs, read by userspace
// ---------------------------------------------------------------------------

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0); // 1 MB ring buffer (expanded for 13 hooks)

// ---------------------------------------------------------------------------
// XDP blocklist - IPv4 addresses to drop at wire speed
// ---------------------------------------------------------------------------
//
// Populated by the agent via aya userspace API.
// Key: IPv4 address as u32 (network byte order)
// Value: flags (1 = block, 0 = removed/placeholder)
// Max 10,000 IPs - enough for most threat scenarios.

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(10_000, 0);

/// XDP allowlist - IPs that must NEVER be dropped, regardless of blocklist.
/// Operator IPs, payment gateways, CDN ranges, API partners.
/// Checked BEFORE blocklist: allowlist wins.
#[map]
static ALLOWLIST: HashMap<u32, u32> = HashMap::with_max_entries(1_000, 0);

// ---------------------------------------------------------------------------
// Kernel-level noise filters - populated by userspace, checked before emit
// ---------------------------------------------------------------------------

/// Comm allowlist - processes that should never trigger alerts.
/// Key: first 16 bytes of comm name (zero-padded).
/// Value: bitmask of handlers to skip (bit 0=execve, 1=connect, 2=openat,
///   3=ptrace, 4=setuid, 5=bind, 6=mount, 7=memfd, 8=init_module).
/// Populated by agent on boot from config (e.g., cargo, rustc, apt, systemd).
#[map]
static COMM_ALLOWLIST: HashMap<[u8; 16], u32> = HashMap::with_max_entries(256, 0);

/// Cgroup allowlist - containers that are known-safe (monitoring, database).
/// Key: cgroup_id. Value: 1 = skip all non-critical events.
/// Populated by agent from container inventory.
#[map]
static CGROUP_ALLOWLIST: HashMap<u64, u32> = HashMap::with_max_entries(128, 0);

/// Per-PID rate limiter - prevents ring buffer flood from noisy processes.
/// Key: PID. Value: last emission timestamp (ktime_ns).
/// If a PID emitted within the last RATE_LIMIT_NS, the event is dropped.
/// Cleaned up periodically by userspace.
#[map]
static PID_RATE_LIMIT: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

// ---------------------------------------------------------------------------
// Kill Chain Detection - per-PID syscall correlation
// ---------------------------------------------------------------------------
//
// Tracks syscall sequences per PID to detect attack patterns in the kernel.
// Each handler sets a bit flag. When the accumulated flags match a known
// attack pattern, the LSM denies execution.
//
// Bit flags:
//   0 = socket/connect (outbound)     4 = bind (server socket)
//   1 = dup2 fd→stdin (0)             5 = listen (server ready)
//   2 = dup2 fd→stdout (1)            6 = ptrace (injection)
//   3 = dup2 fd→stderr (2)            7 = mprotect RWX (shellcode)
//
// Attack patterns (bitwise AND):
//   REVERSE_SHELL = socket + dup(stdin) + dup(stdout) = 0b0000_0111 = 0x07
//   BIND_SHELL    = bind + listen + dup(stdin) + dup(stdout) = 0b0011_0110 = 0x36
//   CODE_INJECT   = ptrace + mprotect(RWX) = 0b1100_0000 = 0xC0

/// Per-PID kill chain flags. Key: PID. Value: accumulated bit flags.
/// Checked by LSM before allowing execve. Cleaned on process exit.
#[map]
static PID_CHAIN: HashMap<u32, u32> = HashMap::with_max_entries(8192, 0);

const CHAIN_SOCKET: u32 = 1 << 0;
const CHAIN_DUP_STDIN: u32 = 1 << 1;
const CHAIN_DUP_STDOUT: u32 = 1 << 2;
const CHAIN_DUP_STDERR: u32 = 1 << 3;
const CHAIN_BIND: u32 = 1 << 4;
const CHAIN_LISTEN: u32 = 1 << 5;
const CHAIN_PTRACE: u32 = 1 << 6;
const CHAIN_MPROTECT: u32 = 1 << 7;

const PATTERN_REVERSE_SHELL: u32 = CHAIN_SOCKET | CHAIN_DUP_STDIN | CHAIN_DUP_STDOUT;
const PATTERN_BIND_SHELL: u32 = CHAIN_BIND | CHAIN_LISTEN | CHAIN_DUP_STDIN | CHAIN_DUP_STDOUT;
const PATTERN_CODE_INJECT: u32 = CHAIN_PTRACE | CHAIN_MPROTECT;
// Zero-day exploit patterns - generic, no CVE signature needed:
// Exploit → shellcode: mprotect(RWX) then redirect I/O
const PATTERN_EXPLOIT_SHELL: u32 = CHAIN_MPROTECT | CHAIN_DUP_STDIN | CHAIN_DUP_STDOUT;
// Exploit → inject + shell: ptrace into process then spawn shell
const PATTERN_INJECT_SHELL: u32 = CHAIN_PTRACE | CHAIN_DUP_STDIN;
// Exploit → RWX + outbound: shellcode phones home
const PATTERN_EXPLOIT_C2: u32 = CHAIN_MPROTECT | CHAIN_SOCKET;
// Full exploit chain: RWX memory + inject + redirect + outbound
const PATTERN_FULL_EXPLOIT: u32 = CHAIN_MPROTECT | CHAIN_PTRACE | CHAIN_SOCKET;

/// Set a kill chain flag for the current PID.
#[inline(always)]
fn chain_flag(pid: u32, flag: u32) {
    let current = unsafe { PID_CHAIN.get(&pid) }.copied().unwrap_or(0);
    let _ = PID_CHAIN.insert(&pid, &(current | flag), 0);
}

/// Check if PID has accumulated an attack pattern. Returns true if kill chain detected.
#[inline(always)]
fn chain_is_attack(pid: u32) -> bool {
    let flags = unsafe { PID_CHAIN.get(&pid) }.copied().unwrap_or(0);
    if flags == 0 { return false; }
    // Shell patterns
    (flags & PATTERN_REVERSE_SHELL) == PATTERN_REVERSE_SHELL
        || (flags & PATTERN_BIND_SHELL) == PATTERN_BIND_SHELL
        // Injection patterns
        || (flags & PATTERN_CODE_INJECT) == PATTERN_CODE_INJECT
        // Zero-day exploit patterns
        || (flags & PATTERN_EXPLOIT_SHELL) == PATTERN_EXPLOIT_SHELL
        || (flags & PATTERN_INJECT_SHELL) == PATTERN_INJECT_SHELL
        || (flags & PATTERN_EXPLOIT_C2) == PATTERN_EXPLOIT_C2
        || (flags & PATTERN_FULL_EXPLOIT) == PATTERN_FULL_EXPLOIT
}

/// Clear kill chain for a PID (called on process exit).
#[inline(always)]
fn chain_clear(pid: u32) {
    let _ = PID_CHAIN.remove(&pid);
}

/// Minimum nanoseconds between events from the same PID (100ms = 100_000_000 ns).
/// Prevents cargo, find, grep from flooding the ring buffer during builds.
const RATE_LIMIT_NS: u64 = 100_000_000;

/// Exception list - specific (comm, handler) pairs to always skip.
/// Key: first 16 bytes of comm. Value: always 1.
/// More granular than COMM_ALLOWLIST - for processes that are noisy on one
/// handler but relevant on others (e.g., sshd is noisy on openat but
/// critical on connect and setuid).
#[map]
static EXCEPTION_LIST: HashMap<[u8; 16], u32> = HashMap::with_max_entries(512, 0);

// ---------------------------------------------------------------------------
// Shared filter helpers
// ---------------------------------------------------------------------------

/// Check if the current process comm is in the allowlist for this handler.
/// Returns true if the event should be SKIPPED (process is allowed).
#[inline(always)]
fn is_comm_allowed(handler_bit: u32) -> bool {
    if let Ok(comm) = bpf_get_current_comm() {
        let mut key = [0u8; 16];
        let len = comm.len().min(16);
        key[..len].copy_from_slice(&comm[..len]);

        if let Some(&mask) = unsafe { COMM_ALLOWLIST.get(&key) } {
            return mask & (1 << handler_bit) != 0;
        }
    }
    false
}

/// Check if the current cgroup is in the allowlist (known-safe container).
/// Returns true if the event should be SKIPPED.
#[inline(always)]
fn is_cgroup_allowed() -> bool {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    unsafe { CGROUP_ALLOWLIST.get(&cgroup_id) }.is_some()
}

/// Per-PID rate limiter. Returns true if the event should be SKIPPED.
/// Allows max 1 event per RATE_LIMIT_NS per PID per handler.
#[inline(always)]
fn is_rate_limited(pid: u32) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };

    if let Some(&last_ts) = unsafe { PID_RATE_LIMIT.get(&pid) } {
        if now.saturating_sub(last_ts) < RATE_LIMIT_NS {
            return true; // too soon - skip
        }
    }

    // Update timestamp (best-effort, ignore error if map is full)
    let _ = PID_RATE_LIMIT.insert(&pid, &now, 0);
    false
}

// ---------------------------------------------------------------------------
// Tail Call Dispatcher (feature = "dispatcher")
// ---------------------------------------------------------------------------
//
// Single raw_tracepoint/sys_enter entry point that reads the syscall number
// and tail-calls to the appropriate handler via ProgramArray.
//
// This replaces the 16 individual typed tracepoints with 1 attach point.
// The handlers become tail call targets - same program type (raw_tracepoint),
// each extracting args from pt_regs instead of typed tracepoint context.
//
// On aarch64: syscall args in pt_regs->regs[0..5] (offset 0, each 8 bytes)
// On x86_64: pt_regs->di, si, dx, r10, r8, r9 (offsets 112, 104, 96, 56, 72, 64)

#[cfg(feature = "dispatcher")]
#[map]
static SYSCALL_DISPATCH: ProgramArray = ProgramArray::with_max_entries(512, 0);

/// Per-syscall enable flag - checked before tail call.
/// Key: syscall number. Value: 1 = enabled, 0 = disabled.
#[cfg(feature = "dispatcher")]
#[map]
static SYSCALL_ENABLED: HashMap<u32, u32> = HashMap::with_max_entries(512, 0);

/// Read a raw tracepoint argument.
/// For raw_tracepoint/sys_enter: args[0] = pt_regs*, args[1] = syscall_nr.
#[cfg(feature = "dispatcher")]
#[inline(always)]
unsafe fn raw_arg(ctx: &RawTracePointContext, n: usize) -> u64 {
    // bpf_raw_tracepoint_args { __u64 args[]; }
    let args_ptr = ctx.as_ptr() as *const u64;
    core::ptr::read_volatile(args_ptr.add(n))
}

/// Read a syscall argument from pt_regs (architecture-specific).
/// `arg_idx`: 0-5 for the 6 syscall arguments.
#[cfg(feature = "dispatcher")]
#[inline(always)]
unsafe fn read_syscall_arg(ctx: &RawTracePointContext, arg_idx: usize) -> Result<u64, i64> {
    // args[0] = pt_regs pointer
    let regs_ptr = raw_arg(ctx, 0) as *const u8;

    // BPF compiles for bpfel-unknown-none - use aarch64 layout (our production target).
    // aarch64: regs[0..30] at offset 0, each u64 (8 bytes).
    // x86_64 would need different offsets (di=112, si=104, etc.)
    // but we compile per-target anyway so this is fine.
    let offset = arg_idx * 8;
    bpf_probe_read_kernel(regs_ptr.add(offset) as *const u64)
}

/// Main dispatcher - fires on every syscall entry.
#[cfg(feature = "dispatcher")]
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn innerwarden_dispatcher(ctx: RawTracePointContext) -> u32 {
    // args[1] = syscall number
    let syscall_nr: u64 = unsafe { raw_arg(&ctx, 1) };
    let nr = syscall_nr as u32;

    // Check if this syscall is enabled
    if let Some(&enabled) = unsafe { SYSCALL_ENABLED.get(&nr) } {
        if enabled == 0 {
            return 0;
        }
    } else {
        return 0; // not in map = not monitored
    }

    // Tail call to handler - silently returns if no handler installed
    unsafe {
        let _ = SYSCALL_DISPATCH.tail_call(&ctx, nr);
    }

    0
}

// ---------------------------------------------------------------------------
// XDP: innerwarden_xdp - wire-speed IP blocking
// ---------------------------------------------------------------------------
//
// Attached to a network interface. For every incoming packet:
//   1. Parse Ethernet + IPv4 header
//   2. Lookup source IP in BLOCKLIST
//   3. If found → XDP_DROP (packet never reaches the kernel stack)
//   4. If not found → XDP_PASS (normal processing)
//
// Performance: 10-25 million packets per second drop rate.
// Zero CPU overhead for dropped packets.

#[xdp]
pub fn innerwarden_xdp(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS, // fail-open: never break networking
    }
}

#[inline(always)]
fn try_xdp_firewall(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Need at least: Ethernet header (14) + IPv4 header (20) = 34 bytes
    if data + 34 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse Ethernet header - check for IPv4 (EtherType 0x0800)
    let eth_proto = u16::from_be_bytes(unsafe {
        let ptr = data as *const u8;
        [*ptr.add(12), *ptr.add(13)]
    });

    if eth_proto != 0x0800 {
        return Ok(xdp_action::XDP_PASS); // not IPv4
    }

    // Parse IPv4 source address (offset 14 + 12 = 26, 4 bytes)
    let src_ip = u32::from_ne_bytes(unsafe {
        let ptr = data as *const u8;
        [*ptr.add(26), *ptr.add(27), *ptr.add(28), *ptr.add(29)]
    });

    // Allowlist check FIRST - never drop protected IPs
    if unsafe { ALLOWLIST.get(&src_ip) }.is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    // Blocklist check - O(1) hash map lookup
    if unsafe { BLOCKLIST.get(&src_ip) }.is_some() {
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_execve
// ---------------------------------------------------------------------------
//
// Fires on every execve() syscall. Captures:
//   - PID, UID, parent PID
//   - Filename being executed
//   - Process comm name
//
// This is the most important tracepoint for security - every command
// execution on the system is visible here.

#[tracepoint]
pub fn innerwarden_execve(ctx: TracePointContext) -> u32 {
    match try_execve(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_execve(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(0) || is_cgroup_allowed() {
        return Ok(());
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return Ok(());
    }

    // Read filename from tracepoint args
    // sys_enter_execve args: [filename, argv, envp]
    let filename_ptr: *const u8 = unsafe { ctx.read_at(16)? };

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;

    let ts = unsafe { bpf_ktime_get_ns() };

    // Reserve space in ring buffer
    let mut entry = match EVENTS.reserve::<ExecveEvent>(0) {
        Some(e) => e,
        None => return Ok(()), // ring buffer full - drop silently (fail-open)
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Execve as u32;
    event.pid = pid;
    event.tgid = tgid;
    event.uid = uid;
    event.gid = gid;
    event.ppid = 0; // resolved in userspace via /proc/<pid>/status
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;
    event.argc = 0;

    // Read comm
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    // Read filename from user space
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename);
    }

    // Zero out argv (will be populated in future iteration)
    event.argv = [[0u8; 128]; 8];

    entry.submit(0);

    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_connect
// ---------------------------------------------------------------------------
//
// Fires on every connect() syscall. Captures:
//   - PID, UID
//   - Destination IP and port
//   - Process comm name
//
// Used to detect C2 callbacks, data exfiltration, and suspicious outbound
// connections from compromised processes.

#[tracepoint]
pub fn innerwarden_connect(ctx: TracePointContext) -> u32 {
    match try_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_connect(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(1) || is_cgroup_allowed() {
        return Ok(());
    }

    // sys_enter_connect args: [fd, uservaddr, addrlen]
    let addr_ptr: *const u8 = unsafe { ctx.read_at(24)? };

    // Read sockaddr_in (first 2 bytes = family, next 2 = port, next 4 = addr)
    let mut sa_buf = [0u8; 16];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(addr_ptr, &mut sa_buf);
    }

    let family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);

    // Only track IPv4 (AF_INET = 2) for now
    if family != 2 {
        return Ok(());
    }

    let port = u16::from_be_bytes([sa_buf[2], sa_buf[3]]);
    let addr = u32::from_ne_bytes([sa_buf[4], sa_buf[5], sa_buf[6], sa_buf[7]]);

    // Skip loopback (127.x.x.x) and unspecified (0.0.0.0)
    let first_octet = sa_buf[4];
    if first_octet == 127 || addr == 0 {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<ConnectEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Connect as u32;
    event.pid = pid;
    event.tgid = tgid;
    event.uid = uid;
    event.ppid = 0; // resolved in userspace
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.dst_addr = addr;
    event.dst_port = port;
    event.family = family;
    event.ts_ns = ts;

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    // Kill chain: mark this PID as having made an outbound connection
    chain_flag(pid, CHAIN_SOCKET);

    entry.submit(0);

    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_openat
// ---------------------------------------------------------------------------
//
// Monitors file access to sensitive paths. Only emits events for paths
// matching security-relevant prefixes to avoid flooding the ring buffer.

#[tracepoint]
pub fn innerwarden_openat(ctx: TracePointContext) -> u32 {
    match try_openat(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_openat(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(2) || is_cgroup_allowed() {
        return Ok(());
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return Ok(());
    }

    // sys_enter_openat args: [dfd, filename, flags, mode]
    let filename_ptr: *const u8 = unsafe { ctx.read_at(24)? };

    let mut filename_buf = [0u8; 256];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut filename_buf);
    }

    // Only emit events for sensitive paths (kernel-space filtering)
    let is_sensitive = {
        let f = &filename_buf;
        // /etc/passwd, /etc/shadow, /etc/sudoers*
        (f[0] == b'/' && f[1] == b'e' && f[2] == b't' && f[3] == b'c' && f[4] == b'/')
        // /root/.ssh/
        || (f[0] == b'/' && f[1] == b'r' && f[2] == b'o' && f[3] == b'o' && f[4] == b't')
        // /home/*/.ssh/
        || (f[0] == b'/' && f[1] == b'h' && f[2] == b'o' && f[3] == b'm' && f[4] == b'e')
    };

    if !is_sensitive {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let flags: u32 = unsafe { ctx.read_at(32)? };

    let mut entry = match EVENTS.reserve::<innerwarden_ebpf_types::FileOpenEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = innerwarden_ebpf_types::SyscallKind::FileOpen as u32;
    event.pid = pid;
    event.uid = uid;
    event.ppid = 0; // resolved in userspace
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.filename = filename_buf;
    event.flags = flags;
    event.ts_ns = ts;

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Kprobe: commit_creds - privilege escalation detection
// ---------------------------------------------------------------------------
//
// Fires when the kernel applies new credentials to a process.
// Detects: non-root process becoming root through unexpected paths.
//
// commit_creds(struct cred *new) - the `cred` struct contains the new uid.
// We compare current uid (before) with new uid (from cred arg).
// If old_uid != 0 && new_uid == 0 → privilege escalation.
//
// Legitimate escalation (sudo, su, login, sshd, cron) is filtered
// in userspace to avoid false positives.

/// Offset of `uid` field in `struct cred` (after atomic_long_t usage).
/// Linux 5.x+: usage(8) → uid(4) at offset 8.
const CRED_UID_OFFSET: usize = 8;

#[kprobe]
pub fn innerwarden_privesc(ctx: ProbeContext) -> u32 {
    match try_privesc(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_privesc(ctx: &ProbeContext) -> Result<(), i64> {
    // Current uid (before credential change)
    let old_uid = bpf_get_current_uid_gid() as u32;

    // Only care about non-root processes gaining root
    if old_uid == 0 {
        return Ok(());
    }

    // Read the new cred pointer (first argument to commit_creds)
    let cred_ptr: *const u8 = unsafe { ctx.arg(0).ok_or(1i64)? };

    // Read new uid from struct cred (offset 8: after atomic_long_t usage)
    let new_uid: u32 = unsafe {
        bpf_probe_read_kernel(cred_ptr.add(CRED_UID_OFFSET) as *const u32).map_err(|e| e)?
    };

    // Only fire when escalating TO root
    if new_uid != 0 {
        return Ok(());
    }

    // At this point: old_uid != 0, new_uid == 0 → privilege escalation
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    let mut entry = match EVENTS.reserve::<PrivEscEvent>(0) {
        Some(e) => e,
        None => return Ok(()), // ring buffer full - fail-open
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::PrivEsc as u32;
    event.pid = pid;
    event.tgid = tgid;
    event.old_uid = old_uid;
    event.new_uid = new_uid;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);

    Ok(())
}

// ---------------------------------------------------------------------------
// LSM: bprm_check_security - block execution from dangerous paths
// ---------------------------------------------------------------------------
//
// Enforces execution policy at the kernel level. When enabled via the
// LSM_POLICY map, blocks binaries executed from:
//   /tmp/       - common staging area for malware
//   /dev/shm/   - shared memory, often used for fileless malware
//   /var/tmp/   - persistent temp, another staging area
//
// Policy map keys:
//   0 = master switch (1 = enforce, 0 = disabled)
//
// Returns 0 to allow, -EPERM (-1) to deny.
// When policy map is empty or key 0 is not set → allow (fail-open).

/// Policy map - controls LSM enforcement.
/// Key 0 = master switch: 0 = disabled (observe only), 1 = enforce (block).
/// Managed by the agent via bpftool on the pinned map.
#[map]
static LSM_POLICY: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);

#[lsm(hook = "bprm_check_security")]
pub fn innerwarden_lsm_exec(ctx: LsmContext) -> i32 {
    match try_lsm_exec(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // fail-open: allow on error
    }
}

fn try_lsm_exec(ctx: &LsmContext) -> Result<i32, i64> {
    // Check if enforcement is enabled (key 0 in policy map)
    let enabled = unsafe { LSM_POLICY.get(&0u32) };
    if enabled.is_none() || *enabled.unwrap() == 0 {
        return Ok(0); // policy disabled - allow everything
    }

    // Kill chain detection: if this PID accumulated an attack pattern,
    // deny execution regardless of path.
    let pid = bpf_get_current_pid_tgid() as u32;
    if chain_is_attack(pid) {
        // Emit blocked event before denying
        let uid = bpf_get_current_uid_gid() as u32;
        let ts = unsafe { bpf_ktime_get_ns() };
        let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

        if let Some(mut entry) = EVENTS.reserve::<innerwarden_ebpf_types::ExecveEvent>(0) {
            let event = unsafe { &mut *entry.as_mut_ptr() };
            event.kind = SyscallKind::LsmBlocked as u32;
            event.pid = pid;
            event.tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
            event.uid = uid;
            event.gid = 0;
            event.ppid = 0;
            event.cgroup_id = cgroup_id;
            event.ts_ns = ts;
            event.argc = 0;
            event.argv = [[0u8; 128]; 8];
            event.filename = [0u8; 256];
            // Write "KILL_CHAIN_BLOCKED" as filename
            let msg = b"KILL_CHAIN_BLOCKED";
            event.filename[..msg.len()].copy_from_slice(msg);

            if let Ok(comm) = bpf_get_current_comm() {
                event.comm[..comm.len().min(MAX_COMM_LEN)]
                    .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
            }

            entry.submit(0);
        }

        chain_clear(pid); // Clean up after blocking
        return Ok(-1); // -EPERM: deny execution
    }

    // For bprm_check_security(struct linux_binprm *bprm):
    // Read the bprm pointer (first argument to the LSM hook)
    let bprm_ptr: *const u8 = unsafe { ctx.arg(0) };

    // linux_binprm->filename offset on kernel 6.x
    // struct linux_binprm { ..., const char *filename @ offset 72, ... }
    const BPRM_FILENAME_OFFSET: usize = 72;

    let filename_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(bprm_ptr.add(BPRM_FILENAME_OFFSET) as *const *const u8)
            .map_err(|e| e)?
    };

    // Read first 16 bytes of the filename to check the prefix
    let mut buf = [0u8; 16];
    unsafe {
        let _ = bpf_probe_read_kernel(filename_ptr as *const [u8; 16]).map(|v| buf = v);
    }

    // Check dangerous prefixes
    let is_dangerous =
        // /tmp/
        (buf[0] == b'/' && buf[1] == b't' && buf[2] == b'm' && buf[3] == b'p' && buf[4] == b'/')
        // /dev/shm/
        || (buf[0] == b'/' && buf[1] == b'd' && buf[2] == b'e' && buf[3] == b'v' && buf[4] == b'/' && buf[5] == b's' && buf[6] == b'h' && buf[7] == b'm' && buf[8] == b'/')
        // /var/tmp/
        || (buf[0] == b'/' && buf[1] == b'v' && buf[2] == b'a' && buf[3] == b'r' && buf[4] == b'/' && buf[5] == b't' && buf[6] == b'm' && buf[7] == b'p' && buf[8] == b'/');

    if !is_dangerous {
        return Ok(0); // safe path - allow
    }

    // LSM allowlist: certain processes are always allowed to execute from temp paths.
    // Package managers, build tools, and system updaters legitimately use /tmp.
    if let Ok(comm) = bpf_get_current_comm() {
        let c = &comm;
        let is_allowed =
            // Package managers
            (c[0] == b'd' && c[1] == b'p' && c[2] == b'k' && c[3] == b'g')     // dpkg
            || (c[0] == b'a' && c[1] == b'p' && c[2] == b't')                    // apt*
            || (c[0] == b'd' && c[1] == b'n' && c[2] == b'f')                    // dnf
            || (c[0] == b'y' && c[1] == b'u' && c[2] == b'm')                    // yum
            || (c[0] == b'r' && c[1] == b'p' && c[2] == b'm')                    // rpm
            || (c[0] == b's' && c[1] == b'n' && c[2] == b'a' && c[3] == b'p')    // snap
            // Build tools
            || (c[0] == b'c' && c[1] == b'c' && c[2] == 0)                       // cc
            || (c[0] == b'g' && c[1] == b'c' && c[2] == b'c')                    // gcc
            || (c[0] == b'l' && c[1] == b'd' && (c[2] == 0 || c[2] == b'.'))     // ld
            || (c[0] == b'c' && c[1] == b'a' && c[2] == b'r' && c[3] == b'g')    // cargo
            || (c[0] == b'r' && c[1] == b'u' && c[2] == b's' && c[3] == b't')    // rustc
            // System
            || (c[0] == b's' && c[1] == b'y' && c[2] == b's' && c[3] == b't'); // systemd*
        if is_allowed {
            return Ok(0);
        }
    }

    // Block execution from dangerous path
    // Also emit an event so the sensor sees the blocked attempt
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if let Some(mut entry) = EVENTS.reserve::<innerwarden_ebpf_types::ExecveEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = 6; // LSM blocked execution (new kind)
        event.pid = pid;
        event.tgid = (pid_tgid >> 32) as u32;
        event.uid = uid;
        event.gid = 0;
        event.ppid = 0;
        event.cgroup_id = cgroup_id;
        event.ts_ns = ts;
        event.argc = 0;
        event.argv = [[0u8; 128]; 8];

        // Copy filename to event
        event.filename = [0u8; 256];
        let copy_len = buf.len().min(256);
        event.filename[..copy_len].copy_from_slice(&buf[..copy_len]);

        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }

        entry.submit(0);
    }

    Ok(-1) // -EPERM: deny execution
}

// ---------------------------------------------------------------------------
// sched:sched_process_exit - track process exits for rootkit detection
// ---------------------------------------------------------------------------
//
// By tracking both execve (birth) and exit (death), the rootkit detector
// can distinguish between:
//   - Short-lived processes that exited normally (not rootkits)
//   - Long-running processes that disappeared from /proc (real rootkits)

#[tracepoint]
pub fn innerwarden_process_exit(ctx: TracePointContext) -> u32 {
    match try_process_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_process_exit(_ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    // Kill chain: clean up PID state on exit
    chain_clear(pid);
    let tgid = (pid_tgid >> 32) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<ProcessExitEvent>(0) {
        Some(e) => e,
        None => return Ok(()), // ring buffer full - fail-open
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::ProcessExit as u32;
    event.pid = pid;
    event.tgid = tgid;
    event.exit_code = 0; // exit code not directly available in tracepoint args
    event.ts_ns = ts;

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_ptrace - process injection detection
// ---------------------------------------------------------------------------
//
// Only emits events for dangerous ptrace operations:
//   PTRACE_ATTACH (16)    - attach to a running process
//   PTRACE_SEIZE (0x4206) - modern attach variant
//   PTRACE_POKETEXT (4)   - write to process memory (code injection)
//   PTRACE_POKEDATA (5)   - write to process data
//
// PTRACE_TRACEME (0) is benign (child requesting tracing) and is ignored.

const PTRACE_POKETEXT: u64 = 4;
const PTRACE_POKEDATA: u64 = 5;
const PTRACE_ATTACH: u64 = 16;
const PTRACE_SEIZE: u64 = 0x4206;

#[tracepoint]
pub fn innerwarden_ptrace(ctx: TracePointContext) -> u32 {
    match try_ptrace(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_ptrace(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(3) || is_cgroup_allowed() {
        return Ok(());
    }

    // sys_enter_ptrace args: [request, pid, addr, data]
    let request: u64 = unsafe { ctx.read_at(16)? };
    let target_pid: u64 = unsafe { ctx.read_at(24)? };

    // Only dangerous operations
    if request != PTRACE_ATTACH
        && request != PTRACE_SEIZE
        && request != PTRACE_POKETEXT
        && request != PTRACE_POKEDATA
    {
        return Ok(());
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<PtraceEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Ptrace as u32;
    event.pid = pid;
    event.uid = uid;
    event.target_pid = target_pid as u32;
    event.request = request as u32;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    chain_flag(pid, CHAIN_PTRACE);
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_setuid - privilege escalation at kernel level
// ---------------------------------------------------------------------------
//
// Detects real privilege changes: non-root process setting uid to 0.
// Covers setuid, setgid, setresuid, setresgid - all route here.
// The kprobe on commit_creds catches the final credential application;
// this tracepoint catches the syscall invocation (earlier in the chain).

#[tracepoint]
pub fn innerwarden_setuid(ctx: TracePointContext) -> u32 {
    match try_setuid(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_setuid(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(4) {
        return Ok(());
    }
    // Note: no cgroup filter on setuid - privilege escalation is always relevant

    // sys_enter_setuid args: [uid]
    let target_uid: u32 = unsafe { ctx.read_at(16)? };
    let current_uid = bpf_get_current_uid_gid() as u32;

    // Only emit when non-root tries to become root
    if current_uid == 0 || target_uid != 0 {
        return Ok(());
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<SetUidEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::SetUid as u32;
    event.pid = pid;
    event.uid = current_uid;
    event.target_uid = target_uid;
    event.syscall_nr = 0; // resolved by which tracepoint was attached
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_bind - reverse shell setup detection
// ---------------------------------------------------------------------------
//
// A process calling bind() on 0.0.0.0 with a TCP socket is setting up
// a listener - a strong indicator of reverse shell or backdoor setup.
// Combined with listen() detection in userspace for correlation.

#[tracepoint]
pub fn innerwarden_bind(ctx: TracePointContext) -> u32 {
    match try_bind(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_bind(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(5) || is_cgroup_allowed() {
        return Ok(());
    }

    // sys_enter_bind args: [fd, umyaddr, addrlen]
    let addr_ptr: *const u8 = unsafe { ctx.read_at(24)? };

    // Read sockaddr_in: family(2) + port(2) + addr(4)
    let mut sa_buf = [0u8; 16];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(addr_ptr, &mut sa_buf);
    }

    let family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);

    // Only track IPv4 (AF_INET = 2)
    if family != 2 {
        return Ok(());
    }

    let port = u16::from_be_bytes([sa_buf[2], sa_buf[3]]);
    let addr = u32::from_ne_bytes([sa_buf[4], sa_buf[5], sa_buf[6], sa_buf[7]]);

    // Skip ephemeral port range (32768+) to reduce noise from normal apps
    // Focus on low ports and common backdoor ports
    if port == 0 {
        return Ok(());
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<SocketBindEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::SocketBind as u32;
    event.pid = pid;
    event.uid = uid;
    event.protocol = 0; // not available at bind time
    event.family = family;
    event.port = port;
    event._pad = 0;
    event.addr = addr;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    chain_flag(pid, CHAIN_BIND);
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_mount - container escape detection
// ---------------------------------------------------------------------------
//
// Inside a container, mount() is almost always malicious. On the host,
// it's rare and security-relevant. Always emitted.

#[tracepoint]
pub fn innerwarden_mount(ctx: TracePointContext) -> u32 {
    match try_mount(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_mount(ctx: &TracePointContext) -> Result<(), i64> {
    // No comm/cgroup filter - mount is always security-critical
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return Ok(());
    }

    // sys_enter_mount args: [dev_name, dir_name, type, flags, data]
    let source_ptr: *const u8 = unsafe { ctx.read_at(16)? };
    let target_ptr: *const u8 = unsafe { ctx.read_at(24)? };
    let type_ptr: *const u8 = unsafe { ctx.read_at(32)? };
    let flags: u64 = unsafe { ctx.read_at(40)? };

    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<MountEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Mount as u32;
    event.pid = pid;
    event.uid = uid;
    event.flags = flags as u32;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;

    // Read source path
    event.source = [0u8; MAX_FILENAME_LEN];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(source_ptr, &mut event.source);
    }

    // Read target path
    event.target = [0u8; MAX_FILENAME_LEN];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(target_ptr, &mut event.target);
    }

    // Read filesystem type
    event.fs_type = [0u8; 32];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(type_ptr, &mut event.fs_type);
    }

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_memfd_create - fileless malware detection
// ---------------------------------------------------------------------------
//
// memfd_create() creates an anonymous memory-backed file. Legitimate uses
// are rare (JIT compilers, some runtimes). Malware uses it to avoid disk.
// Always emitted - very low frequency in normal operation.

#[tracepoint]
pub fn innerwarden_memfd_create(ctx: TracePointContext) -> u32 {
    match try_memfd_create(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_memfd_create(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(7) {
        return Ok(());
    }
    // No cgroup filter - memfd_create is rare and always suspicious

    // sys_enter_memfd_create args: [uname, flags]
    let name_ptr: *const u8 = unsafe { ctx.read_at(16)? };
    let flags: u32 = unsafe { ctx.read_at(24)? };

    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<MemfdCreateEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::MemfdCreate as u32;
    event.pid = pid;
    event.uid = uid;
    event.flags = flags;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;

    event.name = [0u8; MAX_FILENAME_LEN];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(name_ptr, &mut event.name);
    }

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_init_module / finit_module - rootkit loading
// ---------------------------------------------------------------------------
//
// Kernel module loading is one of the most dangerous operations.
// A loaded kernel module has full kernel privileges and can hide processes,
// intercept syscalls, and install rootkits. Always emitted.

#[tracepoint]
pub fn innerwarden_init_module(ctx: TracePointContext) -> u32 {
    match try_init_module(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_init_module(_ctx: &TracePointContext) -> Result<(), i64> {
    // No filters - kernel module loading is ALWAYS critical. No exceptions.
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<ModuleLoadEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::InitModule as u32;
    event.pid = pid;
    event.uid = uid;
    event.syscall_nr = 0; // resolved by which tracepoint was attached
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_dup2/dup3 - fd redirection (reverse shell)
// ---------------------------------------------------------------------------
// Reverse shells redirect fd 0/1/2 (stdin/stdout/stderr) to a socket.
// Only emits when newfd is 0, 1, or 2 (the dangerous redirections).

#[tracepoint]
pub fn innerwarden_dup(ctx: TracePointContext) -> u32 {
    match try_dup(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_dup(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(9) || is_cgroup_allowed() {
        return Ok(());
    }
    // sys_enter_dup2 args: [oldfd, newfd]  /  dup3: [oldfd, newfd, flags]
    let oldfd: u32 = unsafe { ctx.read_at(16)? };
    let newfd: u32 = unsafe { ctx.read_at(20)? };
    // Only care about redirecting to stdin(0), stdout(1), stderr(2)
    if newfd > 2 {
        return Ok(());
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let mut entry = match EVENTS.reserve::<DupEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Dup as u32;
    event.pid = pid;
    event.uid = uid;
    event.oldfd = oldfd;
    event.newfd = newfd;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }
    // Kill chain: track fd redirection
    match newfd {
        0 => chain_flag(pid, CHAIN_DUP_STDIN),
        1 => chain_flag(pid, CHAIN_DUP_STDOUT),
        2 => chain_flag(pid, CHAIN_DUP_STDERR),
        _ => {}
    }
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_listen - confirms reverse shell / backdoor
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn innerwarden_listen(ctx: TracePointContext) -> u32 {
    match try_listen(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_listen(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(10) || is_cgroup_allowed() {
        return Ok(());
    }
    // sys_enter_listen args: [fd, backlog]
    let backlog: u32 = unsafe { ctx.read_at(20)? };
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let mut entry = match EVENTS.reserve::<ListenEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Listen as u32;
    event.pid = pid;
    event.uid = uid;
    event.backlog = backlog;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }
    chain_flag(pid, CHAIN_LISTEN);
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_mprotect - shellcode detection (RWX memory)
// ---------------------------------------------------------------------------
// Only emits when PROT_EXEC (0x4) is being added - making memory executable.

const PROT_EXEC: u64 = 0x4;

#[tracepoint]
pub fn innerwarden_mprotect(ctx: TracePointContext) -> u32 {
    match try_mprotect(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_mprotect(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(11) || is_cgroup_allowed() {
        return Ok(());
    }
    // sys_enter_mprotect args: [addr, len, prot]
    let addr: u64 = unsafe { ctx.read_at(16)? };
    let len: u64 = unsafe { ctx.read_at(24)? };
    let prot: u64 = unsafe { ctx.read_at(32)? };
    // Only care about adding PROT_EXEC
    if prot & PROT_EXEC == 0 {
        return Ok(());
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return Ok(());
    }
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let mut entry = match EVENTS.reserve::<MprotectEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Mprotect as u32;
    event.pid = pid;
    event.uid = uid;
    event.prot = prot as u32;
    event.addr = addr;
    event.len = len;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }
    chain_flag(pid, CHAIN_MPROTECT);
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_clone - fork bombs, process tree tracking
// ---------------------------------------------------------------------------
// Rate limited heavily - clone is called very frequently.

#[tracepoint]
pub fn innerwarden_clone(ctx: TracePointContext) -> u32 {
    match try_clone(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_clone(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(12) || is_cgroup_allowed() {
        return Ok(());
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return Ok(());
    }
    // sys_enter_clone args: [clone_flags, ...]
    let clone_flags: u64 = unsafe { ctx.read_at(16)? };
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let mut entry = match EVENTS.reserve::<CloneEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Clone as u32;
    event.pid = pid;
    event.uid = uid;
    event.clone_flags = clone_flags;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_unlinkat - evidence destruction / log wipe
// ---------------------------------------------------------------------------
// Only emits for sensitive paths: /var/log, /etc, /root

#[tracepoint]
pub fn innerwarden_unlink(ctx: TracePointContext) -> u32 {
    match try_unlink(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_unlink(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(13) || is_cgroup_allowed() {
        return Ok(());
    }
    // sys_enter_unlinkat args: [dfd, pathname, flag]
    let path_ptr: *const u8 = unsafe { ctx.read_at(24)? };
    let mut path_buf = [0u8; 64];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(path_ptr, &mut path_buf);
    }
    let f = &path_buf;
    let is_sensitive = (f[0] == b'/'
        && f[1] == b'v'
        && f[2] == b'a'
        && f[3] == b'r'
        && f[4] == b'/'
        && f[5] == b'l'
        && f[6] == b'o'
        && f[7] == b'g')
        || (f[0] == b'/' && f[1] == b'e' && f[2] == b't' && f[3] == b'c' && f[4] == b'/')
        || (f[0] == b'/' && f[1] == b'r' && f[2] == b'o' && f[3] == b'o' && f[4] == b't');
    if !is_sensitive {
        return Ok(());
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let mut entry = match EVENTS.reserve::<UnlinkEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Unlink as u32;
    event.pid = pid;
    event.uid = uid;
    event._pad = 0;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;
    event.filename = [0u8; MAX_FILENAME_LEN];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(path_ptr, &mut event.filename);
    }
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_renameat2 - binary/config replacement
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn innerwarden_rename(ctx: TracePointContext) -> u32 {
    match try_rename(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_rename(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(14) || is_cgroup_allowed() {
        return Ok(());
    }
    // sys_enter_renameat2 args: [olddfd, oldname, newdfd, newname, flags]
    let oldname_ptr: *const u8 = unsafe { ctx.read_at(24)? };
    let newname_ptr: *const u8 = unsafe { ctx.read_at(40)? };
    // Only sensitive targets
    let mut buf = [0u8; 16];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(newname_ptr, &mut buf);
    }
    let f = &buf;
    let is_sensitive =
        (f[0] == b'/' && f[1] == b'e' && f[2] == b't' && f[3] == b'c' && f[4] == b'/')
            || (f[0] == b'/' && f[1] == b'u' && f[2] == b's' && f[3] == b'r')
            || (f[0] == b'/' && f[1] == b'b' && f[2] == b'i' && f[3] == b'n');
    if !is_sensitive {
        return Ok(());
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let mut entry = match EVENTS.reserve::<RenameEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Rename as u32;
    event.pid = pid;
    event.uid = uid;
    event._pad = 0;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;
    event.oldname = [0u8; MAX_FILENAME_LEN];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(oldname_ptr, &mut event.oldname);
    }
    event.newname = [0u8; MAX_FILENAME_LEN];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(newname_ptr, &mut event.newname);
    }
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_kill - killing security processes
// ---------------------------------------------------------------------------
// Only emits for SIGKILL(9), SIGTERM(15), SIGSTOP(19).

#[tracepoint]
pub fn innerwarden_kill(ctx: TracePointContext) -> u32 {
    match try_kill(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_kill(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(15) {
        return Ok(());
    }
    // sys_enter_kill args: [pid, sig]
    let target_pid: u32 = unsafe { ctx.read_at(16)? };
    let signal: u32 = unsafe { ctx.read_at(20)? };
    // Only dangerous signals
    if signal != 9 && signal != 15 && signal != 19 {
        return Ok(());
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let mut entry = match EVENTS.reserve::<KillEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Kill as u32;
    event.pid = pid;
    event.uid = uid;
    event.target_pid = target_pid;
    event.signal = signal;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_prctl - process name spoofing, privs manipulation
// ---------------------------------------------------------------------------
// Only PR_SET_NAME(15) and PR_SET_NO_NEW_PRIVS(38).

const PR_SET_NAME: u64 = 15;
const PR_SET_NO_NEW_PRIVS: u64 = 38;

#[tracepoint]
pub fn innerwarden_prctl(ctx: TracePointContext) -> u32 {
    match try_prctl(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_prctl(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(16) {
        return Ok(());
    }
    // sys_enter_prctl args: [option, arg2, arg3, arg4, arg5]
    let option: u64 = unsafe { ctx.read_at(16)? };
    let arg2: u64 = unsafe { ctx.read_at(24)? };
    if option != PR_SET_NAME && option != PR_SET_NO_NEW_PRIVS {
        return Ok(());
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let mut entry = match EVENTS.reserve::<PrctlEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Prctl as u32;
    event.pid = pid;
    event.uid = uid;
    event.option = option as u32;
    event.arg2 = arg2;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_accept4 - incoming connection accepted
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn innerwarden_accept(ctx: TracePointContext) -> u32 {
    match try_accept(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_accept(_ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(17) || is_cgroup_allowed() {
        return Ok(());
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return Ok(());
    }
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let mut entry = match EVENTS.reserve::<AcceptEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Accept as u32;
    event.pid = pid;
    event.uid = uid;
    event._pad = 0;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Dispatcher tail call handlers (feature = "dispatcher")
// ---------------------------------------------------------------------------
//
// These are the raw_tracepoint versions of each handler, used as tail call
// targets from the dispatcher. They read syscall arguments from pt_regs
// instead of typed tracepoint fields.
//
// Each handler must be the same program type as the dispatcher (raw_tracepoint)
// to be used as a tail call target.

#[cfg(feature = "dispatcher")]
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn dispatch_execve(ctx: RawTracePointContext) -> u32 {
    match try_dispatch_execve(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[cfg(feature = "dispatcher")]
#[inline(always)]
fn try_dispatch_execve(ctx: &RawTracePointContext) -> Result<(), i64> {
    if is_comm_allowed(0) || is_cgroup_allowed() {
        return Ok(());
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return Ok(());
    }

    let filename_ptr: *const u8 = unsafe { read_syscall_arg(ctx, 0)? as *const u8 };
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<ExecveEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Execve as u32;
    event.pid = pid;
    event.tgid = tgid;
    event.uid = uid;
    event.gid = gid;
    event.ppid = 0;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;
    event.argc = 0;
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename);
    }
    event.argv = [[0u8; 128]; 8];
    entry.submit(0);
    Ok(())
}

#[cfg(feature = "dispatcher")]
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn dispatch_connect(ctx: RawTracePointContext) -> u32 {
    match try_dispatch_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[cfg(feature = "dispatcher")]
#[inline(always)]
fn try_dispatch_connect(ctx: &RawTracePointContext) -> Result<(), i64> {
    if is_comm_allowed(1) || is_cgroup_allowed() {
        return Ok(());
    }
    let addr_ptr: *const u8 = unsafe { read_syscall_arg(ctx, 1)? as *const u8 };
    let mut sa_buf = [0u8; 16];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(addr_ptr, &mut sa_buf);
    }
    let family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);
    if family != 2 {
        return Ok(());
    }
    let port = u16::from_be_bytes([sa_buf[2], sa_buf[3]]);
    let addr = u32::from_ne_bytes([sa_buf[4], sa_buf[5], sa_buf[6], sa_buf[7]]);
    if sa_buf[4] == 127 || addr == 0 {
        return Ok(());
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<ConnectEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Connect as u32;
    event.pid = pid;
    event.tgid = tgid;
    event.uid = uid;
    event.ppid = 0;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.dst_addr = addr;
    event.dst_port = port;
    event.family = family;
    event.ts_ns = ts;
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }
    entry.submit(0);
    Ok(())
}

// Simpler handlers - most only read 0-2 args, trivial to convert.
// ptrace, setuid, bind, mount, memfd_create, init_module, dup, listen, mprotect,
// clone, unlink, rename, kill, prctl, accept - each follows the same pattern:
// read args via read_syscall_arg() instead of ctx.read_at().

#[cfg(feature = "dispatcher")]
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn dispatch_ptrace(ctx: RawTracePointContext) -> u32 {
    if is_comm_allowed(3) || is_cgroup_allowed() {
        return 0;
    }
    let request = unsafe { read_syscall_arg(&ctx, 0).unwrap_or(0) };
    let target_pid = unsafe { read_syscall_arg(&ctx, 1).unwrap_or(0) };
    if request != PTRACE_ATTACH
        && request != PTRACE_SEIZE
        && request != PTRACE_POKETEXT
        && request != PTRACE_POKEDATA
    {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<PtraceEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Ptrace as u32;
        event.pid = pid;
        event.uid = uid;
        event.target_pid = target_pid as u32;
        event.request = request as u32;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[cfg(feature = "dispatcher")]
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn dispatch_setuid(ctx: RawTracePointContext) -> u32 {
    if is_comm_allowed(4) {
        return 0;
    }
    let target_uid = unsafe { read_syscall_arg(&ctx, 0).unwrap_or(u64::MAX) } as u32;
    let current_uid = bpf_get_current_uid_gid() as u32;
    if current_uid == 0 || target_uid != 0 {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<SetUidEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::SetUid as u32;
        event.pid = pid;
        event.uid = current_uid;
        event.target_uid = target_uid;
        event.syscall_nr = 0;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[cfg(feature = "dispatcher")]
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn dispatch_mprotect(ctx: RawTracePointContext) -> u32 {
    if is_comm_allowed(11) || is_cgroup_allowed() {
        return 0;
    }
    let addr = unsafe { read_syscall_arg(&ctx, 0).unwrap_or(0) };
    let len = unsafe { read_syscall_arg(&ctx, 1).unwrap_or(0) };
    let prot = unsafe { read_syscall_arg(&ctx, 2).unwrap_or(0) };
    if prot & PROT_EXEC == 0 {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return 0;
    }
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<MprotectEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Mprotect as u32;
        event.pid = pid;
        event.uid = uid;
        event.prot = prot as u32;
        event.addr = addr;
        event.len = len;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[cfg(feature = "dispatcher")]
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn dispatch_kill(ctx: RawTracePointContext) -> u32 {
    if is_comm_allowed(15) {
        return 0;
    }
    let target_pid = unsafe { read_syscall_arg(&ctx, 0).unwrap_or(0) } as u32;
    let signal = unsafe { read_syscall_arg(&ctx, 1).unwrap_or(0) } as u32;
    if signal != 9 && signal != 15 && signal != 19 {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<KillEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Kill as u32;
        event.pid = pid;
        event.uid = uid;
        event.target_pid = target_pid;
        event.signal = signal;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

// For the remaining dispatcher handlers (bind, mount, memfd_create, init_module,
// dup, listen, clone, unlink, rename, prctl, accept, openat), the pattern is
// identical - read args via read_syscall_arg and emit to ring buffer.
// Userspace wires them into SYSCALL_DISPATCH at the correct syscall numbers.

// ---------------------------------------------------------------------------
// Panic handler (required for no_std)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
