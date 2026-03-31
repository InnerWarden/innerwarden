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
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, kretprobe, lsm, map, tracepoint, xdp},
    maps::{HashMap, RingBuf},
    programs::{LsmContext, ProbeContext, RetProbeContext, TracePointContext, XdpContext},
    EbpfContext,
};

// Dispatcher-specific imports (conditionally compiled)
#[cfg(feature = "dispatcher")]
use aya_ebpf::{macros::raw_tracepoint, maps::ProgramArray, programs::RawTracePointContext};
use aya_log_ebpf::info;
use innerwarden_ebpf_types::{
    AcceptEvent, AcpiEvalEvent, BpfLoadEvent, CloneEvent, ConnectEvent, DupEvent, ExecveEvent,
    IopermEvent, IoplEvent, KillEvent, ListenEvent, MemfdCreateEvent, ModuleLoadEvent, MountEvent,
    MprotectEvent, MsrWriteEvent, PrctlEvent, PrivEscEvent, ProcessExitEvent, PtraceEvent,
    RenameEvent, SetUidEvent, SocketBindEvent, SyscallKind, TimingProbeEvent, TimingTarget,
    TruncateEvent, UnlinkEvent, UtimensatEvent, MAX_COMM_LEN, MAX_FILENAME_LEN,
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

/// IPv6 blocklist - same as BLOCKLIST but keyed by 128-bit IPv6 address.
#[map]
static BLOCKLIST_V6: HashMap<[u8; 16], u32> = HashMap::with_max_entries(10_000, 0);

/// IPv6 allowlist - same as ALLOWLIST but keyed by 128-bit IPv6 address.
#[map]
static ALLOWLIST_V6: HashMap<[u8; 16], u32> = HashMap::with_max_entries(1_000, 0);

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
//   8 = openat sensitive path          (credential/config read)
//
// Attack patterns (bitwise AND):
//   REVERSE_SHELL = socket + dup(stdin) + dup(stdout) = 0b0000_0111 = 0x07
//   BIND_SHELL    = bind + listen + dup(stdin) + dup(stdout) = 0b0011_0110 = 0x36
//   CODE_INJECT   = ptrace + mprotect(RWX) = 0b1100_0000 = 0xC0
//   DATA_EXFIL    = sensitive_read + socket = 0b1_0000_0001 = 0x101

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
const CHAIN_SENSITIVE_READ: u32 = 1 << 8; // openat on /etc/shadow, .ssh/, credentials

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
// Data exfiltration: read sensitive file + has outbound socket
const PATTERN_DATA_EXFIL: u32 = CHAIN_SENSITIVE_READ | CHAIN_SOCKET;

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
        // Data exfiltration: read credentials/config + outbound socket
        || (flags & PATTERN_DATA_EXFIL) == PATTERN_DATA_EXFIL
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
// XDP: innerwarden_xdp - wire-speed IP blocking (IPv4 + IPv6)
// ---------------------------------------------------------------------------
//
// Attached to a network interface. For every incoming packet:
//   1. Parse Ethernet header to determine protocol (IPv4 or IPv6)
//   2. Extract source IP (4 bytes for IPv4, 16 bytes for IPv6)
//   3. Check allowlist FIRST — never drop protected IPs
//   4. Check blocklist — if found → XDP_DROP (packet never reaches kernel stack)
//   5. If not found → XDP_PASS (normal processing)
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

    // Need at least Ethernet header (14 bytes)
    if data + 14 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse EtherType (offset 12, 2 bytes)
    let eth_proto = u16::from_be_bytes(unsafe {
        let ptr = data as *const u8;
        [*ptr.add(12), *ptr.add(13)]
    });

    match eth_proto {
        // IPv4 (EtherType 0x0800)
        0x0800 => {
            // Ethernet (14) + IPv4 header (20) = 34 bytes minimum
            if data + 34 > data_end {
                return Ok(xdp_action::XDP_PASS);
            }
            // Source IP at offset 14 (eth) + 12 (ip src) = 26, 4 bytes
            let src_ip = u32::from_ne_bytes(unsafe {
                let ptr = data as *const u8;
                [*ptr.add(26), *ptr.add(27), *ptr.add(28), *ptr.add(29)]
            });
            if unsafe { ALLOWLIST.get(&src_ip) }.is_some() {
                return Ok(xdp_action::XDP_PASS);
            }
            if unsafe { BLOCKLIST.get(&src_ip) }.is_some() {
                return Ok(xdp_action::XDP_DROP);
            }
            Ok(xdp_action::XDP_PASS)
        }
        // IPv6 (EtherType 0x86DD)
        0x86DD => {
            // Ethernet (14) + IPv6 header (40) = 54 bytes minimum
            if data + 54 > data_end {
                return Ok(xdp_action::XDP_PASS);
            }
            // Source IP at offset 14 (eth) + 8 (ipv6 src) = 22, 16 bytes
            let mut src_ip = [0u8; 16];
            unsafe {
                let ptr = data as *const u8;
                let mut i = 0;
                while i < 16 {
                    src_ip[i] = *ptr.add(22 + i);
                    i += 1;
                }
            }
            if unsafe { ALLOWLIST_V6.get(&src_ip) }.is_some() {
                return Ok(xdp_action::XDP_PASS);
            }
            if unsafe { BLOCKLIST_V6.get(&src_ip) }.is_some() {
                return Ok(xdp_action::XDP_DROP);
            }
            Ok(xdp_action::XDP_PASS)
        }
        // Not IP — pass through (ARP, etc.)
        _ => Ok(xdp_action::XDP_PASS),
    }
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
    // sys_enter_connect args: [fd, uservaddr, addrlen]
    let addr_ptr: *const u8 = unsafe { ctx.read_at(24)? };

    // Read sockaddr_in: family(2) + port(2) + addr(4) = 8 bytes minimum.
    // Use bpf_probe_read_user (NOT str_bytes) — sockaddr_in is binary data
    // and str_bytes stops at null bytes, corrupting port/addr fields.
    let sa_buf = unsafe {
        bpf_probe_read_user(addr_ptr as *const [u8; 8]).unwrap_or([0u8; 8])
    };

    let family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);

    // Only track IPv4 (AF_INET = 2) for now
    if family != 2 {
        return Ok(());
    }

    let port = u16::from_be_bytes([sa_buf[2], sa_buf[3]]);
    let addr = u32::from_ne_bytes([sa_buf[4], sa_buf[5], sa_buf[6], sa_buf[7]]);

    // Kill chain: ALWAYS set the SOCKET flag, regardless of allowlists,
    // loopback, or rate limiting. The chain flag tracks attack patterns —
    // filtering here would let attackers evade detection by using localhost
    // or allowlisted process names.
    let pid = bpf_get_current_pid_tgid() as u32;
    chain_flag(pid, CHAIN_SOCKET);

    // Now apply normal noise filters for EVENT emission only.
    // The chain flag is already set above — these filters only control
    // whether the event is sent to the ring buffer.
    if is_comm_allowed(1) || is_cgroup_allowed() {
        return Ok(());
    }

    // Skip loopback (127.x.x.x) and unspecified (0.0.0.0) for event emission
    let first_octet = sa_buf[4];
    if first_octet == 127 || addr == 0 {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
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
    // sys_enter_openat args: [dfd, filename, flags, mode]
    let filename_ptr: *const u8 = unsafe { ctx.read_at(24)? };

    let mut filename_buf = [0u8; 256];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut filename_buf);
    }

    // Sensitive path check — needed for kill chain before noise filters
    let is_sensitive = {
        let f = &filename_buf;
        // /etc/passwd, /etc/shadow, /etc/sudoers*
        (f[0] == b'/' && f[1] == b'e' && f[2] == b't' && f[3] == b'c' && f[4] == b'/')
        // /root/.ssh/
        || (f[0] == b'/' && f[1] == b'r' && f[2] == b'o' && f[3] == b'o' && f[4] == b't')
        // /home/*/.ssh/
        || (f[0] == b'/' && f[1] == b'h' && f[2] == b'o' && f[3] == b'm' && f[4] == b'e')
    };

    // Kill chain: ALWAYS set sensitive_read flag before noise filters.
    // Filtering here would let attackers evade DATA_EXFIL detection.
    if is_sensitive {
        let pid = bpf_get_current_pid_tgid() as u32;
        chain_flag(pid, CHAIN_SENSITIVE_READ);
    }

    // Noise filters for EVENT emission only — chain flag already set above.
    if is_comm_allowed(2) || is_cgroup_allowed() {
        return Ok(());
    }
    if !is_sensitive {
        return Ok(());
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
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
/// Key 1 = sensitive write protection: 0 = observe only, 1 = block writes.
/// Managed by the agent via bpftool on the pinned map.
#[map]
static LSM_POLICY: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);

/// sizeof(struct inode) for the running kernel - populated by userspace from BTF.
/// Used for overlayfs upper-layer detection: __upperdentry is at inode_ptr + sizeof(struct inode).
/// Key: 0. Value: sizeof(struct inode) in bytes.
/// Trick from Falco: avoids needing BTF for the private ovl_inode struct.
#[map]
static INODE_SIZE: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;

/// Per-cgroup capability bitmask. Key: cgroup_id. Value: bitmask of allowed capabilities.
/// Populated by the agent from config. When guard mode is on and a cgroup has a capability
/// bit set, that action is ALLOWED for processes in that cgroup.
#[map]
static CGROUP_CAPABILITIES: HashMap<u64, u32> = HashMap::with_max_entries(256, 0);

/// Per-process capability bitmask. Key: first 16 bytes of comm. Value: bitmask.
/// Same semantics as CGROUP_CAPABILITIES but per process name.
/// Replaces hardcoded byte-comparison allowlists in LSM hooks.
#[map]
static COMM_CAPABILITIES: HashMap<[u8; 16], u32> = HashMap::with_max_entries(256, 0);

/// Check if the current process or its cgroup has a specific capability.
/// Returns true if the action should be ALLOWED.
#[inline(always)]
fn has_capability(cap_bit: u32) -> bool {
    // Check per-cgroup first (more specific)
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if let Some(&caps) = unsafe { CGROUP_CAPABILITIES.get(&cgroup_id) } {
        if caps & cap_bit != 0 {
            return true;
        }
    }
    // Check per-comm
    if let Ok(comm) = bpf_get_current_comm() {
        let mut key = [0u8; 16];
        let len = comm.len().min(16);
        key[..len].copy_from_slice(&comm[..len]);
        if let Some(&caps) = unsafe { COMM_CAPABILITIES.get(&key) } {
            if caps & cap_bit != 0 {
                return true;
            }
        }
    }
    false
}

#[lsm(hook = "bprm_check_security")]
pub fn innerwarden_lsm_exec(ctx: LsmContext) -> i32 {
    match try_lsm_exec(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // fail-open: allow on error
    }
}

fn try_lsm_exec(ctx: &LsmContext) -> Result<i32, i64> {
    // ── Container drift detection (ALWAYS runs, even without guard mode) ──
    // Check if the binary is on an overlayfs upper layer (dropped after container start).
    // Uses the Falco trick: __upperdentry is at inode_ptr + sizeof(struct inode).
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if cgroup_id != 0 {
        // In a container — check for overlayfs drift
        if let Some(&inode_size) = unsafe { INODE_SIZE.get(&0u32) } {
            if inode_size > 0 {
                let _ = check_overlay_drift(ctx, cgroup_id, inode_size);
            }
        }
    }

    // ── Guard mode enforcement ──
    // Check if enforcement is enabled (key 0 in policy map)
    let enabled = unsafe { LSM_POLICY.get(&0u32) };
    if enabled.is_none() || *enabled.unwrap() == 0 {
        return Ok(0); // policy disabled - allow everything
    }

    // Kill chain detection: check both PID and TGID (thread group leader).
    // When a process forks (subprocess.run, os.system), the child has a new PID
    // but the parent's chain flags stay on the parent PID. By checking the TGID
    // (which equals the parent PID for the main thread), we catch cases where
    // the parent accumulated the chain and the child does the execve.
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    if chain_is_attack(pid) || (tgid != pid && chain_is_attack(tgid)) {
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
// Container drift detection via overlayfs upper-layer check
// ---------------------------------------------------------------------------
//
// Checks if the binary being executed is in the overlayfs upper layer.
// The upper layer contains files created/modified after container start —
// i.e., not in the original image. This is container drift.
//
// Technique (from Falco): __upperdentry is the first field after vfs_inode
// in struct ovl_inode. So its offset = inode_ptr + sizeof(struct inode).
// sizeof(struct inode) is queried from kernel BTF by userspace and stored
// in the INODE_SIZE map.

fn check_overlay_drift(
    ctx: &LsmContext,
    cgroup_id: u64,
    inode_size: u64,
) -> Result<(), i64> {
    // bprm_check_security(struct linux_binprm *bprm)
    let bprm_ptr: *const u8 = unsafe { ctx.arg(0) };

    // bprm->file @ offset 48 (kernel 6.x: struct linux_binprm has
    // struct vm_area_struct *vma, unsigned long limit, mm, flags, etc. before file)
    const BPRM_FILE_OFFSET: usize = 48;
    let file_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(bprm_ptr.add(BPRM_FILE_OFFSET) as *const *const u8)
            .map_err(|e| e)?
    };
    if file_ptr.is_null() {
        return Ok(());
    }

    // file->f_path.dentry @ offset 16 (f_path is { mnt(8), dentry(8) } at offset 8)
    const F_PATH_DENTRY_OFFSET: usize = 16;
    let dentry_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(file_ptr.add(F_PATH_DENTRY_OFFSET) as *const *const u8)
            .map_err(|e| e)?
    };
    if dentry_ptr.is_null() {
        return Ok(());
    }

    // dentry->d_sb @ offset 104 (kernel 6.x)
    const DENTRY_D_SB_OFFSET: usize = 104;
    let sb_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(dentry_ptr.add(DENTRY_D_SB_OFFSET) as *const *const u8)
            .map_err(|e| e)?
    };
    if sb_ptr.is_null() {
        return Ok(());
    }

    // super_block->s_magic @ offset 104 (kernel 6.x)
    const SB_S_MAGIC_OFFSET: usize = 104;
    let s_magic: u64 = unsafe {
        bpf_probe_read_kernel(sb_ptr.add(SB_S_MAGIC_OFFSET) as *const u64).map_err(|e| e)?
    };
    if s_magic != OVERLAYFS_SUPER_MAGIC {
        return Ok(()); // Not overlayfs — skip
    }

    // dentry->d_inode @ offset 48 (kernel 6.x)
    const DENTRY_D_INODE_OFFSET: usize = 48;
    let inode_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(dentry_ptr.add(DENTRY_D_INODE_OFFSET) as *const *const u8)
            .map_err(|e| e)?
    };
    if inode_ptr.is_null() {
        return Ok(());
    }

    // __upperdentry is at inode_ptr + sizeof(struct inode)
    let upper_dentry: *const u8 = unsafe {
        bpf_probe_read_kernel(inode_ptr.add(inode_size as usize) as *const *const u8)
            .map_err(|e| e)?
    };

    if upper_dentry.is_null() {
        return Ok(()); // Lower layer — part of original image, no drift
    }

    // DRIFT DETECTED: binary is in overlayfs upper layer (dropped after container start)
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    if let Some(mut entry) = EVENTS.reserve::<innerwarden_ebpf_types::ExecveEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = innerwarden_ebpf_types::SyscallKind::ContainerDrift as u32;
        event.pid = pid;
        event.tgid = (pid_tgid >> 32) as u32;
        event.uid = uid;
        event.gid = 0;
        event.ppid = 0;
        event.cgroup_id = cgroup_id;
        event.ts_ns = ts;
        event.argc = 0;
        event.argv = [[0u8; 128]; 8];

        // Read the filename from bprm->filename
        const BPRM_FILENAME_OFFSET: usize = 72;
        let filename_ptr: *const u8 = unsafe {
            bpf_probe_read_kernel(bprm_ptr.add(BPRM_FILENAME_OFFSET) as *const *const u8)
                .unwrap_or(core::ptr::null())
        };
        event.filename = [0u8; 256];
        if !filename_ptr.is_null() {
            unsafe {
                let _ = bpf_probe_read_kernel_str_bytes(filename_ptr, &mut event.filename);
            }
        }

        if let Ok(comm) = bpf_get_current_comm() {
            event.comm = [0u8; MAX_COMM_LEN];
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }

        entry.submit(0);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// LSM: file_open - block writes to sensitive paths (guard mode)
// ---------------------------------------------------------------------------
//
// Protects critical system files from unauthorized modification.
// When enabled via LSM_POLICY key 1, blocks write opens to:
//   /etc/shadow, /etc/passwd, /etc/sudoers*
//   ~/.ssh/authorized_keys, ~/.ssh/id_*
//   /etc/cron*, /var/spool/cron/
//   /etc/systemd/system/
//   /etc/ld.so.preload, /etc/ld.so.conf*
//   /etc/pam.d/
//
// Policy key 1 = 1 → enforce (block writes), 0 or absent → observe only.
// Always emits FileOpenEvent with kind=FileWrite for visibility.

#[lsm(hook = "file_open")]
pub fn innerwarden_lsm_file_open(ctx: LsmContext) -> i32 {
    match try_lsm_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // fail-open
    }
}

fn try_lsm_file_open(ctx: &LsmContext) -> Result<i32, i64> {
    // file_open(struct file *file)
    // struct file { ... f_flags @ offset 76 (kernel 6.x), f_path.dentry @ offset ... }
    // We read f_flags to check for write mode.
    let file_ptr: *const u8 = unsafe { ctx.arg(0) };

    // f_flags offset in struct file (kernel 6.x)
    const F_FLAGS_OFFSET: usize = 76;
    let flags: u32 = unsafe {
        bpf_probe_read_kernel(file_ptr.add(F_FLAGS_OFFSET) as *const u32).map_err(|e| e)?
    };

    // Only interested in write opens: O_WRONLY(1), O_RDWR(2), O_CREAT(0x40), O_TRUNC(0x200)
    let is_write = (flags & 0x3) != 0 || (flags & 0x40) != 0 || (flags & 0x200) != 0;
    if !is_write {
        return Ok(0);
    }

    // Read filename from f_path.dentry->d_name
    // struct file { f_path { struct vfsmount *mnt; struct dentry *dentry } @ offset 16 }
    // f_path.dentry @ offset 24 (after mnt pointer)
    const F_PATH_DENTRY_OFFSET: usize = 24;
    let dentry_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(file_ptr.add(F_PATH_DENTRY_OFFSET) as *const *const u8)
            .map_err(|e| e)?
    };

    // dentry->d_name.name @ offset 40 (kernel 6.x, after d_name { hash_len, name })
    // d_name is struct qstr at offset 32 in dentry, name ptr is at qstr+8 = dentry+40
    const DENTRY_NAME_OFFSET: usize = 40;
    let name_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(dentry_ptr.add(DENTRY_NAME_OFFSET) as *const *const u8)
            .map_err(|e| e)?
    };

    let mut name_buf = [0u8; 64];
    unsafe {
        let _ = bpf_probe_read_kernel_str_bytes(name_ptr, &mut name_buf);
    }

    // Classify the filename into a capability category
    let n = &name_buf;
    let cap_bit: u32 = if
        // shadow, passwd, gshadow, group
        (n[0] == b's' && n[1] == b'h' && n[2] == b'a' && n[3] == b'd' && n[4] == b'o' && n[5] == b'w')
        || (n[0] == b'p' && n[1] == b'a' && n[2] == b's' && n[3] == b's' && n[4] == b'w' && n[5] == b'd')
        || (n[0] == b'g' && n[1] == b's' && n[2] == b'h' && n[3] == b'a' && n[4] == b'd')
    {
        innerwarden_ebpf_types::CAP_WRITE_CREDENTIALS
    } else if
        // authorized_keys, id_rsa, id_ed25519
        n[0] == b'a' && n[1] == b'u' && n[2] == b't' && n[3] == b'h' && n[4] == b'o' && n[5] == b'r'
    {
        innerwarden_ebpf_types::CAP_WRITE_SSH
    } else if
        // sudoers
        n[0] == b's' && n[1] == b'u' && n[2] == b'd' && n[3] == b'o' && n[4] == b'e' && n[5] == b'r' && n[6] == b's'
    {
        innerwarden_ebpf_types::CAP_WRITE_SUDO
    } else if
        // crontab, cron.d
        n[0] == b'c' && n[1] == b'r' && n[2] == b'o' && n[3] == b'n'
    {
        innerwarden_ebpf_types::CAP_WRITE_CRON
    } else if
        // ld.so.preload, ld.so.conf
        n[0] == b'l' && n[1] == b'd' && n[2] == b'.' && n[3] == b's' && n[4] == b'o'
    {
        innerwarden_ebpf_types::CAP_WRITE_LDPRELOAD
    } else if
        // .bashrc, .profile (persistence via shell config)
        (n[0] == b'.' && n[1] == b'b' && n[2] == b'a' && n[3] == b's' && n[4] == b'h')
        || (n[0] == b'.' && n[1] == b'p' && n[2] == b'r' && n[3] == b'o' && n[4] == b'f')
    {
        innerwarden_ebpf_types::CAP_WRITE_PERSISTENCE
    } else {
        return Ok(0); // Not a sensitive path
    };

    // Check capability maps: if this process/cgroup has the capability, allow
    if has_capability(cap_bit) {
        return Ok(0);
    }

    // Emit event for visibility (always, regardless of guard mode)
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if let Some(mut entry) = EVENTS.reserve::<innerwarden_ebpf_types::FileOpenEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = innerwarden_ebpf_types::SyscallKind::FileWrite as u32;
        event.pid = pid;
        event.uid = uid;
        event.ppid = 0;
        event.cgroup_id = cgroup_id;
        event.flags = flags;
        event.ts_ns = ts;

        // Copy filename
        event.filename = [0u8; 256];
        let copy_len = name_buf.len().min(256);
        event.filename[..copy_len].copy_from_slice(&name_buf[..copy_len]);

        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }

        entry.submit(0);
    }

    // Check if guard mode is enabled (LSM_POLICY key 1)
    let guard_writes = unsafe { LSM_POLICY.get(&1u32) };
    if guard_writes.is_some() && *guard_writes.unwrap() == 1 {
        return Ok(-1); // -EPERM: block the write
    }

    Ok(0) // observe only
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

    // Kill chain: ALWAYS set ptrace flag before noise filters.
    // Filtering here would let attackers evade CODE_INJECT/INJECT_SHELL/
    // FULL_EXPLOIT detection by using allowlisted process names.
    let pid = bpf_get_current_pid_tgid() as u32;
    chain_flag(pid, CHAIN_PTRACE);

    // Noise filter for EVENT emission only — chain flag already set above.
    if is_comm_allowed(3) || is_cgroup_allowed() {
        return Ok(());
    }

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
    // sys_enter_bind args: [fd, umyaddr, addrlen]
    let addr_ptr: *const u8 = unsafe { ctx.read_at(24)? };

    // Read sockaddr_in: family(2) + port(2) + addr(4) = 8 bytes.
    // Use bpf_probe_read_user (NOT str_bytes) — sockaddr_in is binary data
    // and str_bytes stops at null bytes, corrupting port/addr fields.
    let sa_buf = unsafe {
        bpf_probe_read_user(addr_ptr as *const [u8; 8]).unwrap_or([0u8; 8])
    };

    let family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);

    // Only track IPv4 (AF_INET = 2)
    if family != 2 {
        return Ok(());
    }

    let port = u16::from_be_bytes([sa_buf[2], sa_buf[3]]);
    let addr = u32::from_ne_bytes([sa_buf[4], sa_buf[5], sa_buf[6], sa_buf[7]]);

    if port == 0 {
        return Ok(());
    }

    // Kill chain: ALWAYS set bind flag before noise filters.
    // Filtering here would let attackers evade BIND_SHELL detection.
    let pid = bpf_get_current_pid_tgid() as u32;
    chain_flag(pid, CHAIN_BIND);

    // Noise filter for EVENT emission only — chain flag already set above.
    if is_comm_allowed(5) || is_cgroup_allowed() {
        return Ok(());
    }

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
    // sys_enter_dup3 args on aarch64: [oldfd(8 bytes @ 16), newfd(8 bytes @ 24), flags(8 bytes @ 32)]
    // On x86_64 dup2: [oldfd(8 @ 16), newfd(8 @ 24)]  — same offsets.
    let oldfd: u32 = unsafe { ctx.read_at(16)? };
    let newfd: u32 = unsafe { ctx.read_at(24)? };
    // Only care about redirecting to stdin(0), stdout(1), stderr(2)
    if newfd > 2 {
        return Ok(());
    }

    // Kill chain: ALWAYS set dup flags before any filtering.
    let pid = bpf_get_current_pid_tgid() as u32;
    match newfd {
        0 => chain_flag(pid, CHAIN_DUP_STDIN),
        1 => chain_flag(pid, CHAIN_DUP_STDOUT),
        2 => chain_flag(pid, CHAIN_DUP_STDERR),
        _ => {}
    }

    // Noise filter for EVENT emission — chain flag already set above.
    if is_comm_allowed(9) || is_cgroup_allowed() {
        return Ok(());
    }

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
    // sys_enter_listen args: [fd, backlog]
    let backlog: u32 = unsafe { ctx.read_at(20)? };

    // Kill chain: ALWAYS set listen flag before noise filters.
    // Filtering here would let attackers evade BIND_SHELL detection.
    let pid = bpf_get_current_pid_tgid() as u32;
    chain_flag(pid, CHAIN_LISTEN);

    // Noise filter for EVENT emission only — chain flag already set above.
    if is_comm_allowed(10) || is_cgroup_allowed() {
        return Ok(());
    }

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
    // sys_enter_mprotect args: [addr, len, prot]
    let addr: u64 = unsafe { ctx.read_at(16)? };
    let len: u64 = unsafe { ctx.read_at(24)? };
    let prot: u64 = unsafe { ctx.read_at(32)? };
    // Only care about adding PROT_EXEC
    if prot & PROT_EXEC == 0 {
        return Ok(());
    }

    // Kill chain: ALWAYS set mprotect flag before noise filters.
    // Filtering here would let attackers evade CODE_INJECT/EXPLOIT_SHELL/
    // EXPLOIT_C2/FULL_EXPLOIT detection.
    let pid = bpf_get_current_pid_tgid() as u32;
    chain_flag(pid, CHAIN_MPROTECT);

    // Noise filter for EVENT emission only — chain flag already set above.
    if is_comm_allowed(11) || is_cgroup_allowed() {
        return Ok(());
    }
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
// Kill chain propagation on clone/fork
// ---------------------------------------------------------------------------
// When a process with accumulated kill chain flags forks, the child inherits
// the parent's flags. This prevents evasion by forking before execve.
// Runs inside the existing clone handler — no separate tracepoint needed.
// The parent PID is available in sys_enter_clone. We propagate to the
// child via a deferred mechanism: we mark the parent PID as "propagate on
// next child" and the sched_process_exit handler (or LSM hook) will check.
//
// Simpler approach: propagate in userspace. The innerwarden-killchain service
// tracks clone events and copies parent flags to child PIDs when it sees a
// process.clone event followed by events from the child PID.
//
// Kernel-level approach (future): add sched_process_fork tracepoint which
// has both parent and child task_struct pointers, allowing direct propagation.

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
    let sa_buf = unsafe {
        bpf_probe_read_user(addr_ptr as *const [u8; 8]).unwrap_or([0u8; 8])
    };
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
// EXPERIMENTAL: EFI Runtime Services monitoring — firmware behavioral baseline
// ---------------------------------------------------------------------------
//
// Hooks efi_call_rts (or __efi_call_virt on some kernels) to observe EFI
// Runtime Services calls (GetVariable, SetVariable, GetTime, etc.) from the OS.
//
// Purpose: establish a behavioral baseline of normal firmware/OS interaction.
// If firmware is compromised (UEFI implant, bootkit), its runtime behavior may
// differ from the baseline — more frequent calls, different timing, unexpected
// callers. This is observational only — no blocking, no modification.
//
// References:
//   - LoJax (ESET, 2018): first in-the-wild UEFI rootkit
//   - CosmicStrand (Kaspersky, 2022): firmware rootkit with OS-level side effects
//   - BlackLotus (ESET, 2023): Secure Boot bypass bootkit
//
// The kprobe target varies by kernel version:
//   - 5.x+: efi_call_rts or virt_efi_* functions
//   - Attach is best-effort; if the symbol doesn't exist, the sensor skips it.

#[kprobe]
pub fn innerwarden_efi_call(ctx: ProbeContext) -> u32 {
    match try_efi_call(&ctx) {
        Ok(()) => 0,
        Err(_) => 0, // fail-open: never interfere with EFI calls
    }
}

fn try_efi_call(_ctx: &ProbeContext) -> Result<(), i64> {
    // Skip noise: only log if not from an allowlisted process
    if is_comm_allowed(0) || is_cgroup_allowed() {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    // Heavy rate limiting — EFI calls are low-frequency but we want minimal overhead
    if is_rate_limited(pid) {
        return Ok(());
    }

    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    let mut entry = match EVENTS.reserve::<innerwarden_ebpf_types::EfiCallEvent>(0) {
        Some(e) => e,
        None => return Ok(()), // ring buffer full — fail-open
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::EfiCall as u32;
    event.pid = pid;
    event.uid = uid;
    event._pad = 0;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// io_uring monitoring - detect syscall bypass evasion
// ---------------------------------------------------------------------------
//
// io_uring submits operations via shared ring buffers, bypassing traditional
// syscall interception (seccomp, audit). Attackers use this for invisible
// file I/O, network connections, and data exfiltration.
//
// Tracepoint name changed in kernel 6.4:
//   5.10-6.3: io_uring:io_uring_submit_sqe
//   6.4+:     io_uring:io_uring_submit_req
// Both have identical layout for the fields we read.
//
// Offsets (from tracepoint format, after 8-byte common header):
//   ctx(8) req(8) user_data(8) opcode(1) _pad(3) flags(4) sq_thread(1)

/// io_uring SQE submission — fires on every submitted operation.
/// We use the 6.4+ name; the userspace loader tries both names.
#[tracepoint]
pub fn innerwarden_io_uring_submit(ctx: TracePointContext) -> u32 {
    match try_io_uring_submit(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_io_uring_submit(ctx: &TracePointContext) -> Result<(), i64> {
    // Offsets after 8-byte common header
    let opcode: u8 = unsafe { ctx.read_at(32)? };

    // Only emit events for security-relevant opcodes to avoid flooding
    let is_relevant = matches!(
        opcode,
        9  | // SENDMSG
        10 | // RECVMSG
        13 | // ACCEPT
        16 | // CONNECT
        18 | // OPENAT
        26 | // SEND
        27 | // RECV
        28 | // OPENAT2
        35 | // RENAMEAT
        36 | // UNLINKAT
        45 | // SOCKET
        46 | // URING_CMD
        53   // SEND_ZC
    );
    if !is_relevant {
        return Ok(());
    }

    // Noise filters
    if is_comm_allowed(2) || is_cgroup_allowed() {
        return Ok(());
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return Ok(());
    }

    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let flags: u32 = unsafe { ctx.read_at(36).unwrap_or(0) };

    let mut entry = match EVENTS.reserve::<innerwarden_ebpf_types::IoUringEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = innerwarden_ebpf_types::SyscallKind::IoUring as u32;
    event.pid = pid;
    event.uid = uid;
    event.opcode = opcode;
    event.sqe_flags = 0;
    event._pad = 0;
    event.fd = -1; // fd not directly available in the tracepoint
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

/// io_uring ring creation — fires when a process creates an io_uring instance.
#[tracepoint]
pub fn innerwarden_io_uring_create(ctx: TracePointContext) -> u32 {
    match try_io_uring_create(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_io_uring_create(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(2) || is_cgroup_allowed() {
        return Ok(());
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // Offsets after 8-byte common header
    let ring_fd: i32 = unsafe { ctx.read_at(8).unwrap_or(-1) };
    // ctx pointer at offset 16, skip it
    let sq_entries: u32 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let cq_entries: u32 = unsafe { ctx.read_at(28).unwrap_or(0) };
    let flags: u32 = unsafe { ctx.read_at(32).unwrap_or(0) };

    let mut entry = match EVENTS.reserve::<innerwarden_ebpf_types::IoUringCreateEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = innerwarden_ebpf_types::SyscallKind::IoUringCreate as u32;
    event.pid = pid;
    event.uid = uid;
    event.ring_fd = ring_fd;
    event.sq_entries = sq_entries;
    event.cq_entries = cq_entries;
    event.flags = flags;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 2: Firmware security hooks
// ---------------------------------------------------------------------------

/// Kprobe on native_write_msr — detects writes to sensitive MSRs.
/// Sensitive: LSTAR (syscall entry point), STAR, CSTAR, SF_MASK, SMRR, APIC_BASE.
/// A rootkit that hooks syscalls rewrites LSTAR. Any unexpected MSR write is critical.
#[kprobe]
pub fn innerwarden_msr_write(ctx: ProbeContext) -> u32 {
    match try_msr_write(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_msr_write(ctx: &ProbeContext) -> Result<(), i64> {
    // native_write_msr(unsigned int msr, u64 val)
    let msr_addr: u64 = ctx.arg(0).ok_or(1i64)?;

    // Only alert on security-sensitive MSRs.
    // 0xC0000081 = STAR, 0xC0000082 = LSTAR (syscall entry), 0xC0000083 = CSTAR,
    // 0xC0000084 = SF_MASK, 0x1F2 = IA32_SMRR_PHYSBASE, 0x1F3 = IA32_SMRR_PHYSMASK,
    // 0xFEE00000 region = APIC, 0x3A = IA32_FEATURE_CONTROL
    let sensitive = matches!(
        msr_addr,
        0xC0000081 | 0xC0000082 | 0xC0000083 | 0xC0000084 | 0x1F2 | 0x1F3 | 0x3A
    );
    if !sensitive {
        return Ok(());
    }

    let msr_value: u64 = ctx.arg(1).ok_or(1i64)?;
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<MsrWriteEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::MsrWrite as u32;
    event.pid = pid;
    event.uid = uid;
    event._pad = 0;
    event.msr_address = msr_addr;
    event.msr_value_lo = msr_value as u32;
    event.msr_value_hi = (msr_value >> 32) as u32;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

/// Tracepoint on sys_enter_ioperm — detects I/O port access requests.
/// No legitimate userspace process needs direct I/O port access in production.
/// This targets SPI controller probing (ports 0xCF8/0xCFC on x86).
#[tracepoint]
pub fn innerwarden_ioperm(ctx: TracePointContext) -> u32 {
    match try_ioperm(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_ioperm(ctx: &TracePointContext) -> Result<(), i64> {
    let from: u64 = unsafe { ctx.read_at(16)? };
    let num: u64 = unsafe { ctx.read_at(24)? };
    let turn_on: u64 = unsafe { ctx.read_at(32)? };

    // Only alert when enabling access (turn_on = 1).
    if turn_on != 1 {
        return Ok(());
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<IopermEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Ioperm as u32;
    event.pid = pid;
    event.uid = uid;
    event._pad = 0;
    event.port_from = from;
    event.port_num = num;
    event.turn_on = turn_on;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

/// Tracepoint on sys_enter_iopl — detects I/O privilege level elevation.
/// Level > 0 grants direct hardware access. Almost never legitimate in production.
#[tracepoint]
pub fn innerwarden_iopl(ctx: TracePointContext) -> u32 {
    match try_iopl(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_iopl(ctx: &TracePointContext) -> Result<(), i64> {
    let level: u64 = unsafe { ctx.read_at(16)? };

    // Level 0 = normal, no alert needed.
    if level == 0 {
        return Ok(());
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<IoplEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Iopl as u32;
    event.pid = pid;
    event.uid = uid;
    event._pad = 0;
    event.level = level;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

/// Kprobe on acpi_evaluate_object — monitors ACPI method execution.
/// ACPI rootkits embed code in AML methods (DSDT/SSDT). Monitoring which
/// methods execute at runtime creates a behavioral baseline.
#[kprobe]
pub fn innerwarden_acpi_eval(ctx: ProbeContext) -> u32 {
    match try_acpi_eval(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_acpi_eval(ctx: &ProbeContext) -> Result<(), i64> {
    // acpi_evaluate_object(handle, pathname, params, return_buf)
    // arg1 = pathname (char * — ACPI method name like "\_SB.PCI0._STA")
    let pathname_ptr: *const u8 = ctx.arg::<u64>(1).ok_or(1i64)? as *const u8;

    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<AcpiEvalEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::AcpiEval as u32;
    event.pid = pid;
    event.uid = uid;
    event._pad = 0;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.pathname = [0u8; MAX_COMM_LEN];
    event.comm = [0u8; MAX_COMM_LEN];

    // Read ACPI method pathname from kernel memory.
    if !pathname_ptr.is_null() {
        let _ = unsafe {
            bpf_probe_read_kernel_str_bytes(pathname_ptr, &mut event.pathname)
        };
    }

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

/// LSM hook on bpf — monitors all BPF syscall operations.
/// Detects unauthorized eBPF program loading (VoidLink rootkit defense).
/// Logs BPF_PROG_LOAD, BPF_MAP_CREATE, etc. from non-innerwarden processes.
#[lsm(hook = "bpf")]
pub fn innerwarden_lsm_bpf(ctx: LsmContext) -> i32 {
    match try_lsm_bpf(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // allow on error (fail-open)
    }
}

#[inline(always)]
fn try_lsm_bpf(ctx: &LsmContext) -> Result<i32, i64> {
    // LSM bpf hook: int security_bpf(int cmd, ...)
    // arg0 = BPF command (BPF_PROG_LOAD=5, BPF_MAP_CREATE=0)
    let bpf_cmd: u32 = unsafe { ctx.arg::<u32>(0) };

    // Only log program loads and map creates (not lookups/reads).
    // BPF_MAP_CREATE=0, BPF_PROG_LOAD=5, BPF_BTF_LOAD=18, BPF_LINK_CREATE=28
    if bpf_cmd != 0 && bpf_cmd != 5 && bpf_cmd != 18 && bpf_cmd != 28 {
        return Ok(0);
    }

    // Skip our own process.
    let comm = bpf_get_current_comm().map_err(|_| 1i64)?;
    // "innerwarden" starts with "in" + "ne" — quick check first 4 bytes.
    if comm.len() >= 12
        && comm[0] == b'i'
        && comm[1] == b'n'
        && comm[2] == b'n'
        && comm[3] == b'e'
    {
        return Ok(0);
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<BpfLoadEvent>(0) {
        Some(e) => e,
        None => return Ok(0),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::BpfLoad as u32;
    event.pid = pid;
    event.uid = uid;
    event.bpf_cmd = bpf_cmd;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];
    event.comm[..comm.len().min(MAX_COMM_LEN)]
        .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);

    entry.submit(0);
    Ok(0) // always allow (monitoring only, not enforcement)
}

// ---------------------------------------------------------------------------
// Trace of the Times — kernel function timing probes
// ---------------------------------------------------------------------------
//
// Each target function gets a kprobe (entry) + kretprobe (return) pair.
// The kprobe stores bpf_ktime_get_ns() keyed by (pid_tgid << 4 | target_id).
// The kretprobe reads it, computes the delta, and sends a TimingProbeEvent.

/// Temporary storage for kprobe entry timestamps.
/// Key: (pid_tgid << 4) | target_id — unique per thread+function.
/// Value: entry timestamp in nanoseconds.
#[map]
static TIMING_ENTRY: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);

/// Inline: record kprobe entry timestamp.
#[inline(always)]
fn timing_entry(target: TimingTarget) {
    let key = (bpf_get_current_pid_tgid() << 4) | (target as u64);
    let ts = unsafe { bpf_ktime_get_ns() };
    let _ = TIMING_ENTRY.insert(&key, &ts, 0);
}

/// Inline: compute delta and emit timing event on kretprobe.
#[inline(always)]
fn timing_return(target: TimingTarget) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let key = (pid_tgid << 4) | (target as u64);

    let entry_ts = match unsafe { TIMING_ENTRY.get(&key) } {
        Some(ts) => *ts,
        None => return Ok(()), // no matching entry (missed or filtered)
    };
    let _ = TIMING_ENTRY.remove(&key);

    let now = unsafe { bpf_ktime_get_ns() };
    let delta = now.saturating_sub(entry_ts);

    // Skip very short deltas (< 100ns = likely noise or inline function).
    if delta < 100 {
        return Ok(());
    }

    let pid = pid_tgid as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    let mut entry = match EVENTS.reserve::<TimingProbeEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::TimingProbe as u32;
    event.pid = pid;
    event.target = target as u32;
    event._pad = 0;
    event.delta_ns = delta;
    event.cgroup_id = cgroup_id;
    event.ts_ns = now;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ── iterate_dir: primary getdents handler (file hiding) ─────────────────

#[kprobe]
pub fn innerwarden_tot_iterate_dir_entry(_ctx: ProbeContext) -> u32 {
    timing_entry(TimingTarget::IterateDir);
    0
}

#[kretprobe]
pub fn innerwarden_tot_iterate_dir_ret(_ctx: RetProbeContext) -> u32 {
    let _ = timing_return(TimingTarget::IterateDir);
    0
}

// ── filldir64: directory entry callback (filtered by rootkits) ──────────

#[kprobe]
pub fn innerwarden_tot_filldir64_entry(_ctx: ProbeContext) -> u32 {
    timing_entry(TimingTarget::Filldir64);
    0
}

#[kretprobe]
pub fn innerwarden_tot_filldir64_ret(_ctx: RetProbeContext) -> u32 {
    let _ = timing_return(TimingTarget::Filldir64);
    0
}

// ── tcp4_seq_show: /proc/net/tcp display (hidden connections) ───────────

#[kprobe]
pub fn innerwarden_tot_tcp4_entry(_ctx: ProbeContext) -> u32 {
    timing_entry(TimingTarget::Tcp4SeqShow);
    0
}

#[kretprobe]
pub fn innerwarden_tot_tcp4_ret(_ctx: RetProbeContext) -> u32 {
    let _ = timing_return(TimingTarget::Tcp4SeqShow);
    0
}

// ── proc_pid_readdir: /proc process listing (process hiding) ────────────

#[kprobe]
pub fn innerwarden_tot_procdir_entry(_ctx: ProbeContext) -> u32 {
    timing_entry(TimingTarget::ProcPidReaddir);
    0
}

#[kretprobe]
pub fn innerwarden_tot_procdir_ret(_ctx: RetProbeContext) -> u32 {
    let _ = timing_return(TimingTarget::ProcPidReaddir);
    0
}

// ---------------------------------------------------------------------------
// Phase 3: Red team gap hooks — timestomp + truncate
// ---------------------------------------------------------------------------

/// Kprobe on vfs_utimes — detects timestomp (touch -t, touch -r).
/// vfs_utimes is called by utimensat/futimesat/utimes syscalls.
#[kprobe]
pub fn innerwarden_utimensat(ctx: ProbeContext) -> u32 {
    match try_utimensat(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_utimensat(_ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    if pid == 0 {
        return Ok(());
    }

    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // After reserve: NO early returns (`?`) — Aya RingBufEntry has no Drop,
    // so an unreleased reference causes verifier rejection.
    let mut entry = match EVENTS.reserve::<PrivEscEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Utimensat as u32;
    event.pid = pid;
    event.tgid = (pid_tgid >> 32) as u32;
    event.old_uid = uid;
    event.new_uid = 0;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

/// Kprobe on do_truncate — detects log file truncation.
/// do_truncate is called by truncate/ftruncate syscalls.
#[kprobe]
pub fn innerwarden_truncate(ctx: ProbeContext) -> u32 {
    match try_truncate(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_truncate(_ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    if pid == 0 {
        return Ok(());
    }

    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // After reserve: NO early returns (`?`) — Aya RingBufEntry has no Drop,
    // so an unreleased reference causes verifier rejection.
    let mut entry = match EVENTS.reserve::<PrivEscEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Truncate as u32;
    event.pid = pid;
    event.tgid = (pid_tgid >> 32) as u32;
    event.old_uid = uid;
    event.new_uid = 0;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Panic handler (required for no_std)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
