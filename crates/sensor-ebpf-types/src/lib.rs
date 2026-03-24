//! Shared types between eBPF kernel programs and the userspace sensor.
//!
//! These structs are sent through eBPF ring buffers from kernel space
//! to userspace. They must be `#[repr(C)]` for cross-boundary compatibility.

#![no_std]

/// Maximum blocked IPs in XDP blocklist map.
pub const XDP_BLOCKLIST_MAX: u32 = 10_000;

/// Maximum command line length captured from execve.
pub const MAX_COMM_LEN: usize = 64;
/// Maximum filename/path length.
pub const MAX_FILENAME_LEN: usize = 256;
/// Maximum number of argv entries captured.
pub const MAX_ARGS: usize = 8;
/// Maximum length of each argv entry.
pub const MAX_ARG_LEN: usize = 128;

// ---------------------------------------------------------------------------
// Syscall event types
// ---------------------------------------------------------------------------

/// Identifies which syscall triggered the event.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SyscallKind {
    /// Process execution (execve / execveat)
    Execve = 1,
    /// Outbound network connection (connect)
    Connect = 2,
    /// File open (openat)
    FileOpen = 3,
    /// Write to sensitive path
    FileWrite = 4,
    /// Privilege escalation (commit_creds: uid changed to root)
    PrivEsc = 5,
    /// LSM blocked execution (bprm_check_security denied /tmp, /dev/shm)
    LsmBlocked = 6,
    /// Process exit (sched_process_exit)
    ProcessExit = 7,
}

/// Event emitted by the eBPF `execve` tracepoint.
///
/// Captures: who executed what, with which arguments, from which parent.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveEvent {
    /// Syscall type (always SyscallKind::Execve)
    pub kind: u32,
    /// Process ID of the new process
    pub pid: u32,
    /// Thread group ID
    pub tgid: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Cgroup ID (identifies container namespace, 0 = host)
    pub cgroup_id: u64,
    /// Process name (comm)
    pub comm: [u8; MAX_COMM_LEN],
    /// Filename being executed
    pub filename: [u8; MAX_FILENAME_LEN],
    /// First N argv entries (null-terminated within each slot)
    pub argv: [[u8; MAX_ARG_LEN]; MAX_ARGS],
    /// Number of argv entries actually captured
    pub argc: u32,
    /// Timestamp (nanoseconds since boot)
    pub ts_ns: u64,
}

/// Event emitted by the `connect` tracepoint.
///
/// Captures: who connected where (IP + port).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub kind: u32,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Cgroup ID (identifies container namespace, 0 = host)
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    /// Destination IPv4 address (network byte order)
    pub dst_addr: u32,
    /// Destination port (host byte order)
    pub dst_port: u16,
    /// Address family (AF_INET = 2, AF_INET6 = 10)
    pub family: u16,
    pub ts_ns: u64,
}

/// Event emitted by `openat` tracepoint for sensitive paths.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileOpenEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Cgroup ID (identifies container namespace, 0 = host)
    pub cgroup_id: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_FILENAME_LEN],
    /// Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
    pub flags: u32,
    pub ts_ns: u64,
}

/// Event emitted by the `commit_creds` kprobe — privilege escalation detection.
///
/// Fires when a process's UID transitions from non-root to root
/// through a path other than legitimate login (sudo, su, sshd, login).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrivEscEvent {
    pub kind: u32,
    pub pid: u32,
    pub tgid: u32,
    /// UID before the transition (the current uid at kprobe entry)
    pub old_uid: u32,
    /// UID after the transition (read from new cred struct)
    pub new_uid: u32,
    /// Cgroup ID (container awareness)
    pub cgroup_id: u64,
    /// Process name
    pub comm: [u8; MAX_COMM_LEN],
    pub ts_ns: u64,
}

/// Event emitted by `sched:sched_process_exit` tracepoint.
///
/// Fires when any process exits. Used by the rootkit detector to track
/// process lifecycle — a process seen by execve but never by exit + missing
/// from /proc is a strong rootkit indicator.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExitEvent {
    pub kind: u32,
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; MAX_COMM_LEN],
    pub exit_code: i32,
    pub ts_ns: u64,
}

// ---------------------------------------------------------------------------
// Helpers (usable in both kernel and userspace)
// ---------------------------------------------------------------------------

/// Extract a null-terminated string from a fixed-size byte array.
/// Returns the bytes up to (not including) the first null byte.
pub fn bytes_to_str(buf: &[u8]) -> &[u8] {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    &buf[..len]
}
