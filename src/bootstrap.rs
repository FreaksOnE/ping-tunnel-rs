use std::fmt;

use crate::constants::SYSCTL_ICMP_ECHO_IGNORE_ALL;
use crate::error::TransportError;

/// RAII guard that sets `icmp_echo_ignore_all=1` on creation and restores
/// the original value on drop.
///
/// Only needed when operating in Echo Request mode. In Echo Reply mode,
/// the kernel does not auto-reply to incoming Echo Replies, so no sysctl
/// adjustment is necessary.
///
/// ## Blocking I/O
///
/// Both creation and drop use `std::fs` (blocking I/O) to read/write
/// the procfs sysctl file. This is intentional: the guard is created
/// once at startup and dropped once at shutdown, so the sub-millisecond
/// procfs access does not affect steady-state performance. The `Drop`
/// impl cannot be async, so blocking I/O is the only option there.
///
/// ## Shutdown behavior
///
/// When the guard is dropped (on normal shutdown or panic unwind), the
/// `Drop` implementation writes the *original* sysctl value back to
/// `/proc/sys/net/ipv4/icmp_echo_ignore_all`. If the value was already
/// `"1"` before Singularity started, it remains `"1"` after exit; if it
/// was `"0"`, it is restored to `"0"`. A failure to restore is logged
/// at `error!` level but does not panic.
pub struct SysctlGuard {
    path: &'static str,
    original_value: String,
}

impl SysctlGuard {
    /// Read the current value of `icmp_echo_ignore_all` and set it to `1`.
    ///
    /// The original value is stored and will be restored when the guard is
    /// dropped.
    pub fn suppress_echo_replies() -> Result<Self, TransportError> {
        let original = std::fs::read_to_string(SYSCTL_ICMP_ECHO_IGNORE_ALL)
            .map(|s| s.trim().to_owned())
            .map_err(|source| TransportError::Sysctl {
                path: SYSCTL_ICMP_ECHO_IGNORE_ALL.into(),
                source,
            })?;

        if original != "1" {
            std::fs::write(SYSCTL_ICMP_ECHO_IGNORE_ALL, "1").map_err(
                |source| TransportError::Sysctl {
                    path: SYSCTL_ICMP_ECHO_IGNORE_ALL.into(),
                    source,
                },
            )?;
            tracing::info!(
                path = SYSCTL_ICMP_ECHO_IGNORE_ALL,
                previous = %original,
                "suppressed kernel ICMP echo replies"
            );
        } else {
            tracing::debug!(
                path = SYSCTL_ICMP_ECHO_IGNORE_ALL,
                "kernel ICMP echo replies already suppressed"
            );
        }

        Ok(Self { path: SYSCTL_ICMP_ECHO_IGNORE_ALL, original_value: original })
    }
}

impl Drop for SysctlGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::write(self.path, &self.original_value) {
            tracing::error!(
                path = self.path,
                error = %e,
                "failed to restore sysctl value"
            );
        } else {
            tracing::info!(
                path = self.path,
                restored = %self.original_value,
                "restored kernel ICMP echo setting"
            );
        }
    }
}

impl fmt::Debug for SysctlGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SysctlGuard")
            .field("path", &self.path)
            .field("original_value", &self.original_value)
            .finish()
    }
}
