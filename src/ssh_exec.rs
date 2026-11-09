//! Gated SSH command execution — a SEPARATE path from the HTTP client, for
//! credential-reuse / credential-disclosure exploits where the flag is only
//! reachable over SSH (XBEN-042: creds leaked in /source, flag in ~pedro over SSH).
//!
//! Shells out to `sshpass` + `ssh` so there's no new Rust dependency and no C-library
//! or async-runtime build cost; the molly image ships `sshpass` + `openssh-client`. It
//! does NO gating itself — `fetch::HttpClient::ssh_exec_gated` runs the SAME
//! scope/armed/rate-limit/audit pre-flight first (on the target's host), then calls this.
//! Password auth only (the disclosed-credential case).
//!
//! ## Hardening (do not regress)
//!
//! - **No shell.** `command` and the credentials are passed as argv (no shell), so
//!   there's no shell-injection surface in the command itself.
//! - **No option injection via the destination.** `user` and `host` are validated
//!   (never empty, never starting with `-`, no `@`/whitespace/control bytes) and the
//!   login name is passed as `-l <user>`, never as the `user@host` destination. `--`
//!   terminates ssh option parsing *before* the host, so neither host nor command can
//!   be reparsed as an ssh option (e.g. a `-oProxyCommand=…` username — CWE-88).
//! - **Password not in argv.** The password is passed via the `SSHPASS` env var
//!   (`sshpass -e`), not `sshpass -p <password>`, so it is not visible in the process
//!   table / `/proc/<pid>/cmdline` to other local users (CWE-214).
//! - **Host-key verification on by default.** By default ssh uses
//!   `StrictHostKeyChecking=accept-new` with a persistent known_hosts file, so a key is
//!   pinned on first contact and an active MITM cannot silently impersonate a known host
//!   (CWE-295). Set `MOLLY_SSH_INSECURE_HOST_KEY=1` to restore the old fully-disabled
//!   behavior for ephemeral hosts whose keys legitimately change between runs (see env
//!   tunables in CLAUDE.md); that opt-in is explicitly insecure.

use std::process::Command;

#[derive(Debug)]
pub struct SshResult {
    pub stdout: String,
    pub exit_status: i32,
}

/// Reject a `user`/`host` value that ssh could reparse as an option or that could
/// confuse the destination grammar. Empty, a leading `-`, or an embedded `@`,
/// whitespace, or control byte are all refused.
fn validate_ssh_component(kind: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("ssh_exec: {kind} must not be empty"));
    }
    if value.starts_with('-') {
        return Err(format!(
            "ssh_exec: {kind} must not start with '-' (would be parsed as an ssh option): {value:?}"
        ));
    }
    if let Some(bad) = value
        .chars()
        .find(|c| *c == '@' || c.is_whitespace() || c.is_control())
    {
        return Err(format!(
            "ssh_exec: {kind} contains a disallowed character {bad:?}: {value:?}"
        ));
    }
    Ok(())
}

/// True when an env var is set to a truthy value (`1`/`true`/`yes`/`on`, case-insensitive).
fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| {
            matches!(
                v.trim().to_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Path to the persistent known_hosts file used for TOFU host-key pinning.
/// `MOLLY_SSH_KNOWN_HOSTS` overrides it; otherwise `$HOME/.molly/known_hosts`,
/// falling back to `./.molly/known_hosts` when `$HOME` is unset. The parent
/// directory is created best-effort (ssh creates the file itself on first use).
fn known_hosts_path() -> String {
    if let Ok(p) = std::env::var("MOLLY_SSH_KNOWN_HOSTS") {
        if !p.trim().is_empty() {
            return p;
        }
    }
    let base = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let dir = std::path::Path::new(&base).join(".molly");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("known_hosts").to_string_lossy().to_string()
}

/// ssh host-key `-o` options. Secure by default (accept-new + persistent
/// known_hosts); `MOLLY_SSH_INSECURE_HOST_KEY=1` restores the fully-disabled
/// behavior for ephemeral hosts that cannot be pinned.
fn host_key_options() -> Vec<String> {
    host_key_options_for(env_flag("MOLLY_SSH_INSECURE_HOST_KEY"))
}

/// Pure form of [`host_key_options`], parameterized on the insecure opt-in so it
/// is testable without mutating a process-global env var.
fn host_key_options_for(insecure: bool) -> Vec<String> {
    if insecure {
        vec![
            "-o".into(),
            "StrictHostKeyChecking=no".into(),
            "-o".into(),
            "UserKnownHostsFile=/dev/null".into(),
        ]
    } else {
        vec![
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            format!("UserKnownHostsFile={}", known_hosts_path()),
        ]
    }
}

/// Run `command` on `host:port` as `user`/`password` over SSH, returning stdout +
/// the exit status. Non-interactive, password-only. Never panics; returns Err on a
/// validation failure or a spawn/lookup failure (e.g. sshpass not installed).
///
/// `command` is sent verbatim as a single argv element after `--`, so it can be
/// arbitrary (it is the remote command to run); `user` and `host` are validated so
/// they cannot be reparsed as ssh options. See the module docs for the full hardening
/// contract.
pub(crate) fn ssh_exec(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    command: &str,
    connect_timeout_secs: u64,
) -> Result<SshResult, String> {
    validate_ssh_component("username", user)?;
    validate_ssh_component("host", host)?;

    let mut cmd = Command::new("sshpass");
    cmd.arg("-e") // read the password from the SSHPASS env var, never argv
        .env("SSHPASS", password)
        .arg("ssh");
    cmd.args(host_key_options());
    cmd.args([
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "NumberOfPasswordPrompts=1",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=no",
        // Tear down a hung session instead of wedging the calling thread
        // indefinitely: ~3 missed 15s keepalives (~45s of silence) ends it.
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
    ]);
    cmd.arg("-o")
        .arg(format!("ConnectTimeout={connect_timeout_secs}"))
        // Login name as an option value — never the `user@host` destination,
        // so a username can't smuggle ssh options.
        .arg("-l")
        .arg(user)
        .arg("-p")
        .arg(port.to_string())
        // End option parsing BEFORE the host, so neither host nor command can be
        // reparsed as an ssh option.
        .arg("--")
        .arg(host)
        .arg(command);

    let out = cmd.output().map_err(|e| {
        format!("ssh_exec: could not run sshpass/ssh ({e}) — sshpass/openssh-client installed?")
    })?;

    Ok(SshResult {
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        exit_status: out.status.code().unwrap_or(-1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_username_starting_with_dash() {
        // CWE-88: a `-oProxyCommand=…` username must be refused at validation,
        // before any sshpass/ssh process is spawned.
        let err = ssh_exec(
            "host",
            22,
            "-oProxyCommand=touch /tmp/pwned",
            "pw",
            "id",
            10,
        )
        .unwrap_err();
        assert!(err.contains("username"), "got: {err}");
        assert!(err.contains("option"), "got: {err}");
    }

    #[test]
    fn rejects_username_with_at_sign() {
        let err = ssh_exec("host", 22, "user@elsewhere", "pw", "id", 10).unwrap_err();
        assert!(err.contains("username"), "got: {err}");
    }

    #[test]
    fn rejects_username_with_whitespace() {
        let err = ssh_exec("host", 22, "user name", "pw", "id", 10).unwrap_err();
        assert!(err.contains("username"), "got: {err}");
    }

    #[test]
    fn rejects_host_starting_with_dash() {
        let err = ssh_exec("-oProxyCommand=x", 22, "user", "pw", "id", 10).unwrap_err();
        assert!(err.contains("host"), "got: {err}");
    }

    #[test]
    fn rejects_empty_username_and_host() {
        assert!(ssh_exec("host", 22, "", "pw", "id", 10)
            .unwrap_err()
            .contains("username"));
        assert!(ssh_exec("", 22, "user", "pw", "id", 10)
            .unwrap_err()
            .contains("host"));
    }

    #[test]
    fn host_key_options_default_is_secure() {
        // Default must pin, not disable, host-key checking (CWE-295). Tested via
        // the pure form so it never races on the process-global env var.
        let opts = host_key_options_for(false);
        assert!(opts.iter().any(|o| o == "StrictHostKeyChecking=accept-new"));
        assert!(!opts.iter().any(|o| o == "UserKnownHostsFile=/dev/null"));
    }

    #[test]
    fn host_key_options_insecure_opt_in_restores_disabled_checking() {
        let opts = host_key_options_for(true);
        assert!(opts.iter().any(|o| o == "StrictHostKeyChecking=no"));
        assert!(opts.iter().any(|o| o == "UserKnownHostsFile=/dev/null"));
    }

    #[test]
    fn env_flag_truthiness() {
        let var = "MOLLY_TEST_SSH_ENV_FLAG_XYZ";
        std::env::remove_var(var);
        assert!(!env_flag(var));
        std::env::set_var(var, "1");
        assert!(env_flag(var));
        std::env::set_var(var, "TRUE");
        assert!(env_flag(var));
        std::env::set_var(var, "0");
        assert!(!env_flag(var));
        std::env::set_var(var, "nope");
        assert!(!env_flag(var));
        std::env::remove_var(var);
    }
}
