//! Gated SSH command execution — a SEPARATE path from the HTTP client, for
//! credential-reuse / credential-disclosure exploits where the flag is only
//! reachable over SSH (XBEN-042: creds leaked in /source, flag in ~pedro over SSH).
//!
//! Shells out to `sshpass` + `ssh` so there's no new Rust dependency and no C-library
//! or async-runtime build cost; the molly image ships `sshpass` + `openssh-client`. It
//! does NO gating itself — `fetch::HttpClient::ssh_exec_gated` runs the SAME
//! scope/armed/rate-limit/audit pre-flight first (on the target's host), then calls this.
//! Password auth only (the disclosed-credential case); host-key checking is disabled
//! because benchmark hosts are ephemeral.

use std::process::Command;

#[derive(Debug)]
pub struct SshResult {
    pub stdout: String,
    pub exit_status: i32,
}

/// Run `command` on `host:port` as `user`/`password` over SSH, returning stdout +
/// the exit status. Non-interactive, password-only, host-key checks off. Never panics;
/// returns Err on a spawn/lookup failure (e.g. sshpass not installed). `command` and
/// the credentials are passed as argv (no shell), so there's no shell-injection surface.
pub fn ssh_exec(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    command: &str,
    connect_timeout_secs: u64,
) -> Result<SshResult, String> {
    let out = Command::new("sshpass")
        .arg("-p")
        .arg(password)
        .arg("ssh")
        .args([
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "LogLevel=ERROR",
            "-o", "BatchMode=no",
        ])
        .arg("-o")
        .arg(format!("ConnectTimeout={connect_timeout_secs}"))
        .arg("-p")
        .arg(port.to_string())
        .arg(format!("{user}@{host}"))
        .arg("--")
        .arg(command)
        .output()
        .map_err(|e| {
            format!("ssh_exec: could not run sshpass/ssh ({e}) — sshpass/openssh-client installed?")
        })?;

    Ok(SshResult {
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        exit_status: out.status.code().unwrap_or(-1),
    })
}
