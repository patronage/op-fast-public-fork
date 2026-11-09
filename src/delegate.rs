use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::account::{Auth, TOKEN_ENV};
use crate::config::Config;
use crate::error::{DelegateError, ErrorClass};

/// Deadline when stderr is a TTY (someone may be at the desk to approve).
pub const INTERACTIVE_DEADLINE: Duration = Duration::from_secs(60);
/// Plain network deadline for service-account (and ambient-token) calls.
pub const NETWORK_DEADLINE: Duration = Duration::from_secs(30);

/// Incremented on every delegate child. A copy of op-fast that finds
/// another op-fast copy on PATH would otherwise recurse forever.
const DEPTH_ENV: &str = "OP_FAST_DELEGATE_DEPTH";
const MAX_DEPTH: u32 = 6;

/// Code-signing requirement a delegate must satisfy before op-fast hands it
/// a service-account token: Apple-anchored Developer ID issued to AgileBits
/// (1Password), team 2BUA8C4S2C.
pub const OP_SIGNING_REQUIREMENT: &str =
    "anchor apple generic and certificate leaf[subject.OU] = \"2BUA8C4S2C\"";

/// How one delegate call authenticates, with its token (if any) and deadline.
pub struct CallAuth {
    pub auth: Auth,
    token: Option<String>,
    pub deadline: Duration,
}

impl CallAuth {
    pub fn new(auth: Auth, token: Option<String>, config: &Config) -> Self {
        let deadline = deadline_for(&auth, config);
        Self {
            auth,
            token,
            deadline,
        }
    }

    /// Remove any token text from delegate output before it is shown.
    pub fn redact(&self, text: &str) -> String {
        match &self.token {
            Some(t) if !t.is_empty() => text.replace(t.as_str(), "<redacted>"),
            _ => text.to_string(),
        }
    }
}

/// Deadline for a delegate call with `auth`.
pub fn deadline_for(auth: &Auth, config: &Config) -> Duration {
    deadline_for_tty(auth, config, std::io::stderr().is_terminal())
}

pub fn deadline_for_tty(auth: &Auth, config: &Config, stderr_is_tty: bool) -> Duration {
    if auth.may_prompt() {
        if stderr_is_tty {
            INTERACTIVE_DEADLINE
        } else {
            config.prompt_timeout
        }
    } else {
        NETWORK_DEADLINE
    }
}

pub struct OpDelegate {
    command: PathBuf,
    source: &'static str,
}

pub struct Output {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub timed_out: bool,
}

/// Resolve a configured delegate path: absolute only, canonicalized.
fn absolute_delegate(raw: &Path, what: &str) -> Result<PathBuf> {
    if !raw.is_absolute() {
        bail!(
            "{} must be an absolute path (got a relative path); refusing to guess",
            what
        );
    }
    fs::canonicalize(raw).with_context(|| format!("Failed to resolve {}: {}", what, raw.display()))
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Candidate `op` binaries from absolute PATH entries only. Empty and
/// relative entries (including `.`) are ignored so a repository-local `op`
/// can never become the delegate.
pub fn path_candidates(path_var: Option<&std::ffi::OsStr>) -> Vec<PathBuf> {
    let Some(path_var) = path_var else {
        return Vec::new();
    };
    env::split_paths(path_var)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("op"))
        .filter(|p| is_executable_file(p))
        .collect()
}

impl OpDelegate {
    const ENV_VAR_NAME: &'static str = "OP_FAST_COMMAND";

    /// Resolve the real `op`: `OP_FAST_COMMAND`, then config `op_command`,
    /// then the first `op` in an absolute PATH entry that is not this
    /// executable.
    pub fn new(config: &Config) -> Result<Self> {
        let depth = current_depth();
        if depth >= MAX_DEPTH {
            bail!(
                "op-fast is delegating to itself ({} levels deep); set {} or op_command to the real `op`",
                depth,
                Self::ENV_VAR_NAME
            );
        }

        let me = env::current_exe().and_then(fs::canonicalize).ok();
        let check_not_self = |path: PathBuf, what: &str| -> Result<PathBuf> {
            if me.as_ref() == Some(&path) {
                bail!("Detected self-reference: {} points at op-fast itself", what);
            }
            Ok(path)
        };

        if let Some(var) = env::var_os(Self::ENV_VAR_NAME).filter(|v| !v.is_empty()) {
            let path = absolute_delegate(Path::new(&var), Self::ENV_VAR_NAME)?;
            return Ok(Self {
                command: check_not_self(path, Self::ENV_VAR_NAME)?,
                source: "OP_FAST_COMMAND",
            });
        }

        if let Some(configured) = &config.op_command {
            let path = absolute_delegate(configured, "op_command")?;
            return Ok(Self {
                command: check_not_self(path, "op_command")?,
                source: "config op_command",
            });
        }

        for candidate in path_candidates(env::var_os("PATH").as_deref()) {
            let Ok(path) = candidate.canonicalize() else {
                continue;
            };
            if me.as_ref() == Some(&path) {
                log::debug!("Skipping {} (it is op-fast itself)", candidate.display());
                continue;
            }
            return Ok(Self {
                command: path,
                source: "PATH",
            });
        }

        bail!(
            "Could not find the real `op` in PATH (only op-fast itself, or nothing); set {} or op_command",
            Self::ENV_VAR_NAME
        )
    }

    pub fn path(&self) -> &Path {
        &self.command
    }

    pub fn source(&self) -> &'static str {
        self.source
    }

    /// Refuse to hand a service-account token to anything but a genuine,
    /// 1Password-signed `op`.
    pub fn verify_for_token(&self) -> Result<()> {
        verify_signature(&self.command)
    }

    /// A command for passthrough (inherited stdio, no deadline). `token`
    /// is set only after the delegate passes the signature check.
    pub fn command_with_token(&self, token: Option<&str>) -> Result<Command> {
        let mut cmd = self.command();
        if let Some(token) = token {
            self.verify_for_token()?;
            cmd.env(TOKEN_ENV, token);
        }
        Ok(cmd)
    }

    /// A command with no token (inherited stdio, no deadline).
    pub fn command(&self) -> Command {
        let mut cmd = Command::new(&self.command);
        cmd.env(DEPTH_ENV, (current_depth() + 1).to_string());
        cmd
    }

    /// Run `op` with captured output, killing its whole process group at
    /// `deadline`.
    pub fn exec(
        &self,
        args: &[OsString],
        stdin: Option<&[u8]>,
        auth: &CallAuth,
        deadline: Duration,
    ) -> Result<Output> {
        let mut cmd = self.command_with_token(auth.token.as_deref())?;
        cmd.args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Own process group, so a deadline kill takes grandchildren too.
            .process_group(0);

        let mut child = cmd.spawn().context("Failed to execute `op`")?;
        let pgid = child.id() as libc::pid_t;

        if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
            let data = data.to_vec();
            std::thread::spawn(move || {
                let _ = pipe.write_all(&data);
            });
        }

        let out_rx = spawn_reader(child.stdout.take());
        let err_rx = spawn_reader(child.stderr.take());

        let start = Instant::now();
        let mut timed_out = false;
        let code = loop {
            if let Some(status) = child.try_wait().context("Failed to wait for `op`")? {
                break status.code();
            }
            if start.elapsed() >= deadline {
                unsafe {
                    libc::killpg(pgid, libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                timed_out = true;
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };

        // Both pipes drain concurrently in their own threads. After a kill
        // the whole group is gone and the pipes close at once; after a
        // normal exit, a lingering helper holding a pipe costs at most the
        // grace period.
        let grace = if timed_out {
            Duration::from_millis(500)
        } else {
            Duration::from_secs(2)
        };
        let until = Instant::now() + grace;
        let stdout = collect(&out_rx, until);
        let stderr = collect(&err_rx, until);

        Ok(Output {
            code,
            stdout,
            stderr: auth.redact(&String::from_utf8_lossy(&stderr)),
            timed_out,
        })
    }

    fn failure(&self, out: &Output, auth: &CallAuth, what: &str, refs: &[&str]) -> DelegateError {
        if out.timed_out {
            let class = if auth.auth.may_prompt() {
                ErrorClass::ApprovalUnavailable
            } else {
                ErrorClass::Other
            };
            return DelegateError {
                class,
                code: 1,
                message: format!(
                    "op-fast: `op {}` did not finish within {}s (auth: {})",
                    what,
                    auth.deadline.as_secs(),
                    auth.auth.label()
                ),
            };
        }
        DelegateError {
            class: ErrorClass::classify(&out.stderr, refs, auth.auth.may_prompt()),
            code: out.code.unwrap_or(1),
            message: out.stderr.clone(),
        }
    }

    pub fn read(&self, reference: &str, auth: &CallAuth) -> Result<String> {
        let args = [OsString::from("read"), OsString::from(reference)];
        let out = self.exec(&args, None, auth, auth.deadline)?;
        if out.timed_out || out.code != Some(0) {
            return Err(self.failure(&out, auth, "read", &[reference]).into());
        }

        let value = String::from_utf8(out.stdout)
            .context("op read returned non-UTF8 output")?
            .trim_end()
            .to_string();

        Ok(value)
    }

    pub fn read_batch(
        &self,
        references: &[&str],
        auth: &CallAuth,
    ) -> Result<HashMap<String, String>> {
        if references.is_empty() {
            return Ok(HashMap::new());
        }

        let tag = std::process::id();
        let template = build_batch_template(references, tag);

        let out = self.exec(
            &[OsString::from("inject")],
            Some(template.as_bytes()),
            auth,
            auth.deadline,
        )?;
        if out.timed_out || out.code != Some(0) {
            return Err(self.failure(&out, auth, "inject", references).into());
        }

        let stdout = String::from_utf8(out.stdout).context("op inject returned non-UTF8 output")?;

        let values = parse_batch_output(&stdout, references.len(), tag)?;

        let mut result = HashMap::new();
        for (reference, value) in references.iter().zip(values) {
            result.insert(reference.to_string(), value);
        }

        Ok(result)
    }

    /// `op item get <item> --format json [--vault v]`. Returns the parsed
    /// JSON; the caller must never print field values from it.
    pub fn item_get_json(
        &self,
        item: &str,
        vault: Option<&str>,
        auth: &CallAuth,
    ) -> Result<serde_json::Value> {
        let mut args: Vec<OsString> = vec!["item".into(), "get".into(), item.into()];
        if let Some(v) = vault {
            args.push("--vault".into());
            args.push(v.into());
        }
        args.push("--format".into());
        args.push("json".into());
        let out = self.exec(&args, None, auth, auth.deadline)?;
        if out.timed_out || out.code != Some(0) {
            return Err(self.failure(&out, auth, "item get", &[item]).into());
        }
        serde_json::from_slice(&out.stdout).context("op item get returned invalid JSON")
    }

    /// `op --version`, which never prompts.
    pub fn version(&self) -> Option<String> {
        let auth = CallAuth {
            auth: Auth::Desktop,
            token: None,
            deadline: Duration::from_secs(5),
        };
        let out = self
            .exec(&[OsString::from("--version")], None, &auth, auth.deadline)
            .ok()?;
        (out.code == Some(0)).then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

/// Per-process cache of signature results, keyed by delegate path.
fn signature_cache() -> &'static std::sync::Mutex<HashMap<PathBuf, bool>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<PathBuf, bool>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Debug builds only: tests use a fake (unsigned) `op`, so they may opt out
/// of the signature check. Release builds compile this to `false`.
fn signature_check_skipped() -> bool {
    #[cfg(debug_assertions)]
    {
        if std::env::var_os("OP_FAST_TEST_UNSIGNED_DELEGATE").is_some_and(|v| v == "1") {
            return true;
        }
    }
    false
}

/// Verify that `path` is the genuine 1Password CLI before it may receive a
/// service-account token.
pub fn verify_signature(path: &Path) -> Result<()> {
    if signature_check_skipped() {
        return Ok(());
    }
    if !cfg!(target_os = "macos") {
        bail!(
            "service-account tokens are only supported on macOS for now; refusing to pass a token to {}",
            path.display()
        );
    }
    let cached = signature_cache()
        .lock()
        .ok()
        .and_then(|c| c.get(path).copied());
    let ok = match cached {
        Some(ok) => ok,
        None => {
            let ok = Command::new("/usr/bin/codesign")
                .arg("--verify")
                .arg(format!("-R={}", OP_SIGNING_REQUIREMENT))
                .arg(path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if let Ok(mut c) = signature_cache().lock() {
                c.insert(path.to_path_buf(), ok);
            }
            ok
        }
    };
    if !ok {
        bail!(
            "refusing to pass a service-account token to {}: it is not signed by 1Password (AgileBits, team 2BUA8C4S2C)",
            path.display()
        );
    }
    Ok(())
}

fn current_depth() -> u32 {
    env::var(DEPTH_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn spawn_reader<R: Read + Send + 'static>(pipe: Option<R>) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let Some(mut pipe) = pipe else {
            return;
        };
        let mut buf = [0u8; 8192];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

/// Gather chunks until the reader hangs up or `until` passes.
fn collect(rx: &mpsc::Receiver<Vec<u8>>, until: Instant) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let remaining = until.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(chunk) => out.extend_from_slice(&chunk),
            Err(_) => break,
        }
    }
    out
}

fn sentinel(tag: u32, index: usize, end: bool) -> String {
    let kind = if end { "END" } else { "BEGIN" };
    format!("--OPFAST:{}:{}:{}--", tag, kind, index)
}

pub(crate) fn build_batch_template(references: &[&str], tag: u32) -> String {
    let mut template = String::new();
    for (i, reference) in references.iter().enumerate() {
        template.push_str(&sentinel(tag, i, false));
        template.push('\n');
        template.push_str(reference);
        template.push('\n');
        template.push_str(&sentinel(tag, i, true));
        template.push('\n');
    }
    template
}

pub(crate) fn parse_batch_output(output: &str, expected: usize, tag: u32) -> Result<Vec<String>> {
    let mut values: Vec<String> = Vec::with_capacity(expected);
    let mut current: Option<Vec<&str>> = None;

    for line in output.lines() {
        match &mut current {
            None => {
                if line == sentinel(tag, values.len(), false) {
                    current = Some(Vec::new());
                } else {
                    bail!(
                        "op inject output contains unexpected content outside a sentinel section"
                    );
                }
            }
            Some(lines) => {
                if line == sentinel(tag, values.len(), true) {
                    values.push(lines.join("\n"));
                    current = None;
                } else if line.starts_with(&format!("--OPFAST:{}:", tag)) {
                    // A sentinel for this tag in the wrong position means a
                    // value contained forged markers; refuse rather than risk
                    // shifted assignments.
                    bail!("op inject output contains a misplaced sentinel marker");
                } else {
                    lines.push(line);
                }
            }
        }
    }

    if current.is_some() {
        bail!("op inject output ended inside an unterminated sentinel section");
    }
    if values.len() != expected {
        bail!(
            "op inject returned {} sections for {} references",
            values.len(),
            expected
        );
    }

    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_selection_by_tty_and_auth() {
        let mut config = Config::defaults();
        config.prompt_timeout = Duration::from_secs(7);
        assert_eq!(
            deadline_for_tty(&Auth::Desktop, &config, true),
            Duration::from_secs(60)
        );
        assert_eq!(
            deadline_for_tty(&Auth::Desktop, &config, false),
            Duration::from_secs(7)
        );
        for auth in [Auth::Ambient, Auth::Account("a".into())] {
            assert_eq!(
                deadline_for_tty(&auth, &config, true),
                Duration::from_secs(30)
            );
            assert_eq!(
                deadline_for_tty(&auth, &config, false),
                Duration::from_secs(30)
            );
        }
    }

    #[test]
    fn path_candidates_ignore_relative_and_empty_entries() {
        let base = std::env::temp_dir().join(format!("op-fast-path-test-{}", std::process::id()));
        let abs = base.join("abs");
        fs::create_dir_all(&abs).unwrap();
        let op = abs.join("op");
        fs::write(&op, "#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&op, fs::Permissions::from_mode(0o755)).unwrap();
        let path_var = format!(".::relative/dir:{}", abs.display());
        let found = path_candidates(Some(std::ffi::OsStr::new(&path_var)));
        assert_eq!(found, vec![op]);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn relative_configured_delegates_are_rejected() {
        assert!(absolute_delegate(Path::new("op"), "OP_FAST_COMMAND").is_err());
        assert!(absolute_delegate(Path::new("./bin/op"), "op_command").is_err());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn signature_requirement_rejects_other_signers() {
        // Apple-signed system binaries are not AgileBits-signed.
        let err = verify_signature(Path::new("/usr/bin/printenv")).unwrap_err();
        assert!(err.to_string().contains("/usr/bin/printenv"));
        // Unsigned scripts fail too.
        assert!(verify_signature(Path::new("/bin/sh")).is_err());
        // The genuine CLI passes, when installed on this machine.
        for real in ["/opt/homebrew/bin/op", "/usr/local/bin/op"] {
            let p = Path::new(real);
            if p.exists() {
                let canonical = p.canonicalize().unwrap();
                assert!(verify_signature(&canonical).is_ok(), "{}", real);
            }
        }
    }

    // Simulate what `op inject` produces for a template: each reference line
    // replaced by its value, all other lines passed through verbatim.
    fn simulate_inject(template: &str, values: &[&str]) -> String {
        let mut out = String::new();
        let mut value_iter = values.iter();
        for line in template.lines() {
            if line.starts_with("op://") {
                out.push_str(value_iter.next().expect("more refs than values"));
            } else {
                out.push_str(line);
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn template_wraps_each_reference_in_sentinels() {
        let template = build_batch_template(&["op://a/b/c", "op://d/e/f"], 42);
        assert_eq!(
            template,
            "--OPFAST:42:BEGIN:0--\nop://a/b/c\n--OPFAST:42:END:0--\n\
             --OPFAST:42:BEGIN:1--\nop://d/e/f\n--OPFAST:42:END:1--\n"
        );
    }

    #[test]
    fn parse_assigns_single_line_values_in_order() {
        let refs = ["op://a/b/c", "op://d/e/f"];
        let template = build_batch_template(&refs, 7);
        let output = simulate_inject(&template, &["first", "second"]);
        let values = parse_batch_output(&output, 2, 7).unwrap();
        assert_eq!(values, vec!["first".to_string(), "second".to_string()]);
    }

    #[test]
    fn parse_preserves_multi_line_values() {
        let refs = ["op://vault/ssh/key"];
        let template = build_batch_template(&refs, 7);
        let output = simulate_inject(&template, &["-----BEGIN KEY-----\nabc\n-----END KEY-----"]);
        let values = parse_batch_output(&output, 1, 7).unwrap();
        assert_eq!(
            values,
            vec!["-----BEGIN KEY-----\nabc\n-----END KEY-----".to_string()]
        );
    }

    #[test]
    fn parse_empty_value_yields_empty_string() {
        let refs = ["op://a/b/c"];
        let template = build_batch_template(&refs, 7);
        let output = simulate_inject(&template, &[""]);
        let values = parse_batch_output(&output, 1, 7).unwrap();
        assert_eq!(values, vec![String::new()]);
    }

    #[test]
    fn parse_regression_multiline_plus_empty_do_not_misassign() {
        // The upstream line-count bug: value "x\ny" plus value "" produced two
        // lines for two refs and mis-assigned "y" to the second reference.
        let refs = ["op://a/b/c", "op://d/e/f"];
        let template = build_batch_template(&refs, 7);
        let output = simulate_inject(&template, &["x\ny", ""]);
        let values = parse_batch_output(&output, 2, 7).unwrap();
        assert_eq!(values, vec!["x\ny".to_string(), String::new()]);
    }

    #[test]
    fn parse_fails_on_missing_end_marker() {
        let output = "--OPFAST:7:BEGIN:0--\nvalue\n";
        assert!(parse_batch_output(output, 1, 7).is_err());
    }

    #[test]
    fn parse_fails_on_section_count_mismatch() {
        let refs = ["op://a/b/c"];
        let template = build_batch_template(&refs, 7);
        let output = simulate_inject(&template, &["only"]);
        assert!(parse_batch_output(&output, 2, 7).is_err());
    }

    #[test]
    fn parse_fails_closed_when_a_value_forges_aligned_sentinels() {
        // Hostile value 0 forges an early END:0 plus a BEGIN:1 so that the
        // real markers land inside section 1 and the section count still
        // matches. Must error - never return shifted/garbage assignments.
        let refs = ["op://a/b/c", "op://d/e/f"];
        let template = build_batch_template(&refs, 7);
        let forged = "real\n--OPFAST:7:END:0--\n--OPFAST:7:BEGIN:1--\nPWNED";
        let output = simulate_inject(&template, &[forged, "actual"]);
        assert!(parse_batch_output(&output, 2, 7).is_err());
    }

    #[test]
    fn parse_fails_on_unexpected_content_outside_sections() {
        let refs = ["op://a/b/c"];
        let template = build_batch_template(&refs, 7);
        let mut output = String::from("unexpected preamble\n");
        output.push_str(&simulate_inject(&template, &["value"]));
        assert!(parse_batch_output(&output, 1, 7).is_err());
    }
}
