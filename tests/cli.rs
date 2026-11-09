//! End-to-end tests for the op-fast binary against a fake `op`
//! (`tests/fake-op.sh`). Every test gets its own temp directory for the
//! store, config, audit log, and keyring, so nothing touches the operator's
//! real cache, config, or Keychain.

// The test keyring backend only exists in debug builds; a release build
// would point these tests at the real OS keyring.
#[cfg(not(debug_assertions))]
compile_error!("integration tests need a debug build (the test keyring backend is debug-only)");

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_op-fast");
const FAKE_OP: &str = include_str!("fake-op.sh");

// Obviously fake token strings; nothing here could pass for a real credential.
const TOKEN_AGENTS: &str = "FAKE-TEST-TOKEN-agents-not-a-real-credential";
const TOKEN_CI: &str = "FAKE-TEST-TOKEN-ci-not-a-real-credential";
const TOKEN_AMBIENT: &str = "FAKE-TEST-TOKEN-ambient-not-a-real-credential";

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Env {
    dir: PathBuf,
    fake: PathBuf,
    extra: Vec<(String, String)>,
}

impl Env {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("op-fast-it-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bin")).unwrap();
        let fake = dir.join("bin").join("fake-op");
        write_exe(&fake, FAKE_OP);
        fs::write(dir.join("values"), "").unwrap();
        fs::write(dir.join("log"), "").unwrap();
        fs::write(
            dir.join("tokens"),
            format!(
                "{}\tagents\n{}\tci\n{}\tambient\n",
                TOKEN_AGENTS, TOKEN_CI, TOKEN_AMBIENT
            ),
        )
        .unwrap();
        let env = Self {
            dir,
            fake,
            extra: Vec::new(),
        };
        env.config("");
        env
    }

    fn config(&self, toml: &str) {
        fs::write(self.dir.join("config.toml"), toml).unwrap();
    }

    fn set_values(&self, pairs: &[(&str, &str)]) {
        let body: String = pairs
            .iter()
            .map(|(r, v)| format!("{}\t{}\n", r, v))
            .collect();
        fs::write(self.dir.join("values"), body).unwrap();
    }

    fn with(mut self, key: &str, value: &str) -> Self {
        self.extra.push((key.to_string(), value.to_string()));
        self
    }

    fn set(&mut self, key: &str, value: &str) {
        self.extra.retain(|(k, _)| k != key);
        self.extra.push((key.to_string(), value.to_string()));
    }

    fn unset(&mut self, key: &str) {
        self.extra.retain(|(k, _)| k != key);
    }

    /// A command with a scrubbed, test-only environment.
    fn base(&self, program: &Path) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.dir.join("home"))
            .env("OP_FAST_STORE_DIR", self.dir.join("store"))
            .env("OP_FAST_CONFIG", self.dir.join("config.toml"))
            .env("OP_FAST_TEST_KEYRING_DIR", self.dir.join("keyring"))
            .env("OP_FAST_KEYRING_SERVICE", "op-fast-integration-test")
            .env("OP_FAST_PROMPT_TIMEOUT", "2s")
            // Debug-only escape: the fake `op` is not signed by 1Password.
            .env("OP_FAST_TEST_UNSIGNED_DELEGATE", "1")
            .env("FAKE_OP_VALUES", self.dir.join("values"))
            .env("FAKE_OP_LOG", self.dir.join("log"))
            .env("FAKE_OP_TOKENS", self.dir.join("tokens"))
            .stdin(Stdio::null());
        for (k, v) in &self.extra {
            cmd.env(k, v);
        }
        cmd
    }

    fn cmd(&self) -> Command {
        let mut cmd = self.base(Path::new(BIN));
        cmd.env("OP_FAST_COMMAND", &self.fake);
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd().args(args).output().unwrap()
    }

    fn run_stdin(&self, args: &[&str], stdin: &str) -> Output {
        use std::io::Write;
        let mut child = self
            .cmd()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The binary may exit before reading stdin (e.g. a validation
        // error); a broken pipe here is not a test failure.
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        child.wait_with_output().unwrap()
    }

    /// Delegate calls recorded by the fake: (token label, args).
    fn calls(&self) -> Vec<(String, Vec<String>)> {
        fs::read_to_string(self.dir.join("log"))
            .unwrap()
            .lines()
            .map(|l| {
                let mut parts = l.split('\t').map(str::to_string);
                let label = parts.next().unwrap();
                (label, parts.collect())
            })
            .collect()
    }

    fn clear_calls(&self) {
        fs::write(self.dir.join("log"), "").unwrap();
    }

    fn audit_text(&self) -> String {
        let dir = self.dir.join("store").join("audit");
        let mut text = String::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries.flatten() {
                text.push_str(&fs::read_to_string(e.path()).unwrap());
            }
        }
        text
    }

    fn audit_events(&self) -> Vec<serde_json::Value> {
        self.audit_text()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn add_token(&self, name: &str, token: &str) {
        let out = self.run_stdin(&["sa", "add", name, "--stdin"], token);
        assert!(out.status.success(), "sa add failed: {}", stderr(&out));
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn write_exe(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn assert_ok(o: &Output) {
    assert!(
        o.status.success(),
        "exit {:?}\nstdout: {}\nstderr: {}",
        o.status.code(),
        stdout(o),
        stderr(o)
    );
}

fn args_of(call: &(String, Vec<String>)) -> Vec<&str> {
    call.1.iter().map(String::as_str).collect()
}

const APPROVAL_TIMEOUT: &str =
    "[ERROR] 2026/11/09 12:00:00 error initializing client: authorization timeout";
const NEEDS_APPROVAL_PREFIX: &str = "op-fast: needs approval:";

// ---------------------------------------------------------------- harness

#[test]
fn miss_fetches_once_then_hits_cache() {
    let env = Env::new();
    env.set_values(&[("op://Private/db/password", "fake-value-1")]);

    let first = env.run(&["read", "op://Private/db/password"]);
    assert_ok(&first);
    assert_eq!(stdout(&first), "fake-value-1\n");

    let second = env.run(&["read", "op://Private/db/password"]);
    assert_ok(&second);
    assert_eq!(stdout(&second), "fake-value-1\n");

    let calls = env.calls();
    assert_eq!(
        calls.len(),
        1,
        "second read must be a cache hit: {:?}",
        calls
    );
    assert_eq!(args_of(&calls[0]), ["read", "op://Private/db/password"]);
    assert_eq!(calls[0].0, "unset");
}

#[test]
fn test_harness_uses_isolated_keyring_backend() {
    let env = Env::new();
    let out = env.run(&["doctor", "--json"]);
    assert_ok(&out);
    let report: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(report["keyring"], "test-directory (debug build)");
    assert!(
        report["store"]["path"]
            .as_str()
            .unwrap()
            .starts_with(env.dir.to_str().unwrap())
    );
}

// ------------------------------------------------------ drop-in compatibility

#[test]
fn unmodeled_flag_on_read_passes_through_with_identical_argv() {
    let env = Env::new();
    env.set_values(&[("op://Private/db/password", "fake-value-1")]);
    let out = env.run(&["read", "--account", "x", "op://Private/db/password"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "fake-value-1\n");
    let calls = env.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        args_of(&calls[0]),
        ["read", "--account", "x", "op://Private/db/password"]
    );
    assert!(env.audit_text().contains(r#""outcome":"unmodeled-flag""#));
}

#[test]
fn unmodeled_flags_on_run_inject_and_globals_pass_through() {
    let env = Env::new();
    env.set_values(&[("op://a/b/c", "fake-value-1")]);
    for args in [
        vec!["run", "--environment", "prod", "--", "true"],
        vec!["inject", "--format", "json", "-i", "x"],
        vec!["--account", "x", "read", "op://a/b/c"],
        vec!["read", "--unknown-future-flag", "op://a/b/c"],
    ] {
        env.clear_calls();
        let out = env.run(&args);
        assert_ok(&out);
        let calls = env.calls();
        assert_eq!(calls.len(), 1, "{:?}", args);
        assert_eq!(args_of(&calls[0]), args);
    }
}

#[test]
fn our_own_flags_are_stripped_on_passthrough() {
    let env = Env::new();
    env.set_values(&[("op://a/b/c", "fake-value-1")]);
    let out = env.run(&["read", "--refresh", "--account", "x", "op://a/b/c"]);
    assert_ok(&out);
    assert_eq!(
        args_of(&env.calls()[0]),
        ["read", "--account", "x", "op://a/b/c"]
    );
}

#[test]
fn unknown_commands_pass_through() {
    let env = Env::new();
    let out = env.run(&["item", "list", "--vault", "Private"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "fake-op: item list --vault Private\n");
}

#[test]
fn delegate_exit_code_is_preserved() {
    let env = Env::new().with("FAKE_OP_EXIT", "3");
    let out = env.run(&["read", "op://Private/missing/field"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(stderr(&out).contains("isn't an item"));
}

#[test]
fn op_named_symlink_or_copy_first_on_path_resolves_the_real_op_behind_it() {
    for mode in ["symlink", "copy"] {
        let env = Env::new();
        env.set_values(&[("op://Private/db/password", "fake-value-1")]);
        let shim_dir = env.dir.join("shim");
        let real_dir = env.dir.join("real");
        fs::create_dir_all(&shim_dir).unwrap();
        fs::create_dir_all(&real_dir).unwrap();
        let shim = shim_dir.join("op");
        if mode == "symlink" {
            std::os::unix::fs::symlink(BIN, &shim).unwrap();
        } else {
            fs::copy(BIN, &shim).unwrap();
        }
        write_exe(&real_dir.join("op"), FAKE_OP);

        let path = format!(
            "{}:{}:/usr/bin:/bin",
            shim_dir.display(),
            real_dir.display()
        );
        let out = env
            .base(&shim)
            .env("PATH", path)
            .args(["read", "op://Private/db/password"])
            .output()
            .unwrap();
        assert_ok(&out);
        assert_eq!(stdout(&out), "fake-value-1\n", "{}", mode);
        assert_eq!(env.calls().len(), 1, "{}", mode);
    }
}

#[test]
fn op_command_in_config_is_used_and_env_var_wins() {
    let env = Env::new();
    env.set_values(&[("op://Private/db/password", "fake-value-1")]);
    env.config(&format!("op_command = \"{}\"\n", env.fake.display()));
    let out = env
        .base(Path::new(BIN))
        .args(["read", "op://Private/db/password"])
        .output()
        .unwrap();
    assert_ok(&out);
    assert_eq!(stdout(&out), "fake-value-1\n");

    // OP_FAST_COMMAND wins over op_command.
    env.config("op_command = \"/nonexistent/op\"\n");
    let out = env.run(&["read", "--refresh", "op://Private/db/password"]);
    assert_ok(&out);
}

#[test]
fn bypass_sends_everything_to_real_op() {
    let env = Env::new().with("OP_FAST_BYPASS", "1");
    env.set_values(&[("op://Private/db/password", "fake-value-1")]);
    for _ in 0..2 {
        let out = env.run(&["read", "op://Private/db/password"]);
        assert_ok(&out);
        assert_eq!(stdout(&out), "fake-value-1\n");
    }
    assert_eq!(env.calls().len(), 2, "bypass must never serve from cache");
    let out = env.run(&["item", "list"]);
    assert_eq!(stdout(&out), "fake-op: item list\n");
}

#[test]
fn run_still_handles_hyphenated_child_args() {
    let env = Env::new().with("SECRET", "op://Private/db/password");
    env.set_values(&[("op://Private/db/password", "fake-value-1")]);
    let out = env.run(&["run", "--no-masking", "--", "sh", "-c", "echo \"$SECRET\""]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "fake-value-1\n");
}

// ---------------------------------------------------------------- refresh

#[test]
fn refresh_bypasses_and_overwrites_the_cache() {
    let env = Env::new();
    env.set_values(&[("op://Private/db/password", "old-fake")]);
    assert_eq!(
        stdout(&env.run(&["read", "op://Private/db/password"])),
        "old-fake\n"
    );

    env.set_values(&[("op://Private/db/password", "new-fake")]);
    assert_eq!(
        stdout(&env.run(&["read", "op://Private/db/password"])),
        "old-fake\n"
    );

    let refreshed = env.run(&["read", "--refresh", "op://Private/db/password"]);
    assert_ok(&refreshed);
    assert_eq!(stdout(&refreshed), "new-fake\n");

    assert_eq!(
        stdout(&env.run(&["read", "op://Private/db/password"])),
        "new-fake\n"
    );
    assert_eq!(env.calls().len(), 2);
    assert!(env.audit_text().contains(r#""outcome":"refreshed""#));
}

#[test]
fn force_flag_prints_note_and_does_not_refresh() {
    let env = Env::new();
    env.set_values(&[("op://Private/db/password", "old-fake")]);
    env.run(&["read", "op://Private/db/password"]);
    env.set_values(&[("op://Private/db/password", "new-fake")]);

    let out = env.run(&["read", "-f", "op://Private/db/password"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "old-fake\n");
    assert_eq!(
        stderr(&out),
        "note: -f does not refresh the cache; use --refresh\n"
    );
    assert_eq!(env.calls().len(), 1);
}

#[test]
fn refresh_flag_on_run_and_inject() {
    let env = Env::new().with("SECRET", "op://Private/db/password");
    env.set_values(&[("op://Private/db/password", "old-fake")]);
    env.run(&["read", "op://Private/db/password"]);
    env.set_values(&[("op://Private/db/password", "new-fake")]);

    let out = env.run(&[
        "run",
        "--no-masking",
        "--refresh",
        "--",
        "sh",
        "-c",
        "echo \"$SECRET\"",
    ]);
    assert_eq!(stdout(&out), "new-fake\n");

    env.set_values(&[("op://Private/db/password", "newer-fake")]);
    let out = env.run_stdin(
        &["inject", "--refresh"],
        "x={{ op://Private/db/password }}\n",
    );
    assert_eq!(stdout(&out), "x=newer-fake\n");
}

#[test]
fn refresh_command_prints_counts_not_values() {
    let env = Env::new();
    env.set_values(&[("op://Private/a/f", "old-a"), ("op://Private/b/f", "old-b")]);
    env.run(&["read", "op://Private/a/f"]);
    env.run(&["read", "op://Private/b/f"]);
    env.set_values(&[("op://Private/a/f", "new-a"), ("op://Private/b/f", "new-b")]);

    let out = env.run(&["refresh", "op://Private/a/f"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "refreshed: 1, failed: 0, skipped: 0\n");
    assert_eq!(stdout(&env.run(&["read", "op://Private/a/f"])), "new-a\n");
    assert_eq!(stdout(&env.run(&["read", "op://Private/b/f"])), "old-b\n");

    let out = env.run(&["refresh", "--all"]);
    assert_ok(&out);
    assert!(!stdout(&out).contains("new-"));
    assert_eq!(stdout(&env.run(&["read", "op://Private/b/f"])), "new-b\n");
}

// --------------------------------------------- deadlines, exit 75, stale

fn expired_env() -> Env {
    let env = Env::new();
    env.config("default_ttl = \"1s\"\n");
    env.set_values(&[("op://Private/db/password", "cached-fake")]);
    assert_ok(&env.run(&["read", "op://Private/db/password"]));
    std::thread::sleep(Duration::from_millis(2100));
    env
}

#[test]
fn sleeping_delegate_is_killed_at_the_deadline_and_exits_75() {
    let env = Env::new()
        .with("FAKE_OP_SLEEP", "30")
        .with("OP_FAST_PROMPT_TIMEOUT", "1s");
    let start = Instant::now();
    let out = env.run(&["read", "op://Private/db/password"]);
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(8), "took {:?}", elapsed);
    assert_eq!(out.status.code(), Some(75));
    let err = stderr(&out);
    assert_eq!(err.lines().count(), 1, "stderr: {}", err);
    assert!(err.starts_with(NEEDS_APPROVAL_PREFIX), "stderr: {}", err);
    assert!(err.contains("op://Private/db/password"));
    assert!(err.contains("op-fast warm"));
}

#[test]
fn approval_failure_serves_expired_entry_in_grace_with_warning() {
    let mut env = expired_env();
    env.set("FAKE_OP_STDERR", APPROVAL_TIMEOUT);
    let out = env.run(&["read", "op://Private/db/password"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "cached-fake\n");
    let err = stderr(&out);
    assert!(
        err.starts_with("warning: served expired cache for op://Private/db/password (expired "),
        "{}",
        err
    );
    assert!(
        err.trim_end()
            .ends_with("ago); 1Password approval unavailable"),
        "{}",
        err
    );
    assert!(env.audit_text().contains(r#""outcome":"stale-served""#));

    // A deadline kill counts as approval-unavailable too.
    env.unset("FAKE_OP_STDERR");
    env.set("FAKE_OP_SLEEP", "30");
    env.set("OP_FAST_PROMPT_TIMEOUT", "1s");
    let out = env.run(&["read", "op://Private/db/password"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "cached-fake\n");
}

#[test]
fn approval_failure_without_cache_exits_75_with_one_line() {
    let env = Env::new().with("FAKE_OP_STDERR", APPROVAL_TIMEOUT);
    let out = env.run(&["read", "op://Private/db/password"]);
    assert_eq!(out.status.code(), Some(75));
    let err = stderr(&out);
    assert_eq!(err.lines().count(), 1);
    assert!(err.starts_with(NEEDS_APPROVAL_PREFIX));
}

#[test]
fn not_found_never_serves_stale() {
    let mut env = expired_env();
    env.set_values(&[]);
    env.set("FAKE_OP_EXIT", "4");
    let out = env.run(&["read", "op://Private/db/password"]);
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(stdout(&out), "");
    assert!(stderr(&out).contains("isn't an item"));
    assert!(!env.audit_text().contains("stale-served"));
    assert!(env.audit_text().contains(r#""error_class":"not-found""#));
}

#[test]
fn no_stale_env_disables_fallback() {
    let env = expired_env()
        .with("FAKE_OP_STDERR", APPROVAL_TIMEOUT)
        .with("OP_FAST_NO_STALE", "1");
    let out = env.run(&["read", "op://Private/db/password"]);
    assert_eq!(out.status.code(), Some(75));
    assert_eq!(stdout(&out), "");
}

#[test]
fn refresh_never_serves_stale() {
    let env = expired_env().with("FAKE_OP_STDERR", APPROVAL_TIMEOUT);
    let out = env.run(&["read", "--refresh", "op://Private/db/password"]);
    assert_eq!(out.status.code(), Some(75));
}

#[test]
fn stale_grace_window_is_respected() {
    let env = Env::new();
    env.config("default_ttl = \"1s\"\nstale_grace = \"1s\"\n");
    env.set_values(&[("op://Private/db/password", "cached-fake")]);
    assert_ok(&env.run(&["read", "op://Private/db/password"]));
    std::thread::sleep(Duration::from_millis(3200));
    let env = env.with("FAKE_OP_STDERR", APPROVAL_TIMEOUT);
    let out = env.run(&["read", "op://Private/db/password"]);
    assert_eq!(out.status.code(), Some(75));
}

#[test]
fn batch_approval_failure_lists_unservable_references() {
    let env = Env::new()
        .with("FAKE_OP_STDERR", APPROVAL_TIMEOUT)
        .with("A", "op://Private/a/f")
        .with("B", "op://Private/b/f");
    let out = env.run(&["run", "--", "true"]);
    assert_eq!(out.status.code(), Some(75));
    let err = stderr(&out);
    assert_eq!(err.lines().count(), 1);
    assert!(err.contains("op://Private/a/f") && err.contains("op://Private/b/f"));
}

// ------------------------------------------------------- service accounts

const TWO_ACCOUNTS: &str = r#"
[[service_account]]
name = "agents"
vaults = ["Agents", "Shared"]
ttl = "15m"

[[service_account]]
name = "ci"
vaults = ["CI"]
"#;

fn sa_env() -> Env {
    let env = Env::new()
        .with("A", "op://Agents/a/f")
        .with("S", "op://Shared/s/f")
        .with("C", "op://CI/c/f")
        .with("P", "op://Private/p/f");
    env.config(TWO_ACCOUNTS);
    env.add_token("agents", TOKEN_AGENTS);
    env.add_token("ci", TOKEN_CI);
    env.set_values(&[
        ("op://Agents/a/f", "va"),
        ("op://Shared/s/f", "vs"),
        ("op://CI/c/f", "vc"),
        ("op://Private/p/f", "vp"),
    ]);
    env.clear_calls();
    env
}

/// (token label, references) per inject call.
fn inject_groups(env: &Env) -> Vec<(String, Vec<String>)> {
    let mut groups: Vec<(String, Vec<String>)> = env
        .calls()
        .into_iter()
        .filter(|(_, a)| a.first().map(String::as_str) == Some("inject"))
        .map(|(label, args)| {
            let mut refs: Vec<String> = args
                .iter()
                .filter_map(|a| a.strip_prefix("stdin:").map(str::to_string))
                .collect();
            refs.sort();
            (label, refs)
        })
        .collect();
    groups.sort();
    groups
}

fn assert_no_token_leak(env: &Env, outputs: &[&Output]) {
    let mut haystacks = vec![
        env.audit_text(),
        fs::read_to_string(env.dir.join("log")).unwrap(),
    ];
    for o in outputs {
        haystacks.push(stdout(o));
        haystacks.push(stderr(o));
    }
    for h in haystacks {
        for t in [TOKEN_AGENTS, TOKEN_CI, TOKEN_AMBIENT, "FAKE-TEST-TOKEN"] {
            assert!(!h.contains(t), "token text leaked: {}", h);
        }
    }
}

#[test]
fn mixed_vault_batch_makes_one_call_per_account_with_scoped_tokens() {
    let env = sa_env();
    let out = env.run(&[
        "run",
        "--no-masking",
        "--",
        "sh",
        "-c",
        "env | grep -E '^(A|S|C|P)=' | sort",
    ]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "A=va\nC=vc\nP=vp\nS=vs\n");
    assert_eq!(
        inject_groups(&env),
        vec![
            (
                "agents".to_string(),
                vec!["op://Agents/a/f".to_string(), "op://Shared/s/f".to_string()]
            ),
            ("ci".to_string(), vec!["op://CI/c/f".to_string()]),
            ("unset".to_string(), vec!["op://Private/p/f".to_string()]),
        ]
    );
    assert_no_token_leak(&env, &[&out]);

    let events = env.audit_events();
    let account_of = |r: &str| {
        events
            .iter()
            .find(|e| e["reference"] == r && e["outcome"] == "fetched")
            .map(|e| e["account"].as_str().unwrap().to_string())
    };
    assert_eq!(account_of("op://Agents/a/f").as_deref(), Some("agents"));
    assert_eq!(account_of("op://CI/c/f").as_deref(), Some("ci"));
    assert_eq!(account_of("op://Private/p/f").as_deref(), Some("desktop"));
}

#[test]
fn token_does_not_reach_the_child_process_of_run() {
    let env = sa_env();
    let out = env.run(&[
        "run",
        "--no-masking",
        "--",
        "sh",
        "-c",
        "printenv OP_SERVICE_ACCOUNT_TOKEN || echo none",
    ]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "none\n");
}

#[test]
fn forced_none_and_ambient_token_suppress_selection() {
    let env = sa_env();
    let out = env.run(&["--sa", "none", "run", "--", "true"]);
    assert_ok(&out);
    let groups = inject_groups(&env);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].0, "unset");
    assert_eq!(groups[0].1.len(), 4);
    assert_no_token_leak(&env, &[&out]);

    let env = sa_env().with("OP_SERVICE_ACCOUNT_TOKEN", TOKEN_AMBIENT);
    let out = env.run(&["run", "--", "true"]);
    assert_ok(&out);
    let groups = inject_groups(&env);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].0, "ambient");
    assert_no_token_leak(&env, &[&out]);
}

#[test]
fn forced_account_by_env_and_flag() {
    let env = sa_env().with("OP_FAST_ACCOUNT", "ci");
    assert_ok(&env.run(&["run", "--", "true"]));
    let groups = inject_groups(&env);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].0, "ci");

    let env = sa_env();
    let out = env.run(&["read", "--sa", "agents", "op://Private/p/f"]);
    assert_ok(&out);
    assert_eq!(env.calls()[0].0, "agents");

    let out = env.run(&["read", "--sa", "nobody", "op://Private/p/f"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("unknown service account"));
}

#[test]
fn single_reads_select_by_vault() {
    let env = sa_env();
    for (r, label) in [
        ("op://Agents/a/f", "agents"),
        ("op://CI/c/f", "ci"),
        ("op://Private/p/f", "unset"),
    ] {
        env.clear_calls();
        let out = env.run(&["read", r]);
        assert_ok(&out);
        let calls = env.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, label, "{}", r);
        assert_no_token_leak(&env, &[&out]);
    }
}

#[test]
fn passthrough_selects_by_vault_flag() {
    let env = sa_env();
    assert_ok(&env.run(&["item", "list", "--vault", "Agents"]));
    assert_ok(&env.run(&["item", "list"]));
    assert_ok(&env.run(&["read", "--account", "x", "--vault", "CI", "op://CI/c/f"]));
    assert_ok(&env.run(&["--sa", "none", "item", "list", "--vault", "Agents"]));
    assert_ok(&env.run(&["--sa", "ci", "item", "list"]));
    let labels: Vec<String> = env.calls().into_iter().map(|c| c.0).collect();
    // `--sa none` always forces desktop auth, even with --vault (S6).
    assert_eq!(labels, ["agents", "unset", "ci", "unset", "ci"]);
}

#[test]
fn missing_token_is_an_error_not_a_desktop_fallback() {
    let env = Env::new();
    env.config(TWO_ACCOUNTS);
    let out = env.run(&["read", "op://Agents/a/f"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("op-fast sa add agents"));
    assert!(env.calls().is_empty());
}

#[test]
fn service_account_ttl_applies_and_desktop_ttl_is_unchanged() {
    let env = sa_env();
    env.config(&format!("default_ttl = \"14days\"\n{}", TWO_ACCOUNTS));
    assert_ok(&env.run(&["read", "op://Agents/a/f"]));
    assert_ok(&env.run(&["read", "op://Private/p/f"]));
    let out = env.run(&["status", "--json", "op://Agents/a/f", "op://Private/p/f"]);
    let rows: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let ttl =
        |i: usize| rows[i]["expires_at"].as_u64().unwrap() - rows[i]["stored_at"].as_u64().unwrap();
    assert_eq!(ttl(0), 15 * 60);
    assert_eq!(ttl(1), 14 * 86400);
}

#[test]
fn sa_list_and_remove() {
    let env = sa_env();
    let out = env.run(&["sa", "list", "--json"]);
    assert_ok(&out);
    let rows: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(rows[0]["name"], "agents");
    assert_eq!(rows[0]["token"], true);
    assert_no_token_leak(&env, &[&out]);

    assert_ok(&env.run(&["sa", "remove", "agents"]));
    let rows: serde_json::Value =
        serde_json::from_str(&stdout(&env.run(&["sa", "list", "--json"]))).unwrap();
    assert_eq!(rows[0]["token"], false);
    assert_eq!(rows[1]["token"], true);
}

#[test]
fn sa_add_without_tty_or_stdin_flag_refuses() {
    let env = Env::new();
    env.config(TWO_ACCOUNTS);
    let out = env.run(&["sa", "add", "agents"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--stdin"));
}

#[test]
fn approval_failure_on_desktop_does_not_block_service_account_group() {
    let env = sa_env()
        .with("FAKE_OP_STDERR", APPROVAL_TIMEOUT)
        .with("FAKE_OP_FAIL_DESKTOP_ONLY", "1");
    let out = env.run(&["read", "op://Agents/a/f"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "va\n");
    let out = env.run(&["read", "op://Private/p/f"]);
    assert_eq!(out.status.code(), Some(75));
}

// ---------------------------------------------------------------- warm

#[test]
fn warm_refreshes_everything_in_one_call_per_group_and_prints_counts() {
    let env = Env::new();
    env.set_values(&[
        ("op://Private/a/f", "old-a"),
        ("op://Private/b/f", "old-b"),
        ("op://Private/c/f", "old-c"),
    ]);
    for r in ["op://Private/a/f", "op://Private/b/f", "op://Private/c/f"] {
        env.run(&["read", r]);
    }
    env.set_values(&[
        ("op://Private/a/f", "new-a"),
        ("op://Private/b/f", "new-b"),
        ("op://Private/c/f", "new-c"),
    ]);
    env.clear_calls();

    let out = env.run(&["warm"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "refreshed: 3, failed: 0, skipped: 0\n");
    assert_eq!(env.calls().len(), 1, "one approval for the desktop group");
    assert!(!stdout(&out).contains("new-") && !stderr(&out).contains("new-"));
    assert_eq!(stdout(&env.run(&["read", "op://Private/b/f"])), "new-b\n");
}

#[test]
fn warm_includes_expired_in_grace_entries() {
    let env = expired_env();
    env.set_values(&[("op://Private/db/password", "fresh-fake")]);
    let out = env.run(&["warm"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "refreshed: 1, failed: 0, skipped: 0\n");
}

#[test]
fn warm_isolates_a_bad_reference() {
    let env = Env::new();
    let manifest = env.dir.join("refs");
    fs::write(
        &manifest,
        "# test\nop://Private/a/f\nop://Private/gone/f  # deleted\n\nop://Private/b/f\nnot-a-ref\n",
    )
    .unwrap();
    env.set_values(&[("op://Private/a/f", "va"), ("op://Private/b/f", "vb")]);
    let out = env.run(&["warm", "--manifest", manifest.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), "refreshed: 2, failed: 1, skipped: 1\n");
    assert!(stderr(&out).contains("failed: op://Private/gone/f (not-found)"));
}

#[test]
fn warm_dry_run_makes_no_delegate_calls() {
    let env = Env::new();
    env.config(TWO_ACCOUNTS);
    let manifest = env.dir.join("refs");
    fs::write(&manifest, "op://Agents/a/f\nop://Private/p/f\n").unwrap();
    let out = env.run(&[
        "warm",
        "--dry-run",
        "--manifest",
        manifest.to_str().unwrap(),
    ]);
    assert_ok(&out);
    assert_eq!(
        stdout(&out),
        "agents\top://Agents/a/f\ndesktop\top://Private/p/f\nwould refresh: 2, skipped: 0\n"
    );
    assert!(env.calls().is_empty());
}

#[test]
fn warm_under_approval_failure_exits_75() {
    let env = Env::new().with("FAKE_OP_STDERR", APPROVAL_TIMEOUT);
    let manifest = env.dir.join("refs");
    fs::write(&manifest, "op://Private/a/f\n").unwrap();
    let out = env.run(&["warm", "--manifest", manifest.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(75));
    assert_eq!(stderr(&out).lines().count(), 1);
    assert!(stderr(&out).starts_with(NEEDS_APPROVAL_PREFIX));
}

// ------------------------------------------- doctor, status, ref, help, audit

#[test]
fn doctor_makes_no_delegate_call_that_could_prompt() {
    let env = sa_env();
    env.set_values(&[("op://Private/p/f", "vp")]);
    env.run(&["read", "op://Private/p/f"]);
    env.clear_calls();

    let out = env.run(&["doctor"]);
    assert_ok(&out);
    let json = env.run(&["doctor", "--json"]);
    assert_ok(&json);
    let report: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();

    for (_, args) in env.calls() {
        assert_eq!(args, ["--version"], "doctor may only call `op --version`");
    }
    assert_eq!(report["delegate"]["version"], "2.99.0-fake");
    assert_eq!(report["store"]["valid"], 1);
    assert_eq!(report["service_accounts"][0]["token_present"], true);
    assert_eq!(report["prompt_timeout"], "2s");
    assert_eq!(report["effective_desktop_deadline"], "2s");
    assert_eq!(report["stderr_is_tty"], false);
    assert_no_token_leak(&env, &[&out, &json]);
}

#[test]
fn status_reports_metadata_only() {
    let env = Env::new();
    env.set_values(&[("op://Private/a/f", "SECRET-FAKE-VALUE")]);
    env.run(&["read", "op://Private/a/f"]);
    env.clear_calls();
    let out = env.run(&[
        "status",
        "--json",
        "op://Private/a/f",
        "op://Private/none/f",
    ]);
    assert_ok(&out);
    let rows: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(rows[0]["state"], "valid");
    assert_eq!(rows[0]["account"], "desktop");
    assert_eq!(rows[1]["state"], "absent");
    assert!(!stdout(&out).contains("SECRET-FAKE-VALUE"));
    let text = env.run(&["status", "op://Private/a/f"]);
    assert!(stdout(&text).contains("state: valid"));
    assert!(env.calls().is_empty());
}

#[test]
fn store_list_json() {
    let env = Env::new();
    env.set_values(&[("op://Private/a/f", "SECRET-FAKE-VALUE")]);
    env.run(&["read", "op://Private/a/f"]);
    let out = env.run(&["store", "list", "--json"]);
    assert_ok(&out);
    let rows: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(rows[0]["reference"], "op://Private/a/f");
    assert_eq!(rows[0]["state"], "valid");
    assert!(!stdout(&out).contains("SECRET-FAKE-VALUE"));
}

const ITEM_JSON: &str = r#"{
  "id": "itmfake123",
  "title": "Stripe (live)",
  "vault": {"id": "vltfake456", "name": "Agents"},
  "fields": [
    {"id": "username", "label": "username", "value": "SECRET-FAKE-USER"},
    {"id": "fldfake789", "label": "secret key", "value": "SECRET-FAKE-KEY"}
  ]
}"#;

#[test]
fn ref_prints_id_based_reference_and_no_values() {
    let env = sa_env();
    fs::write(env.dir.join("item.json"), ITEM_JSON).unwrap();
    let item_path = env.dir.join("item.json").to_str().unwrap().to_string();
    let env = env.with("FAKE_OP_ITEM_JSON", &item_path);

    let out = env.run(&["ref", "Stripe (live)", "secret key", "--vault", "Agents"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "op://Agents/itmfake123/fldfake789\n");
    let calls = env.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "agents");
    assert_eq!(
        args_of(&calls[0]),
        [
            "item",
            "get",
            "Stripe (live)",
            "--vault",
            "Agents",
            "--format",
            "json"
        ]
    );

    let all = env.run(&["ref", "Stripe (live)", "--vault", "Agents"]);
    assert_ok(&all);
    assert!(stdout(&all).contains("op://Agents/itmfake123/username\tusername"));
    for o in [&out, &all] {
        assert!(!stdout(o).contains("SECRET-FAKE"));
        assert!(!stderr(o).contains("SECRET-FAKE"));
    }
    assert_no_token_leak(&env, &[&out, &all]);
}

#[test]
fn ref_under_approval_failure_exits_75() {
    let env = Env::new().with("FAKE_OP_STDERR", APPROVAL_TIMEOUT);
    let out = env.run(&["ref", "Stripe (live)"]);
    assert_eq!(out.status.code(), Some(75));
    assert_eq!(stderr(&out).lines().count(), 1);
    assert!(stderr(&out).starts_with(NEEDS_APPROVAL_PREFIX));
}

#[test]
fn help_lists_every_command_and_agent_help_fits_one_screen() {
    let env = Env::new();
    let help = stdout(&env.run(&["--help"]));
    for cmd in [
        "read",
        "run",
        "inject",
        "refresh",
        "warm",
        "status",
        "ref",
        "doctor",
        "agent-help",
        "sa",
        "store",
        "audit",
    ] {
        assert!(
            help.lines()
                .any(|l| l.trim_start().starts_with(&format!("{} ", cmd))),
            "--help is missing {}: {}",
            cmd,
            help
        );
    }
    let out = env.run(&["agent-help"]);
    assert_ok(&out);
    let text = stdout(&out);
    assert!(text.lines().count() < 60);
    for needle in [
        "--refresh",
        "75",
        "op-fast ref",
        "whoami",
        "doctor",
        "--reveal",
        "run",
    ] {
        assert!(text.contains(needle), "agent-help missing {}", needle);
    }
    assert!(env.calls().is_empty());
}

#[test]
fn audit_records_error_class_account_session_and_summary_json() {
    let env = Env::new()
        .with("FAKE_OP_STDERR", APPROVAL_TIMEOUT)
        .with("CODEX_SESSION_ID", "fake-session-1");
    env.run(&["read", "op://Private/a/f"]);
    let events = env.audit_events();
    let e = events.iter().find(|e| e["outcome"] == "error").unwrap();
    assert_eq!(e["error_class"], "approval-unavailable");
    assert_eq!(e["account"], "desktop");
    assert_eq!(e["session"], "fake-session-1");
    if cfg!(target_os = "macos") {
        assert!(e["chain"].as_array().is_some_and(|c| !c.is_empty()));
    }

    let out = env.run(&["audit", "summary", "--json"]);
    assert_ok(&out);
    let summary: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(summary["by_error_class"]["approval-unavailable"], 1);
}

// ------------------------------------------------------ review round 1

fn without_signature_escape(env: &Env) -> Command {
    let mut cmd = env.cmd();
    cmd.env_remove("OP_FAST_TEST_UNSIGNED_DELEGATE");
    cmd
}

#[test]
fn b1_signature_check_is_active_by_default_in_debug_builds() {
    let env = sa_env();
    let out = without_signature_escape(&env)
        .args(["read", "op://Agents/a/f"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = stderr(&out);
    let expected = if cfg!(target_os = "macos") {
        "not signed by 1Password"
    } else {
        "only supported on macOS"
    };
    assert!(err.contains(expected), "{}", err);
    assert!(err.contains(env.fake.to_str().unwrap()), "{}", err);
    assert!(env.calls().is_empty(), "no delegate call may carry a token");

    // Passthrough refuses too.
    let out = without_signature_escape(&env)
        .args(["item", "list", "--vault", "Agents"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(env.calls().is_empty());

    // Desktop references are unaffected.
    let out = without_signature_escape(&env)
        .args(["read", "op://Private/p/f"])
        .output()
        .unwrap();
    assert_ok(&out);
    assert_no_token_leak(&env, &[&out]);
}

#[test]
fn b1_printenv_as_delegate_never_receives_the_token() {
    let env = sa_env();
    let out = without_signature_escape(&env)
        .env("OP_FAST_COMMAND", "/usr/bin/printenv")
        .args(["--sa", "agents", "OP_SERVICE_ACCOUNT_TOKEN"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_no_token_leak(&env, &[&out]);

    // Token-eligible paths refuse the unsigned delegate by name.
    for args in [
        vec!["--sa", "agents", "read", "op://Private/p/f"],
        vec![
            "--sa",
            "agents",
            "read",
            "--account",
            "x",
            "op://Private/p/f",
        ],
        vec!["--sa", "agents", "whoami"],
    ] {
        let out = without_signature_escape(&env)
            .env("OP_FAST_COMMAND", "/usr/bin/printenv")
            .args(&args)
            .output()
            .unwrap();
        assert!(!out.status.success(), "{:?}", args);
        assert!(
            stderr(&out).contains("/usr/bin/printenv"),
            "{}",
            stderr(&out)
        );
        assert_no_token_leak(&env, &[&out]);
    }
}

#[test]
fn b2_passthrough_run_under_an_account_is_refused() {
    let env = sa_env();
    for args in [
        vec![
            "--sa",
            "agents",
            "run",
            "--environment",
            "x",
            "--",
            "printenv",
            "OP_SERVICE_ACCOUNT_TOKEN",
        ],
        vec![
            "run",
            "--environment",
            "x",
            "--vault",
            "Agents",
            "--",
            "printenv",
            "OP_SERVICE_ACCOUNT_TOKEN",
        ],
    ] {
        let out = env.run(&args);
        assert!(!out.status.success(), "{:?}", args);
        assert!(
            stderr(&out).contains("refusing to pass service account"),
            "{}",
            stderr(&out)
        );
        assert_no_token_leak(&env, &[&out]);
    }
    assert!(env.calls().is_empty());

    // Without an account the fake execs the child normally.
    let out = env.run(&["run", "--environment", "x", "--", "echo", "child-ran"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "child-ran\n");
}

#[test]
fn b2_non_allowlisted_passthrough_gets_desktop_auth() {
    let env = sa_env();
    let out = env.run(&["plugin", "list", "--vault", "Agents"]);
    assert_ok(&out);
    assert!(stderr(&out).contains("is not used for `op plugin`"));
    assert_eq!(env.calls()[0].0, "unset");
    let out = env.run(&["item", "get", "x", "--vault", "Agents"]);
    assert_ok(&out);
    assert_eq!(env.calls()[1].0, "agents");
}

fn path_env() -> (Env, PathBuf) {
    let env = Env::new();
    env.set_values(&[("op://Private/db/password", "real-fake-value")]);
    let shim_dir = env.dir.join("shim");
    let real_dir = env.dir.join("real");
    let cwd = env.dir.join("repo");
    for d in [&shim_dir, &real_dir, &cwd] {
        fs::create_dir_all(d).unwrap();
    }
    std::os::unix::fs::symlink(BIN, shim_dir.join("op")).unwrap();
    write_exe(&real_dir.join("op"), FAKE_OP);
    let marker = env.dir.join("evil-ran");
    write_exe(
        &cwd.join("op"),
        &format!("#!/bin/sh\necho evil-value\ntouch {}\n", marker.display()),
    );
    (env, cwd)
}

#[test]
fn b3_repo_local_op_is_never_the_delegate() {
    for middle in [":.:", "::", ":"] {
        let (env, cwd) = path_env();
        let path = format!(
            "{}{}{}:/usr/bin:/bin",
            env.dir.join("shim").display(),
            middle,
            env.dir.join("real").display()
        );
        let out = env
            .base(&env.dir.join("shim").join("op"))
            .current_dir(&cwd)
            .env("PATH", path)
            .args(["read", "op://Private/db/password"])
            .output()
            .unwrap();
        assert_ok(&out);
        assert_eq!(
            stdout(&out),
            "real-fake-value\n",
            "PATH middle {:?}",
            middle
        );
        assert!(
            !env.dir.join("evil-ran").exists(),
            "PATH middle {:?}",
            middle
        );
    }

    // Only relative entries: no delegate at all.
    let (env, cwd) = path_env();
    let out = env
        .base(Path::new(BIN))
        .current_dir(&cwd)
        .env("PATH", ".:")
        .args(["read", "op://Private/db/password"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!env.dir.join("evil-ran").exists());
}

#[test]
fn b3_relative_op_fast_command_and_op_command_are_rejected() {
    let (env, cwd) = path_env();
    let out = env
        .base(Path::new(BIN))
        .current_dir(&cwd)
        .env("OP_FAST_COMMAND", "op")
        .args(["read", "op://Private/db/password"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("absolute path"), "{}", stderr(&out));

    env.config("op_command = \"./op\"\n");
    let out = env
        .base(Path::new(BIN))
        .current_dir(&cwd)
        .args(["read", "op://Private/db/password"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("absolute path"), "{}", stderr(&out));
    assert!(!env.dir.join("evil-ran").exists());
}

#[test]
fn b4_deleted_item_named_like_an_approval_error_never_serves_stale() {
    let reference = "op://Private/authorization timeout/password";
    let env = Env::new();
    env.config("default_ttl = \"1s\"\n");
    env.set_values(&[(reference, "cached-fake")]);
    assert_ok(&env.run(&["read", reference]));
    std::thread::sleep(Duration::from_millis(2100));
    let msg = format!(
        "[ERROR] 2026/11/09 12:00:00 could not read secret '{}': \"authorization timeout\" isn't an item in the \"Private\" vault",
        reference
    );
    let env = env.with("FAKE_OP_STDERR", &msg);
    let out = env.run(&["read", reference]);
    assert!(!out.status.success());
    assert_eq!(stdout(&out), "");
    assert!(!env.audit_text().contains("stale-served"));
}

#[test]
fn b4_service_account_failure_never_serves_stale() {
    let env = sa_env();
    env.config(
        "default_ttl = \"1s\"\n[[service_account]]\nname = \"agents\"\nvaults = [\"Agents\"]\n",
    );
    assert_ok(&env.run(&["read", "op://Agents/a/f"]));
    std::thread::sleep(Duration::from_millis(2100));
    for msg in [
        "[ERROR] 2026/11/09 12:00:00 (401) Unauthorized: error initializing client: authorization timeout",
        APPROVAL_TIMEOUT,
    ] {
        let out = env
            .cmd()
            .env("FAKE_OP_STDERR", msg)
            .args(["read", "op://Agents/a/f"])
            .output()
            .unwrap();
        assert!(!out.status.success(), "{}", msg);
        assert_ne!(out.status.code(), Some(75));
        assert_eq!(stdout(&out), "");
    }
    assert!(!env.audit_text().contains("stale-served"));
}

#[test]
fn b5_invoked_as_op_meta_flags_go_to_real_op() {
    let env = Env::new();
    let shim_dir = env.dir.join("shim");
    fs::create_dir_all(&shim_dir).unwrap();
    let shim = shim_dir.join("op");
    std::os::unix::fs::symlink(BIN, &shim).unwrap();
    let run_as = |prog: &Path, args: &[&str]| {
        env.base(prog)
            .env("OP_FAST_COMMAND", &env.fake)
            .args(args)
            .output()
            .unwrap()
    };

    assert_eq!(stdout(&run_as(&shim, &["--version"])), "2.99.0-fake\n");
    assert_eq!(stdout(&run_as(&shim, &["-v"])), "fake-op: -v\n");
    assert_eq!(stdout(&run_as(&shim, &["--help"])), "fake-op: --help\n");
    assert_eq!(stdout(&run_as(&shim, &["help"])), "fake-op: help\n");
    assert_eq!(stdout(&run_as(&shim, &[])), "fake-op: \n");

    let own = run_as(Path::new(BIN), &["--version"]);
    assert!(stdout(&own).starts_with("op-fast "), "{}", stdout(&own));
    let help = run_as(Path::new(BIN), &["--help"]);
    assert!(stdout(&help).contains("agent-help"));
}

#[test]
fn n1_passthrough_survives_a_broken_config() {
    let env = Env::new();
    env.config("this is = = not toml");
    let out = env.run(&["item", "list"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "fake-op: item list\n");
    assert_eq!(
        stderr(&out).matches("warning").count(),
        1,
        "{}",
        stderr(&out)
    );

    let out = env.run(&["--sa", "nobody", "item", "list"]);
    assert!(!out.status.success(), "unknown --sa stays a hard error");
    let env = env.with("OP_FAST_ACCOUNT", "nobody");
    assert!(!env.run(&["item", "list"]).status.success());
}

#[test]
fn n2_deadline_kills_the_whole_process_group() {
    let pidfile = std::env::temp_dir().join(format!("op-fast-gc-pid-{}", std::process::id()));
    let env = Env::new()
        .with("FAKE_OP_GRANDCHILD", pidfile.to_str().unwrap())
        .with("OP_FAST_PROMPT_TIMEOUT", "1s");
    let start = Instant::now();
    let out = env.run(&["read", "op://Private/db/password"]);
    let elapsed = start.elapsed();
    assert_eq!(out.status.code(), Some(75));
    assert!(elapsed < Duration::from_millis(2500), "took {:?}", elapsed);
    let pid = fs::read_to_string(&pidfile).unwrap().trim().to_string();
    let _ = fs::remove_file(&pidfile);
    let mut alive = true;
    for _ in 0..20 {
        alive = Command::new("/bin/kill")
            .args(["-0", &pid])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success();
        if !alive {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!alive, "grandchild {} survived the deadline kill", pid);
}

#[test]
fn n4_doctor_checks_token_presence_without_reading_it() {
    let env = sa_env();
    // Make every stored token unreadable: a value read would fail.
    for dir in fs::read_dir(env.dir.join("keyring")).unwrap().flatten() {
        for f in fs::read_dir(dir.path()).unwrap().flatten() {
            fs::set_permissions(f.path(), fs::Permissions::from_mode(0o000)).unwrap();
        }
    }
    let out = env.run(&["doctor", "--json"]);
    assert_ok(&out);
    let report: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(report["service_accounts"][0]["token_present"], true);
    let out = env.run(&["sa", "list", "--json"]);
    assert_ok(&out);
    let rows: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(rows[0]["token"], true);
}

#[test]
fn n5_no_stale_uses_the_shared_truthiness_rules() {
    let env = expired_env()
        .with("FAKE_OP_STDERR", APPROVAL_TIMEOUT)
        .with("OP_FAST_NO_STALE", "false");
    let out = env.run(&["read", "op://Private/db/password"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "cached-fake\n");
}

#[test]
fn n6_sa_is_stripped_anywhere_and_bypass_keeps_local_commands() {
    let env = sa_env();
    assert_ok(&env.run(&["item", "list", "--sa", "ci", "--refresh"]));
    let calls = env.calls();
    // Only `--sa` is ours on external subcommands; `--refresh` goes to op.
    assert_eq!(args_of(&calls[0]), ["item", "list", "--refresh"]);
    assert_eq!(calls[0].0, "ci");

    let env = env.with("OP_FAST_BYPASS", "1");
    env.clear_calls();
    let out = env.run(&["doctor", "--json"]);
    assert_ok(&out);
    assert!(stdout(&out).contains("\"op_fast_version\""));
    assert!(env.run(&["agent-help"]).status.success());
    assert_ok(&env.run(&["--sa", "agents", "item", "list"]));
    let calls = env.calls();
    let last = calls.last().unwrap();
    assert_eq!(args_of(last), ["item", "list"]);
    assert_eq!(last.0, "unset", "bypass never injects a token");
}

#[test]
fn n7_token_key_and_invalid_names_are_never_echoed() {
    let env = Env::new();
    env.config("[[service_account]]\nname = \"a\"\ntoken = \"FAKE-CONFIG-SECRET-VALUE\"\n");
    let out = env.run(&["read", "op://Private/x/y"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("token"));
    assert!(
        !stderr(&out).contains("FAKE-CONFIG-SECRET-VALUE"),
        "{}",
        stderr(&out)
    );

    let env = Env::new();
    let long = "y".repeat(70);
    for name in ["ops_FAKEFAKEFAKE", long.as_str()] {
        let out = env.run_stdin(&["sa", "add", name, "--stdin"], "x");
        assert!(!out.status.success());
        assert!(!stderr(&out).contains(name), "{}", stderr(&out));
        let out = env.run(&["--sa", name, "read", "op://Private/x/y"]);
        assert!(!stderr(&out).contains(name), "{}", stderr(&out));
    }
}

#[test]
fn n8_prompt_timeout_is_floored_at_one_second() {
    let env = Env::new()
        .with("FAKE_OP_SLEEP", "30")
        .with("OP_FAST_PROMPT_TIMEOUT", "0s");
    let start = Instant::now();
    let out = env.run(&["read", "op://Private/db/password"]);
    assert_eq!(out.status.code(), Some(75));
    assert!(
        start.elapsed() >= Duration::from_millis(950),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn n9_exit_75_with_force_flag_prints_one_line() {
    let env = Env::new().with("FAKE_OP_STDERR", APPROVAL_TIMEOUT);
    let out = env.run(&["read", "-f", "op://Private/db/password"]);
    assert_eq!(out.status.code(), Some(75));
    assert_eq!(stderr(&out).lines().count(), 1, "{}", stderr(&out));
}

#[test]
fn n11_sigint_during_hidden_prompt_restores_echo() {
    if !Path::new("/usr/bin/expect").exists() {
        eprintln!("skipping: /usr/bin/expect not available");
        return;
    }
    let env = Env::new();
    env.config(TWO_ACCOUNTS);
    let script = env.dir.join("sigint.exp");
    let mut vars = String::new();
    for key in [
        "OP_FAST_STORE_DIR",
        "OP_FAST_CONFIG",
        "OP_FAST_TEST_KEYRING_DIR",
        "OP_FAST_KEYRING_SERVICE",
    ] {
        let value = match key {
            "OP_FAST_STORE_DIR" => env.dir.join("store").display().to_string(),
            "OP_FAST_CONFIG" => env.dir.join("config.toml").display().to_string(),
            "OP_FAST_TEST_KEYRING_DIR" => env.dir.join("keyring").display().to_string(),
            _ => "op-fast-integration-test".to_string(),
        };
        vars.push_str(&format!("set env({}) {{{}}}\n", key, value));
    }
    fs::write(
        &script,
        format!(
            r#"set timeout 10
{vars}spawn /bin/sh -c {{trap 'stty -a; exit 0' INT; "{bin}" sa add agents; stty -a}}
expect "token for agents: "
send "\003"
expect {{
  -re {{lflags:[^\n]*-echo }} {{ puts "RESULT=echo-off"; exit 0 }}
  -re {{lflags:[^\n]* echo }} {{ puts "RESULT=echo-on"; exit 0 }}
  timeout {{ puts "RESULT=timeout"; exit 1 }}
}}
"#,
            vars = vars,
            bin = BIN
        ),
    )
    .unwrap();
    let out = Command::new("/usr/bin/expect")
        .arg(&script)
        .output()
        .unwrap();
    let text = stdout(&out);
    assert!(text.contains("RESULT=echo-on"), "{}", text);
}

#[test]
fn p1_variables_expand_before_caching() {
    let env = Env::new();
    env.set_values(&[
        ("op://prod/db/password", "prod-fake"),
        ("op://dev/db/password", "dev-fake"),
    ]);
    let mut env = env.with("VAULT", "prod");
    assert_eq!(
        stdout(&env.run(&["read", "op://$VAULT/db/password"])),
        "prod-fake\n"
    );
    env.set("VAULT", "dev");
    assert_eq!(
        stdout(&env.run(&["read", "op://$VAULT/db/password"])),
        "dev-fake\n"
    );
    let audit = env.audit_text();
    assert!(audit.contains("\"reference\":\"op://dev/db/password\""));
    assert!(!audit.contains("$VAULT"));
    let out = env.run(&[
        "status",
        "--json",
        "op://prod/db/password",
        "op://dev/db/password",
    ]);
    let rows: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(rows[0]["state"], "valid");
    assert_eq!(rows[1]["state"], "valid");
}

#[test]
fn p2_masked_run_is_lossless() {
    let env = Env::new().with("SECRET", "op://Private/db/password");
    env.set_values(&[("op://Private/db/password", "fake-secret-xyz")]);
    let out = env.run(&["run", "--", "sh", "-c", "seq 1 200000"]);
    assert_ok(&out);
    assert_eq!(stdout(&out).lines().count(), 200000);
    assert!(stdout(&out).ends_with("200000\n"));

    let out = env.run(&[
        "run",
        "--",
        "sh",
        "-c",
        "printf 'a\\377b\\nafter fake-secret-xyz\\n'",
    ]);
    assert_ok(&out);
    assert_eq!(
        out.stdout,
        b"a\xffb\nafter <concealed by 1Password>\n".to_vec()
    );
}

#[test]
fn p3_run_expands_env_before_detecting_and_leaves_argv_alone() {
    let env = Env::new().with("VV", "Private").with("X", "op://$VV/i/f");
    env.set_values(&[
        ("op://Private/i/f", "one-fake"),
        ("op://Private/j/f", "two-fake"),
    ]);
    // Embedded references are resolved only from --env-file (round 3, T2).
    let file = env.dir.join(".env");
    fs::write(&file, "BOTH=op://Private/i/f C=op://Private/j/f\n").unwrap();
    let out = env.run(&[
        "run",
        "--no-masking",
        "--env-file",
        file.to_str().unwrap(),
        "--",
        "sh",
        "-c",
        "printenv X; printenv BOTH",
    ]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "one-fake\none-fake C=two-fake\n");

    // argv is never expanded or substituted by op-fast.
    let out = env.run(&[
        "run",
        "--no-masking",
        "--",
        "echo",
        "op://Private/i/f",
        "$X",
    ]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "op://Private/i/f $X\n");
}

#[test]
fn gc_keeps_entries_inside_grace_and_deletes_past_it() {
    let env = Env::new();
    env.config("default_ttl = \"1s\"\nstale_grace = \"2s\"\n");
    env.set_values(&[
        ("op://Private/old/f", "o"),
        ("op://Private/new/f", "n"),
        ("op://Private/x/f", "x"),
    ]);
    assert_ok(&env.run(&["read", "op://Private/old/f"]));
    std::thread::sleep(Duration::from_millis(3200));
    assert_ok(&env.run(&["read", "op://Private/new/f"]));
    std::thread::sleep(Duration::from_millis(2100));
    // old: expired ~4s ago (past grace); new: expired ~1s ago (in grace).
    let env = env.with("OP_FAST_TEST_FORCE_GC", "1");
    assert_ok(&env.run(&["read", "op://Private/x/f"]));
    let out = env.run(&["store", "list", "--json"]);
    let rows: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let refs: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["reference"].as_str().unwrap())
        .collect();
    assert!(!refs.contains(&"op://Private/old/f"), "{:?}", refs);
    assert!(refs.contains(&"op://Private/new/f"), "{:?}", refs);
}

#[test]
fn force_note_absent_with_out_file_and_out_file_mode_is_600() {
    let env = Env::new();
    env.set_values(&[("op://Private/a/f", "file-fake")]);
    let path = env.dir.join("secret.out");
    let out = env.run(&[
        "read",
        "-f",
        "-o",
        path.to_str().unwrap(),
        "op://Private/a/f",
    ]);
    assert_ok(&out);
    assert_eq!(stderr(&out), "");
    assert_eq!(fs::read_to_string(&path).unwrap(), "file-fake");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

// ------------------------------------------------------ review round 2

#[test]
fn b6_non_reference_cache_keys_are_rejected_everywhere() {
    let env = sa_env();
    for args in [
        vec!["read", "agents"],
        vec!["read", "--refresh", "agents"],
        vec!["status", "agents"],
        vec!["refresh", "agents"],
        vec!["store", "clear", "agents"],
    ] {
        let out = env.run(&args);
        assert!(!out.status.success(), "{:?}", args);
        assert!(
            stderr(&out).contains("must start with op://"),
            "{:?}: {}",
            args,
            stderr(&out)
        );
        assert_no_token_leak(&env, &[&out]);
    }
    assert!(env.calls().is_empty());
    // The stored token is untouched.
    let rows: serde_json::Value =
        serde_json::from_str(&stdout(&env.run(&["sa", "list", "--json"]))).unwrap();
    assert_eq!(rows[0]["token"], true);
}

#[test]
fn b6_cache_code_cannot_address_the_token_service() {
    let env = sa_env().with(
        "OP_FAST_KEYRING_SERVICE",
        "op-fast-integration-test-service-account",
    );
    let out = env.run(&["read", "op://Private/p/f"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("token keyring service"),
        "{}",
        stderr(&out)
    );
    assert_no_token_leak(&env, &[&out]);
    let out = env.run(&["doctor", "--json"]);
    let report: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_ne!(
        report["keyring_services"]["cache"],
        report["keyring_services"]["tokens"]
    );
}

#[test]
fn b7_flag_ordering_cannot_smuggle_a_token() {
    let env = sa_env();
    // The reviewer's repro.
    let out = env.run(&[
        "--sa",
        "agents",
        "--no-masking",
        "read",
        "run",
        "--",
        "/bin/sh",
        "-c",
        "printenv OP_SERVICE_ACCOUNT_TOKEN",
    ]);
    assert_no_token_leak(&env, &[&out]);
    for args in [
        vec!["--format", "json", "item", "list", "--vault", "Agents"],
        vec!["item", "--vault", "Agents", "get", "y"],
        vec!["--sa", "agents", "--format", "json", "item", "list"],
    ] {
        let out = env.run(&args);
        assert_ok(&out);
        assert_no_token_leak(&env, &[&out]);
    }
    for (label, _) in env.calls() {
        assert_eq!(label, "unset");
    }
    // The strict shape still gets a token.
    env.clear_calls();
    assert_ok(&env.run(&["item", "list", "--vault", "Agents", "--format", "json"]));
    assert_eq!(env.calls()[0].0, "agents");
}

#[test]
fn s1_signature_is_verified_before_every_token_bearing_spawn() {
    let env = sa_env();
    let log = env.dir.join("sig.log");
    let env = env.with("OP_FAST_TEST_SIGNATURE_LOG", log.to_str().unwrap());
    let manifest = env.dir.join("refs");
    // The missing ref sinks the batch, so warm falls back to per-ref reads:
    // one inject + two reads = three token-bearing spawns, plus the check
    // before the token is read.
    fs::write(&manifest, "op://Agents/a/f\nop://Agents/gone/f\n").unwrap();
    let out = env.run(&["warm", "--manifest", manifest.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let spawns = env.calls().iter().filter(|(l, _)| l == "agents").count();
    assert_eq!(spawns, 3);
    let checks = fs::read_to_string(&log).unwrap().lines().count();
    assert_eq!(
        checks,
        spawns + 1,
        "one check per token-bearing spawn, uncached"
    );
}

#[test]
fn s2_control_characters_in_references_are_rejected_before_anything() {
    let spoof = "op://Private/x\n[ERROR] 2026/11/09 12:00:00 error initializing client: authorization timeout/f";
    let env = expired_env().with("FAKE_OP_STDERR", APPROVAL_TIMEOUT);
    let audit_before = env.audit_text();
    for args in [
        vec!["read", spoof],
        vec!["status", spoof],
        vec!["refresh", spoof],
        vec!["read", "--account", "x", spoof],
        vec!["read", "op://Private/x\u{1b}[2J/f"],
    ] {
        let out = env.run(&args);
        assert!(!out.status.success(), "{:?}", args);
        assert!(
            stderr(&out).contains("control character"),
            "{}",
            stderr(&out)
        );
    }
    assert!(
        env.calls()
            .iter()
            .all(|(_, a)| a.first().map(String::as_str) != Some("read")
                || !a.iter().any(|x| x.contains('\n')))
    );
    assert_eq!(env.audit_text(), audit_before, "no audit write");
}

#[test]
fn s3_ref_checks_the_signature_before_reading_the_token() {
    let env = sa_env();
    // Make the token unreadable: reading it would fail with a keyring
    // error, so a signature refusal proves the check ran first.
    for dir in fs::read_dir(env.dir.join("keyring")).unwrap().flatten() {
        for f in fs::read_dir(dir.path()).unwrap().flatten() {
            fs::set_permissions(f.path(), fs::Permissions::from_mode(0o000)).unwrap();
        }
    }
    let out = without_signature_escape(&env)
        .args(["ref", "item", "--vault", "Agents"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("not signed by 1Password")
            || stderr(&out).contains("only supported on macOS"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn s4_config_type_errors_never_quote_the_value() {
    let env = Env::new();
    env.config("[[service_account]]\nname = \"a\"\nvaults = \"ops_FAKETOKEN1\"\n");
    for args in [
        vec!["read", "op://Private/x/y"],
        vec!["doctor"],
        vec!["item", "list"],
    ] {
        let out = env.run(&args);
        let text = format!("{}{}", stdout(&out), stderr(&out));
        assert!(!text.contains("FAKETOKEN"), "{:?}: {}", args, text);
    }
    let out = env.run(&["read", "op://Private/x/y"]);
    assert!(
        stderr(&out).contains("service_account.vaults"),
        "{}",
        stderr(&out)
    );
    assert!(stderr(&out).contains("line 3"), "{}", stderr(&out));
}

#[test]
fn s5_tty_fetch_stays_in_the_foreground_group() {
    if !Path::new("/usr/bin/expect").exists() {
        eprintln!("skipping: /usr/bin/expect not available");
        return;
    }
    let env = Env::new();
    let script = env.dir.join("tty.exp");
    let mut vars = String::new();
    for (k, v) in [
        (
            "OP_FAST_STORE_DIR",
            env.dir.join("store").display().to_string(),
        ),
        (
            "OP_FAST_CONFIG",
            env.dir.join("config.toml").display().to_string(),
        ),
        (
            "OP_FAST_TEST_KEYRING_DIR",
            env.dir.join("keyring").display().to_string(),
        ),
        (
            "OP_FAST_KEYRING_SERVICE",
            "op-fast-integration-test".to_string(),
        ),
        ("OP_FAST_COMMAND", env.fake.display().to_string()),
        ("FAKE_OP_TTY_READ", "1".to_string()),
    ] {
        vars.push_str(&format!("set env({}) {{{}}}\n", k, v));
    }
    fs::write(
        &script,
        format!(
            r#"set timeout 8
{vars}spawn "{bin}" read op://Private/tty/f
expect {{
  "enter value: " {{ send "typed-at-tty\r" }}
  timeout {{ puts "RESULT=no-prompt"; exit 1 }}
}}
expect {{
  -re {{typed-at-tty\r?\n.*typed-at-tty}} {{ puts "RESULT=ok"; exit 0 }}
  timeout {{ puts "RESULT=hung"; exit 1 }}
}}
"#,
            vars = vars,
            bin = BIN
        ),
    )
    .unwrap();
    let start = Instant::now();
    let out = Command::new("/usr/bin/expect")
        .arg(&script)
        .output()
        .unwrap();
    let text = stdout(&out);
    assert!(text.contains("RESULT=ok"), "{}", text);
    assert!(start.elapsed() < Duration::from_secs(8));
}

#[test]
fn s6_sa_none_forces_desktop_even_with_vault_and_named_sa_yields() {
    let env = sa_env();
    assert_ok(&env.run(&["--sa", "none", "item", "list", "--vault", "Agents"]));
    assert_ok(&env.run(&["--sa", "ci", "item", "list", "--vault", "Agents"]));
    let labels: Vec<String> = env.calls().into_iter().map(|c| c.0).collect();
    assert_eq!(labels, ["unset", "agents"]);
    let help = stdout(&env.run(&["agent-help"]));
    assert!(
        help.contains("`--sa none` always forces desktop"),
        "{}",
        help
    );
}

#[test]
fn s7_two_op_fast_files_on_path_reach_the_real_op_in_one_hop() {
    let env = Env::new();
    env.set_values(&[("op://Private/db/password", "real-fake-value")]);
    let copy_dir = env.dir.join("copy");
    let link_dir = env.dir.join("link");
    let real_dir = env.dir.join("real");
    for d in [&copy_dir, &link_dir, &real_dir] {
        fs::create_dir_all(d).unwrap();
    }
    fs::copy(BIN, copy_dir.join("op")).unwrap();
    std::os::unix::fs::symlink(BIN, link_dir.join("op")).unwrap();
    write_exe(&real_dir.join("op"), FAKE_OP);
    let path = format!(
        "{}:{}:{}:/usr/bin:/bin",
        copy_dir.display(),
        link_dir.display(),
        real_dir.display()
    );
    let out = env
        .base(&copy_dir.join("op"))
        .env("PATH", path)
        .args(["read", "op://Private/db/password"])
        .output()
        .unwrap();
    assert_ok(&out);
    assert_eq!(stdout(&out), "real-fake-value\n");
    assert_eq!(env.calls().len(), 1);
}

#[test]
fn s9_refresh_is_stripped_only_on_accelerated_commands() {
    let env = Env::new();
    env.set_values(&[("op://a/b/c", "v")]);
    assert_ok(&env.run(&["read", "--refresh", "--account", "x", "op://a/b/c"]));
    assert_ok(&env.run(&["vault", "list", "--refresh", "--sa", "none"]));
    let calls = env.calls();
    assert_eq!(args_of(&calls[0]), ["read", "--account", "x", "op://a/b/c"]);
    assert_eq!(args_of(&calls[1]), ["vault", "list", "--refresh"]);
}

#[test]
fn s10_unset_variable_in_a_reference_is_an_error() {
    let env = Env::new().with("X", "op://$NOPE_VAR/i/f");
    env.set_values(&[("op://Private/db/password", "v")]);
    let out = env.run(&["read", "op://$NOPE_VAR/db/password"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("NOPE_VAR"), "{}", stderr(&out));
    let out = env.run(&["run", "--", "true"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("NOPE_VAR"));
    let out = env.run_stdin(&["inject"], "x={{ op://$NOPE_VAR/db/password }}\n");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("NOPE_VAR"));
    assert!(
        env.calls().is_empty(),
        "never fetch a partly expanded reference"
    );
    assert!(!env.audit_text().contains("op://"), "never audit it either");

    // ${VAR:-default} is supported, as documented.
    let out = env.run(&["read", "op://${NOPE_VAR:-Private}/db/password"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "v\n");
}

#[test]
fn s10_env_file_values_expand_and_inherited_values_do_not() {
    let env = Env::new()
        .with("WHO", "world")
        .with("RAW", "a$WHO ${WHO:-x} \\n");
    let file = env.dir.join(".env");
    fs::write(&file, "GREETING=hello-$WHO\nPLAIN=${MISSING:-fallback}\n").unwrap();
    let out = env.run(&[
        "run",
        "--no-masking",
        "--env-file",
        file.to_str().unwrap(),
        "--",
        "sh",
        "-c",
        "printenv GREETING; printenv PLAIN; printenv RAW",
    ]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "hello-world\nfallback\na$WHO ${WHO:-x} \\n\n");
}

#[test]
fn s11_invoked_as_op_subcommand_help_goes_to_real_op() {
    let env = Env::new();
    let shim_dir = env.dir.join("shim");
    fs::create_dir_all(&shim_dir).unwrap();
    let shim = shim_dir.join("op");
    std::os::unix::fs::symlink(BIN, &shim).unwrap();
    for sub in ["read", "run", "inject"] {
        let out = env
            .base(&shim)
            .env("OP_FAST_COMMAND", &env.fake)
            .args([sub, "--help"])
            .output()
            .unwrap();
        assert_ok(&out);
        assert_eq!(stdout(&out), format!("fake-op: {} --help\n", sub));
    }
    // op-fast's own name keeps op-fast's help.
    let out = env.run(&["read", "--help"]);
    assert!(stdout(&out).contains("--refresh"));
}

#[test]
fn s12_multi_line_secrets_are_masked_per_line_and_signals_map_to_128_plus() {
    // Per-line masking of multi-line values is pinned by
    // run::tests::multi_line_secrets_mask_every_line_and_longest_first (the
    // fake `op` stores one line per value).
    let env = Env::new().with("KEY", "op://Private/key/pem");
    env.set_values(&[("op://Private/key/pem", "line-one-secret")]);
    let out = env.run(&["run", "--", "sh", "-c", "echo before line-one-secret after"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "before <concealed by 1Password> after\n");

    let out = env.run(&["run", "--", "sh", "-c", "kill -TERM $$"]);
    assert_eq!(out.status.code(), Some(128 + 15));
    let out = env.run(&["run", "--no-masking", "--", "sh", "-c", "kill -TERM $$"]);
    assert_eq!(out.status.code(), Some(128 + 15));
}

#[test]
fn s13_inject_reference_never_spans_a_newline() {
    let env = Env::new();
    env.set_values(&[("op://V/i/f", "pw-fake")]);
    let out = env.run_stdin(&["inject"], "password: op://V/i/f\nuser: bob\n");
    assert_ok(&out);
    assert_eq!(stdout(&out), "password: pw-fake\nuser: bob\n");
    let rows: serde_json::Value =
        serde_json::from_str(&stdout(&env.run(&["store", "list", "--json"]))).unwrap();
    let keys: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["reference"].as_str().unwrap())
        .collect();
    assert_eq!(keys, ["op://V/i/f"]);
}

#[test]
fn s14_non_executable_op_on_path_is_skipped() {
    let env = Env::new();
    env.set_values(&[("op://Private/db/password", "real-fake-value")]);
    let noexec = env.dir.join("noexec");
    let real = env.dir.join("real");
    fs::create_dir_all(&noexec).unwrap();
    fs::create_dir_all(&real).unwrap();
    fs::write(noexec.join("op"), "#!/bin/sh\necho evil\n").unwrap();
    fs::set_permissions(noexec.join("op"), fs::Permissions::from_mode(0o644)).unwrap();
    write_exe(&real.join("op"), FAKE_OP);
    let out = env
        .base(Path::new(BIN))
        .env(
            "PATH",
            format!("{}:{}:/usr/bin:/bin", noexec.display(), real.display()),
        )
        .args(["read", "op://Private/db/password"])
        .output()
        .unwrap();
    assert_ok(&out);
    assert_eq!(stdout(&out), "real-fake-value\n");
}

#[test]
fn s14_inherited_env_without_references_is_byte_identical() {
    let odd = "x$HOME ${HOME:-y} op:/not-a-ref \\t \u{e9}";
    let env = Env::new()
        .with("ODD", odd)
        .with("SECRET", "op://Private/db/password");
    env.set_values(&[("op://Private/db/password", "v")]);
    let out = env.run(&["run", "--no-masking", "--", "printenv", "ODD"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), format!("{}\n", odd));
}

// ------------------------------------------------------ review round 3

#[test]
fn b8_run_masks_a_line_pattern_followed_by_another_secret() {
    let env = Env::new()
        .with("PEM", "op://Private/pem/f")
        .with("S", "op://Private/s/f");
    env.set_values(&[
        (
            "op://Private/pem/f",
            "FAKEPEMHEAD-12345ab\\nFAKE-PEM-LINE-2",
        ),
        ("op://Private/s/f", "abcdefSECRET"),
    ]);
    let out = env.run(&[
        "run",
        "--",
        "sh",
        "-c",
        "echo FAKEPEMHEAD-12345abcdefSECRET; echo FAKE-PEM-LINE-2; echo plain",
    ]);
    assert_ok(&out);
    assert_eq!(
        stdout(&out),
        "<concealed by 1Password>\n<concealed by 1Password>\nplain\n"
    );
    // A short line pattern never matches inside inserted mask text.
    env.set_values(&[
        ("op://Private/pem/f", "concealed\\nword"),
        ("op://Private/s/f", "abcdefSECRET"),
    ]);
    let out = env.run(&["run", "--refresh", "--", "echo", "x abcdefSECRET y"]);
    assert_eq!(stdout(&out), "x <concealed by 1Password> y\n");
}

#[test]
fn t1_debug_or_config_flags_never_get_a_token() {
    let env = sa_env();
    for args in [
        vec![
            "--sa",
            "agents",
            "read",
            "--debug",
            "--account",
            "x",
            "op://Agents/a/f",
        ],
        vec!["item", "list", "--vault", "Agents", "--debug"],
        vec![
            "item",
            "list",
            "--vault",
            "Agents",
            "--config",
            "/tmp/fake-op-config",
        ],
        vec![
            "item",
            "list",
            "--vault",
            "Agents",
            "--config=/tmp/fake-op-config",
        ],
    ] {
        env.clear_calls();
        let out = env.run(&args);
        assert_ok(&out);
        assert!(
            stderr(&out).contains("is not used for"),
            "{:?}: {}",
            args,
            stderr(&out)
        );
        assert_eq!(env.calls()[0].0, "unset", "{:?}", args);
        assert_no_token_leak(&env, &[&out]);
    }
    // `ref` refuses an item name that `op` would parse as a flag.
    let out = env.run(&["ref", "--vault", "Agents", "--", "--debug"]);
    assert!(!out.status.success());
}

#[test]
fn t2_inherited_values_are_references_only_when_whole() {
    let env = Env::new()
        .with("DOC", "op://$VAULT_UNSET_T2/item")
        .with("DOC2", "use op://vault/item/field syntax")
        .with("URL", "https://x.test/?next=op://V/zz")
        .with("A", "op://V/i/f");
    env.set_values(&[("op://V/i/f", "resolved-fake")]);
    let out = env.run(&[
        "run",
        "--no-masking",
        "--",
        "sh",
        "-c",
        "printenv DOC; printenv DOC2; printenv URL; printenv A",
    ]);
    assert_ok(&out);
    assert_eq!(
        stdout(&out),
        "op://$VAULT_UNSET_T2/item\nuse op://vault/item/field syntax\nhttps://x.test/?next=op://V/zz\nresolved-fake\n"
    );
    let calls = env.calls();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].1.iter().any(|a| a == "stdin:op://V/i/f"));

    // A whole-value inherited reference with an unset variable is still
    // the named error.
    let env = Env::new().with("W", "op://$VAULT_UNSET_T2/item/field");
    let out = env.run(&["run", "--", "true"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("VAULT_UNSET_T2"));
}

/// Plant a legacy cache entry (a key with a control character) directly in
/// the test store and the debug-only test keyring.
fn plant_legacy_entry(env: &Env, key: &str) -> PathBuf {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Meta {
        stored_at: u64,
        ttl_seconds: u64,
    }
    let store = env.dir.join("store");
    fs::create_dir_all(&store).unwrap();
    let lmdb = unsafe {
        heed::EnvOpenOptions::new()
            .max_dbs(1)
            .map_size(10 * 1024 * 1024)
            .open(&store)
            .unwrap()
    };
    let mut wtxn = lmdb.write_txn().unwrap();
    let db: heed::Database<heed::types::Str, heed::types::SerdeBincode<Meta>> =
        lmdb.create_database(&mut wtxn, None).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    db.put(
        &mut wtxn,
        key,
        &Meta {
            stored_at: now,
            ttl_seconds: 3600,
        },
    )
    .unwrap();
    wtxn.commit().unwrap();
    drop(lmdb);
    let hex = |s: &str| s.bytes().map(|b| format!("{:02x}", b)).collect::<String>();
    let item = env
        .dir
        .join("keyring")
        .join(hex("op-fast-integration-test"))
        .join(hex(key));
    fs::create_dir_all(item.parent().unwrap()).unwrap();
    fs::write(&item, "legacy-fake-value").unwrap();
    item
}

#[test]
fn t3_legacy_control_character_keys_can_be_deleted_but_not_read() {
    let key = "op://Private/legacy\nitem/f";

    // store clear <key> removes keyring item and metadata.
    let env = Env::new();
    let item = plant_legacy_entry(&env, key);
    let list = env.run(&["store", "list"]);
    assert!(
        stdout(&list).contains("op://Private/legacy\\nitem/f"),
        "{}",
        stdout(&list)
    );
    assert!(!stdout(&list).contains("legacy\nitem"));
    assert!(
        !env.run(&["read", key]).status.success(),
        "reads still refuse it"
    );
    let out = env.run(&["store", "clear", key]);
    assert_ok(&out);
    assert!(stdout(&out).contains("Deleted: op://Private/legacy\\nitem/f"));
    assert!(!item.exists(), "keyring item removed");
    assert_eq!(stdout(&env.run(&["store", "list"])), "Store is empty\n");

    // store clear (all) removes it too.
    let env = Env::new();
    let item = plant_legacy_entry(&env, key);
    assert_ok(&env.run(&["store", "clear"]));
    assert!(!item.exists());

    // GC removes it once it is past the grace window (planted long expired).
    let env2 = Env::new();
    env2.config("stale_grace = \"1s\"\n");
    {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Meta {
            stored_at: u64,
            ttl_seconds: u64,
        }
        let store = env2.dir.join("store");
        fs::create_dir_all(&store).unwrap();
        let lmdb = unsafe {
            heed::EnvOpenOptions::new()
                .max_dbs(1)
                .map_size(10 * 1024 * 1024)
                .open(&store)
                .unwrap()
        };
        let mut wtxn = lmdb.write_txn().unwrap();
        let db: heed::Database<heed::types::Str, heed::types::SerdeBincode<Meta>> =
            lmdb.create_database(&mut wtxn, None).unwrap();
        db.put(
            &mut wtxn,
            key,
            &Meta {
                stored_at: 1_000,
                ttl_seconds: 1,
            },
        )
        .unwrap();
        wtxn.commit().unwrap();
    }
    let hex = |s: &str| s.bytes().map(|b| format!("{:02x}", b)).collect::<String>();
    let item2 = env2
        .dir
        .join("keyring")
        .join(hex("op-fast-integration-test"))
        .join(hex(key));
    fs::create_dir_all(item2.parent().unwrap()).unwrap();
    fs::write(&item2, "legacy-fake-value").unwrap();
    let env2 = env2.with("OP_FAST_TEST_FORCE_GC", "1");
    assert_ok(&env2.run(&["store", "list"]));
    assert!(!item2.exists(), "GC removed the legacy keyring item");
    assert_eq!(stdout(&env2.run(&["store", "list"])), "Store is empty\n");
}

#[test]
fn t4_default_applies_when_variable_is_empty() {
    let env = Env::new().with("EMPTY_T4", "");
    env.set_values(&[("op://Private/db/password", "v")]);
    let out = env.run(&["read", "op://${EMPTY_T4:-Private}/db/password"]);
    assert_ok(&out);
    assert_eq!(stdout(&out), "v\n");
}

#[test]
fn t5_unmodeled_flag_on_external_subcommand_keeps_refresh() {
    let env = Env::new();
    assert_ok(&env.run(&["--format", "json", "item", "list", "--refresh"]));
    assert_eq!(
        args_of(&env.calls()[0]),
        ["--format", "json", "item", "list", "--refresh"]
    );
}
