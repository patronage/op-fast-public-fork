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
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
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
    let out = env.run(&["store", "list"]);
    assert_eq!(stdout(&out), "fake-op: store list\n");
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
    let labels: Vec<String> = env.calls().into_iter().map(|c| c.0).collect();
    assert_eq!(labels, ["agents", "unset", "ci"]);
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
    assert_eq!(stdout(&out), "op://vltfake456/itmfake123/fldfake789\n");
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
    assert!(stdout(&all).contains("op://vltfake456/itmfake123/username\tusername"));
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
