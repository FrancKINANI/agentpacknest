#![cfg(unix)]

//! Black-box CLI tests for `pn run` (Milestones 9, 10, 13).
//!
//! The real binary is exercised through `CARGO_BIN_EXE_pn`. Bundles are
//! assembled with the library so the tests focus on CLI behavior:
//! strict verification by default, the exact `--allow-unverified`
//! boundaries, and flag parsing (never a positional argument).
//!
//! A fake `node` shim is prepended to PATH because the Pi harness runtime
//! check requires Node >= 20 and CI runners do not install Node.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use agentpacknest::domain::manifest;
use agentpacknest::security::integrity;
use agentpacknest::security::signing;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Ensure a signing keypair exists (create it on first use).
fn ensure_keypair() {
    if signing::load_verifying_key().is_err() {
        let _ = signing::generate_keypair();
    }
}

/// Fake `node` that reports v20, satisfying the Pi runtime preflight without
/// requiring a real Node install on the test machine. Created once per
/// process and intentionally leaked (test-only).
fn node_shim() -> &'static Path {
    static SHIM: OnceLock<PathBuf> = OnceLock::new();
    SHIM.get_or_init(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let node = dir.path().join("node");
        fs::write(&node, "#!/bin/sh\necho v20.0.0\n").unwrap();
        let mut perms = fs::metadata(&node).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&node, perms).unwrap();
        std::mem::forget(dir); // leak on purpose: lives for the whole test process
        node
    })
}

fn path_with_shim() -> String {
    let shim = node_shim();
    let orig = std::env::var("PATH").unwrap_or_default();
    format!("{}:{}", shim.display(), orig)
}

/// Assemble a signed, valid bundle under a fresh temp dir.
/// Returns (temp_root, bundle_dir, manifest_path) — caller keeps temp_root alive.
fn signed_bundle(name: &str, payload_value: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    ensure_keypair();
    let root = tempfile::TempDir::new().unwrap();
    let bundle = root.path().join(name);
    fs::create_dir_all(bundle.join("agent/config")).unwrap();
    fs::write(bundle.join("agent/config/settings.json"), payload_value).unwrap();

    let mut m = manifest::default_pi(name, "0.1.0");
    m.integrity.checksum = Some(integrity::compute_bundle_checksum(&bundle).unwrap());
    let manifest_path = bundle.join("manifest.yaml");
    manifest::save(&manifest_path, &m).unwrap();

    let sig = signing::sign_canonical_manifest(&m).unwrap();
    fs::create_dir_all(bundle.join("signing")).unwrap();
    fs::write(bundle.join("manifest.sig"), &sig).unwrap();
    fs::write(
        bundle.join("signing/public.key"),
        signing::get_public_key_bytes().unwrap(),
    )
    .unwrap();

    (root, bundle, manifest_path)
}

/// Run `pn run <bundle> <args>` with a fake node shim on PATH.
fn run_pn(bundle: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pn"))
        .arg("run")
        .arg(bundle)
        .args(args)
        .env("PATH", path_with_shim())
        .output()
        .expect("failed to spawn pn binary")
}

/// Run `pn run <args...>` (no explicit bundle) in `dir` with the shim on PATH.
fn run_pn_bare(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pn"))
        .arg("run")
        .args(args)
        .current_dir(dir)
        .env("PATH", path_with_shim())
        .output()
        .expect("failed to spawn pn binary")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn all_out(o: &Output) -> String {
    format!("{}\n{}", stdout(o), stderr(o))
}

// ---------------------------------------------------------------------------
// Strict default verification (Milestone 9)
// ---------------------------------------------------------------------------

#[test]
fn valid_signed_bundle_dry_run_succeeds() {
    let (_root, bundle, _) = signed_bundle("valid-agent", "v1");
    let out = run_pn(&bundle, &["--dry-run"]);

    assert!(
        out.status.success(),
        "valid bundle must run --dry-run successfully:\n{}",
        all_out(&out)
    );
    let text = all_out(&out);
    assert!(text.contains("Checksum: ✓ verified"), "{}", text);
    assert!(text.contains("Signature: ✓ verified"), "{}", text);
    assert!(text.contains("dry run"), "{}", text);

    // prepare_runtime preserves argument boundaries: the executable is `pi`
    // and `--agent-dir agent` stays a separate, structured argument pair.
    assert!(
        text.contains("Command:     pi --agent-dir agent"),
        "structured args must stay separated:\n{}",
        text
    );
}

#[test]
fn embedded_args_command_refused_with_repack_error() {
    // A manifest whose launch.command embeds arguments with no structured
    // launch.args is ambiguous: whitespace cannot preserve argument
    // boundaries. It must be refused with a clear re-pack error — never
    // silently whitespace-split into a command line.
    let (_root, bundle, manifest_path) = signed_bundle("legacy-agent", "v1");

    let mut m = manifest::load(&manifest_path).unwrap();
    m.launch.command = "pi --agent-dir agent".to_string();
    m.launch.args = vec![];
    manifest::save(&manifest_path, &m).unwrap();
    let sig = signing::sign_canonical_manifest(&m).unwrap();
    fs::write(bundle.join("manifest.sig"), &sig).unwrap();

    let out = run_pn(&bundle, &["--dry-run"]);
    let text = all_out(&out);
    assert!(
        !out.status.success(),
        "ambiguous embedded-args command must be refused:\n{}",
        text
    );
    assert!(
        text.contains("cannot safely run this bundle") && text.contains("re-run `pn pack`"),
        "refusal must carry a clear repack error, got:\n{}",
        text
    );
}

#[test]
fn quoted_command_string_never_shell_parsed() {
    // Even a quoted-looking command string gets no shell semantics: it is
    // ambiguous and refused, never interpreted.
    let (_root, bundle, manifest_path) = signed_bundle("legacy-quoted-agent", "v1");

    let mut m = manifest::load(&manifest_path).unwrap();
    m.launch.command = "pi --name \"hello world\"".to_string();
    m.launch.args = vec![];
    manifest::save(&manifest_path, &m).unwrap();
    let sig = signing::sign_canonical_manifest(&m).unwrap();
    fs::write(bundle.join("manifest.sig"), &sig).unwrap();

    let out = run_pn(&bundle, &["--dry-run"]);
    let text = all_out(&out);
    assert!(
        !out.status.success(),
        "ambiguous quoted command must fail, not run:\n{}",
        text
    );
    assert!(
        text.contains("cannot safely run this bundle"),
        "failure must be a clear error, got:\n{}",
        text
    );
}

#[test]
fn binary_reports_version_0_2_0() {
    let out = Command::new(env!("CARGO_BIN_EXE_pn"))
        .arg("--version")
        .output()
        .expect("failed to spawn pn binary");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "`pn --version` must succeed:\n{}",
        text
    );
    assert_eq!(
        env!("CARGO_PKG_VERSION"),
        "0.2.0",
        "the release crate version must be 0.2.0"
    );
    assert!(
        text.contains(env!("CARGO_PKG_VERSION")),
        "version output must report 0.2.0, got: {}",
        text
    );
}

#[test]
fn tampered_payload_refused_by_default() {
    let (_root, bundle, _) = signed_bundle("tamper-agent", "v1");

    // Tamper with a payload file after packing
    fs::write(bundle.join("agent/config/settings.json"), "EVIL").unwrap();

    let out = run_pn(&bundle, &["--dry-run"]);
    assert!(
        !out.status.success(),
        "tampered payload must be refused by default:\n{}",
        all_out(&out)
    );
    assert!(
        all_out(&out).contains("checksum mismatch"),
        "{}",
        all_out(&out)
    );
}

#[test]
fn invalid_signature_refused_by_default() {
    let (_root, bundle, _) = signed_bundle("sig-agent", "v1");

    // Corrupt the signature file
    let sig_path = bundle.join("manifest.sig");
    let mut sig = fs::read(&sig_path).unwrap();
    sig[0] ^= 0xff;
    fs::write(&sig_path, sig).unwrap();

    let out = run_pn(&bundle, &["--dry-run"]);
    assert!(
        !out.status.success(),
        "invalid signature must be refused by default:\n{}",
        all_out(&out)
    );
    assert!(
        all_out(&out).contains("invalid manifest signature"),
        "{}",
        all_out(&out)
    );
}

#[test]
fn missing_signature_refused_by_default() {
    let (_root, bundle, _) = signed_bundle("nosig-agent", "v1");
    fs::remove_file(bundle.join("manifest.sig")).unwrap();

    let out = run_pn(&bundle, &["--dry-run"]);
    assert!(
        !out.status.success(),
        "missing signature must be refused by default:\n{}",
        all_out(&out)
    );
    assert!(
        all_out(&out).contains("missing manifest signature"),
        "{}",
        all_out(&out)
    );
}

#[test]
fn replaced_public_key_refused_by_default() {
    let (_root, bundle, _) = signed_bundle("swapkey-agent", "v1");

    // Replace bundled public key with a different valid key
    let mut rng = rand::thread_rng();
    let attacker = ed25519_dalek::SigningKey::generate(&mut rng);
    fs::write(
        bundle.join("signing/public.key"),
        attacker.verifying_key().to_bytes(),
    )
    .unwrap();

    let out = run_pn(&bundle, &["--dry-run"]);
    assert!(
        !out.status.success(),
        "replaced public key must be refused by default:\n{}",
        all_out(&out)
    );
    assert!(
        all_out(&out).contains("invalid manifest signature"),
        "{}",
        all_out(&out)
    );
}

// ---------------------------------------------------------------------------
// Trust-layer bypass is bounded: signature failures are bypassable by the
// documented policy (SECURITY.md), but only with the override + warnings.
// ---------------------------------------------------------------------------

#[test]
fn invalid_signature_bypassable_with_override() {
    let (_root, bundle, _) = signed_bundle("override-badsig", "v1");

    let sig_path = bundle.join("manifest.sig");
    let mut sig = fs::read(&sig_path).unwrap();
    sig[0] ^= 0xff;
    fs::write(&sig_path, sig).unwrap();

    let out = run_pn(&bundle, &["--allow-unverified", "--dry-run"]);
    assert!(
        out.status.success(),
        "invalid signature is a trust failure — override must bypass with warnings:\n{}",
        all_out(&out)
    );
    let text = all_out(&out);
    assert!(
        text.contains("--allow-unverified") && text.contains("WARNING"),
        "{}",
        text
    );
}

#[test]
fn replaced_public_key_bypassable_with_override() {
    let (_root, bundle, _) = signed_bundle("override-key", "v1");

    let mut rng = rand::thread_rng();
    let attacker = ed25519_dalek::SigningKey::generate(&mut rng);
    fs::write(
        bundle.join("signing/public.key"),
        attacker.verifying_key().to_bytes(),
    )
    .unwrap();

    let out = run_pn(&bundle, &["--allow-unverified", "--dry-run"]);
    assert!(
        out.status.success(),
        "replaced public key is a trust failure — override must bypass:\n{}",
        all_out(&out)
    );
    let text = all_out(&out);
    assert!(text.contains("WARNING"), "{}", text);
}

#[test]
fn garbage_signature_refused_by_default_and_bypassable_with_override() {
    let (_root, bundle, _) = signed_bundle("garbage-sig", "v1");
    // Unparseable signature material (wrong length, not Ed25519) — the
    // extreme case of "signature cannot be trusted".
    fs::write(bundle.join("manifest.sig"), b"not-an-ed25519-signature").unwrap();

    // Default: refuse.
    let out = run_pn(&bundle, &["--dry-run"]);
    assert!(
        !out.status.success(),
        "garbage signature must be refused by default:\n{}",
        all_out(&out)
    );
    assert!(
        all_out(&out).contains("signature verification failed"),
        "{}",
        all_out(&out)
    );

    // Override: trust cannot be established, but the override is documented
    // to proceed in that case (with warnings) — structural checks already
    // passed (manifest parsed, validated, payload digest intact).
    let out = run_pn(&bundle, &["--allow-unverified", "--dry-run"]);
    assert!(
        out.status.success(),
        "garbage signature is a trust failure — override must bypass with warnings:\n{}",
        all_out(&out)
    );
    assert!(all_out(&out).contains("WARNING"), "{}", all_out(&out));
}

// ---------------------------------------------------------------------------
// --allow-unverified boundaries (Milestone 10)
// ---------------------------------------------------------------------------

#[test]
fn allow_unverified_bypasses_checksum_mismatch() {
    let (_root, bundle, _) = signed_bundle("allow-tamper", "v1");
    fs::write(bundle.join("agent/config/settings.json"), "EVIL").unwrap();

    let out = run_pn(&bundle, &["--allow-unverified", "--dry-run"]);
    assert!(
        out.status.success(),
        "--allow-unverified must continue past a checksum mismatch:\n{}",
        all_out(&out)
    );
    let text = all_out(&out);
    assert!(
        text.contains("--allow-unverified") && text.contains("WARNING"),
        "a strong warning must be printed:\n{}",
        text
    );
}

#[test]
fn allow_unverified_bypasses_missing_signature() {
    let (_root, bundle, _) = signed_bundle("allow-nosig", "v1");
    fs::remove_file(bundle.join("manifest.sig")).unwrap();

    let out = run_pn(&bundle, &["--allow-unverified", "--dry-run"]);
    assert!(
        out.status.success(),
        "--allow-unverified must continue without a signature:\n{}",
        all_out(&out)
    );
}

#[test]
fn allow_unverified_does_not_bypass_invalid_yaml() {
    let (_root, bundle, _) = signed_bundle("bad-yaml", "v1");
    fs::write(bundle.join("manifest.yaml"), "{{{{ not yaml").unwrap();

    let out = run_pn(&bundle, &["--allow-unverified", "--dry-run"]);
    assert!(
        !out.status.success(),
        "--allow-unverified must NOT bypass malformed manifests:\n{}",
        all_out(&out)
    );
    assert!(
        all_out(&out).contains("failed to parse manifest"),
        "{}",
        all_out(&out)
    );
}

#[test]
fn allow_unverified_does_not_bypass_unsupported_schema() {
    let (_root, bundle, manifest_path) = signed_bundle("future-schema", "v1");

    // Rewrite with an unsupported future schema version
    let mut m = manifest::default_pi("future-schema", "0.1.0");
    m.schema_version = "9.9".to_string();
    manifest::save(&manifest_path, &m).unwrap();

    let out = run_pn(&bundle, &["--allow-unverified", "--dry-run"]);
    assert!(
        !out.status.success(),
        "--allow-unverified must NOT bypass unsupported schema versions:\n{}",
        all_out(&out)
    );
    assert!(
        all_out(&out).contains("unsupported schema_version"),
        "{}",
        all_out(&out)
    );
}

#[test]
fn allow_unverified_does_not_bypass_unsupported_bundle_format() {
    let (_root, bundle, manifest_path) = signed_bundle("future-fmt", "v1");

    let mut m = manifest::default_pi("future-fmt", "0.1.0");
    m.bundle_version = 99;
    manifest::save(&manifest_path, &m).unwrap();

    let out = run_pn(&bundle, &["--allow-unverified", "--dry-run"]);
    assert!(
        !out.status.success(),
        "--allow-unverified must NOT bypass unsupported bundle formats:\n{}",
        all_out(&out)
    );
    assert!(
        all_out(&out).contains("unsupported bundle format version"),
        "{}",
        all_out(&out)
    );
}

#[test]
fn allow_unverified_does_not_bypass_missing_manifest() {
    let (_root, bundle, _) = signed_bundle("no-manifest", "v1");
    fs::remove_file(bundle.join("manifest.yaml")).unwrap();

    let out = run_pn(&bundle, &["--allow-unverified", "--dry-run"]);
    assert!(
        !out.status.success(),
        "--allow-unverified must NOT bypass a missing manifest:\n{}",
        all_out(&out)
    );
}

#[test]
fn allow_unverified_does_not_bypass_traversal_workdir() {
    // A manifest whose launch.working_directory escapes the bundle must be
    // refused even with --allow-unverified (structural, not trust, check).
    let (_root, bundle, manifest_path) = signed_bundle("traversal-agent", "v1");

    let mut m = manifest::default_pi("traversal-agent", "0.1.0");
    m.launch.working_directory = Some("../..".to_string());
    manifest::save(&manifest_path, &m).unwrap();

    let out = run_pn(&bundle, &["--allow-unverified", "--dry-run"]);
    assert!(
        !out.status.success(),
        "--allow-unverified must NOT bypass path traversal:\n{}",
        all_out(&out)
    );
    assert!(
        all_out(&out).contains("must stay inside the bundle")
            || all_out(&out).contains("escapes the bundle"),
        "{}",
        all_out(&out)
    );
}

// ---------------------------------------------------------------------------
// Structural failures can never be bypassed, even by --allow-unverified
// ---------------------------------------------------------------------------

#[test]
fn absolute_working_directory_refused_even_with_override() {
    // launch.working_directory must be bundle-relative; an absolute path is
    // a structural (format) failure rejected at manifest validation.
    let (_root, bundle, manifest_path) = signed_bundle("abs-wd-agent", "v1");

    let mut m = manifest::load(&manifest_path).unwrap();
    m.launch.working_directory = Some("/tmp".to_string());
    manifest::save(&manifest_path, &m).unwrap();

    let out = run_pn(&bundle, &["--allow-unverified", "--dry-run"]);
    assert!(
        !out.status.success(),
        "absolute working_directory must be refused even with override:\n{}",
        all_out(&out)
    );
    assert!(
        all_out(&out).contains("must be relative to the bundle root"),
        "{}",
        all_out(&out)
    );
}

#[test]
fn missing_declared_secrets_file_refused_even_with_override() {
    // The manifest declares secrets_encrypted but secrets/keys.enc is absent:
    // a structurally broken bundle. Decryption is attempted only after
    // verification — and the missing file is refused regardless of override.
    let (_root, bundle, manifest_path) = signed_bundle("no-keys-agent", "v1");

    let mut m = manifest::load(&manifest_path).unwrap();
    m.security.secrets_encrypted = true;
    m.security.encryption = Some("aes-256-gcm".to_string());
    manifest::save(&manifest_path, &m).unwrap();
    let sig = signing::sign_canonical_manifest(&m).unwrap();
    fs::write(bundle.join("manifest.sig"), &sig).unwrap();

    let out = run_pn(&bundle, &["--allow-unverified", "--dry-run"]);
    assert!(
        !out.status.success(),
        "missing declared secrets file must be refused even with override:\n{}",
        all_out(&out)
    );
    assert!(
        all_out(&out).contains("secrets/keys.enc is missing"),
        "{}",
        all_out(&out)
    );
}

// ---------------------------------------------------------------------------
// Flag parsing (Milestone 10: --allow-unverified is always a flag)
// ---------------------------------------------------------------------------

#[test]
fn allow_unverified_parses_before_bundle_path() {
    // `pn run --allow-unverified <bundle> --dry-run`
    let (_root, bundle, _) = signed_bundle("flag-first", "v1");

    let out = Command::new(env!("CARGO_BIN_EXE_pn"))
        .arg("run")
        .arg("--allow-unverified")
        .arg(&bundle)
        .arg("--dry-run")
        .env("PATH", path_with_shim())
        .output()
        .expect("failed to spawn pn binary");

    assert!(
        out.status.success(),
        "--allow-unverified before the bundle path must be treated as a flag:\n{}",
        all_out(&out)
    );
}

#[test]
fn allow_unverified_is_not_a_positional_bundle_argument() {
    // `pn run --allow-unverified` with no bundle defaults the bundle to "."
    // and must fail cleanly (no manifest there) — never panic, never exec.
    let root = tempfile::TempDir::new().unwrap();

    let out = run_pn_bare(root.path(), &["--allow-unverified"]);
    let text = all_out(&out);
    assert!(!text.contains("panic"), "must not panic: {}", text);
    assert!(
        text.contains("no manifest.yaml") || text.contains("manifest"),
        "{}",
        text
    );
}

// ---------------------------------------------------------------------------
// Structural failures are clean (never panic)
// ---------------------------------------------------------------------------

#[test]
fn non_bundle_directory_fails_cleanly() {
    let root = tempfile::TempDir::new().unwrap();

    let out = run_pn(root.path(), &["--dry-run"]);
    let text = all_out(&out);
    assert!(!out.status.success());
    assert!(!text.contains("panic"), "must not panic: {}", text);
    assert!(text.contains("no manifest.yaml"), "{}", text);
}

#[test]
fn nonexistent_bundle_path_fails_cleanly() {
    let missing = Path::new("/nonexistent/bundle/dir");

    let out = run_pn(missing, &["--dry-run"]);
    let text = all_out(&out);
    assert!(!out.status.success());
    assert!(!text.contains("panic"), "must not panic: {}", text);
}
