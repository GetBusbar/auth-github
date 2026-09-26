// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE AUTH MODULE, BOTH DOORS, ONE ROW** — the GitHub login module's linked + dropped-in
//! conformance (DECISIONS #2 rule (1): a plugin is compiled in OR dropped in — same contract, same
//! loading path), run against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The module is held two ways at once: LINKED (this crate's `BUSBAR_COLD_ENTRY`, the boundary
//! `export_login_plugin!` emits and a busbar build that compiles the module in hands the loader,
//! through `PluginRegistry::link`) and DROPPED IN (this crate's built cdylib, signed first-party
//! under the SAME statement into a temp `plugins/` directory and found by the loader's scan). Each
//! arm is opened by the one `open_login` and driven through the same script — the verify face, the
//! login kind, the authorize URL built from core-minted state and PKCE, and the whole
//! code → token → `/user` → `/user/orgs` hop chain the CORE executes — and the two transcripts, with
//! the registry row each door resolves the name to, must be byte-identical.
//!
//! The RED arms are in the same file: the same cdylib opened under a DIFFERENT config is a different
//! transcript (so the equality is not vacuous), and the same bytes signed as `secret` are refused at
//! the kind handshake, naming both kinds. A missing cdylib PANICS — this test IS the dropped-in
//! door's proof, and never skips.

use busbar_contract::auth::{AuthPlugin, BeginLogin, CompleteLogin, LoginHttpResponse};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

/// The module's registry name and alias (what an operator's `auth.chain` names).
const NAME: &str = "busbar-auth-github";
const ALIAS: &str = "github";

/// The operator config both arms are opened with.
const CFG: &str = r#"{"client_id":"Iv1.conformance","fetch_orgs":true}"#;

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip.
fn cdylib() -> Vec<u8> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_auth_github_plugin");
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-auth-github-plugin cdylib ({file}) is not built"));
    std::fs::read(found).expect("read the cdylib")
}

/// The statement both doors make for the module, as `kind`, at the newest payload schema the
/// loader speaks for that kind.
fn statement(kind: &str) -> Manifest {
    Manifest {
        name: NAME.into(),
        alias: ALIAS.into(),
        kind: kind.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: *busbar_plugin_loader::supported_abi(kind)
            .iter()
            .max()
            .expect("a payload schema for the kind"),
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
    }
}

/// THE LINKED DOOR: this crate's boundary, registered through `PluginRegistry::link`.
fn linked() -> PluginRegistry {
    PluginRegistry::empty()
        .link(vec![LinkedPlugin::boundary(
            statement("auth"),
            &busbar_auth_github_plugin::BUSBAR_COLD_ENTRY,
        )])
        .expect("the linked door admits the module")
}

/// THE DROPPED-IN DOOR: `lib` signed first-party under `manifest` into a fresh `plugins/`
/// directory, scanned under a policy holding the release key.
fn dropped(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    let dir = std::env::temp_dir().join(format!("auth-github-conf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let signed = sign(&release(), manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libauth.so", lib).unwrap();
    std::fs::write(dir.join("auth.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release().verifying_key()),
        binary_version: env!("CARGO_PKG_VERSION").into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    let registry =
        busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the signed module scans");
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

fn resp(status: u16, body: &str) -> Option<LoginHttpResponse> {
    Some(LoginHttpResponse {
        status,
        body: body.into(),
    })
}

/// What one door does with the module opened under `cfg`, as one comparable transcript: the row the
/// name resolves to (and the row its alias resolves to), then the script's every answer.
fn transcript(registry: &PluginRegistry, cfg: &str) -> Vec<String> {
    let p = registry.resolve(NAME).expect("the name resolves");
    let stated = Manifest {
        sha256: String::new(),
        signature: String::new(),
        ..p.manifest.clone()
    };
    let by_alias = registry.resolve(ALIAS).map(|a| a.manifest.name.clone());
    let (module, abi): (Box<dyn AuthPlugin>, u32) = registry
        .open_login(ALIAS, cfg)
        .expect("the module opens through its alias");
    let cv = Some("conformance-verifier".to_string());
    let feed = |body: Option<LoginHttpResponse>| CompleteLogin {
        code_verifier: cv.clone(),
        token_response: body,
        ..Default::default()
    };
    vec![
        serde_json::to_string(&stated).unwrap(),
        format!("alias -> {by_alias:?}; abi {abi}"),
        format!("name={} cacheable={}", module.name(), module.cacheable()),
        format!("login_kind={:?}", module.login_kind()),
        format!("{:?}", module.authenticate(Some("gho_opaque"))),
        format!("{:?}", module.authenticate(None)),
        format!(
            "{:?}",
            module.begin_login(&BeginLogin {
                redirect_uri: "https://node.example/auth/token".into(),
                state: "conformance-state".into(),
                code_challenge: "conformance-challenge".into(),
                nonce: None,
                scopes: vec!["user:email".into()],
            })
        ),
        // The hop chain the CORE executes: code -> token exchange, token -> /user, /user -> orgs,
        // orgs -> Identify.
        format!(
            "{:?}",
            module.complete_login(&CompleteLogin {
                code: Some("the-code".into()),
                redirect_uri: Some("https://node.example/auth/token".into()),
                ..feed(None)
            })
        ),
        format!(
            "{:?}",
            module.complete_login(&feed(resp(200, r#"{"access_token":"gho_x"}"#)))
        ),
        format!(
            "{:?}",
            module.complete_login(&feed(resp(200, r#"{"login":"octocat","id":1}"#)))
        ),
        format!(
            "{:?}",
            module.complete_login(&feed(resp(200, r#"[{"login":"acme"}]"#)))
        ),
        // A refused step: a non-2xx token response fails closed.
        format!(
            "{:?}",
            module.complete_login(&CompleteLogin {
                code: Some("the-code".into()),
                redirect_uri: Some("https://node.example/auth/token".into()),
                ..feed(None)
            })
        ),
        format!("{:?}", module.complete_login(&feed(resp(401, "{}")))),
    ]
}

/// The GitHub module registers ONE row and behaves as ONE module through either door — and the RED
/// arms show the comparison is not vacuous.
#[test]
fn the_linked_and_the_dropped_in_github_module_are_one_module() {
    let lib = cdylib();
    let linked = transcript(&linked(), CFG);
    let dropped_registry = dropped("dropped", statement("auth"), &lib);
    let dropped_in = transcript(&dropped_registry, CFG);
    assert_eq!(linked, dropped_in, "the two doors are not one module");

    // Not a vacuous pass: the script did what the module is for.
    let text = linked.join("\n");
    assert!(
        text.contains("Authorize(\"https://github.com/login/oauth/authorize?"),
        "{text}"
    );
    assert!(
        text.contains("state=conformance-state&code_challenge=conformance-challenge"),
        "{text}"
    );
    assert!(text.contains("id: \"github:octocat\""), "{text}");
    assert!(text.contains("\"github:org/acme\""), "{text}");
    assert_eq!(linked.last().map(String::as_str), Some("Reject"));

    // RED ARM 1: the same cdylib under a different operator config is a different transcript.
    let other = transcript(
        &dropped_registry,
        r#"{"client_id":"Iv1.someone-else","fetch_orgs":false}"#,
    );
    assert_ne!(
        other, linked,
        "a different config must not read as the same module"
    );

    // RED ARM 2: the same bytes signed as `secret` are refused at the kind handshake.
    let wrong = dropped("as-secret", statement("secret"), &lib);
    let e = match wrong.open_secret(ALIAS, CFG) {
        Ok(_) => panic!("an auth library signed as secret must not open"),
        Err(e) => e,
    };
    assert!(
        e.contains(&format!(
            "plugin '{NAME}' exports kind 'auth' but is being loaded as 'secret'"
        )),
        "{e}"
    );
}
