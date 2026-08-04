// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Unit tests for THIS crate's own responsibility: adapting the engine's JSON config into a real
//! GitHub login module. Hermetic — no network. The hop-chain / identity logic is `busbar-auth-github`'s
//! own job and is covered by that crate's tests; these only cover what `open` does with the config.

use super::open;
use busbar_api::{AuthPlugin, BeginLogin, LoginOutcome};

fn expect_err(result: Result<Box<dyn AuthPlugin>, String>) -> String {
    match result {
        Ok(_) => panic!("expected open() to fail, but it succeeded"),
        Err(e) => e,
    }
}

#[test]
fn empty_config_is_rejected() {
    assert!(expect_err(open("")).contains("config"));
    assert!(expect_err(open("   \n\t ")).contains("config"));
}

#[test]
fn malformed_json_is_rejected() {
    assert!(expect_err(open("{ not json")).contains("invalid github plugin config"));
}

#[test]
fn config_missing_client_id_is_rejected() {
    // `client_id` has no default in GitHubConfig — it is required.
    let err = expect_err(open(r#"{"scopes":["read:user"]}"#));
    assert!(err.contains("invalid github plugin config"), "got: {err}");
}

#[test]
fn unknown_config_field_is_rejected() {
    // GitHubConfig is deny_unknown_fields — a stray operator key fails loud at boot.
    let err = expect_err(open(r#"{"client_id":"x","bogus":true}"#));
    assert!(err.contains("invalid github plugin config"), "got: {err}");
}

#[test]
fn secret_field_in_config_is_rejected() {
    // The client_secret is the CORE's alone (browser_login.client_secret). deny_unknown_fields makes
    // an attempt to put it in the module config a hard error, structurally keeping it off this path.
    let err = expect_err(open(r#"{"client_id":"x","client_secret":"leak"}"#));
    assert!(err.contains("invalid github plugin config"), "got: {err}");
}

#[test]
fn minimal_config_succeeds_and_is_login_capable() {
    let module = open(r#"{"client_id":"Iv1.abc"}"#).expect("minimal config must succeed");
    assert_eq!(module.name(), "github");
    assert!(!module.cacheable());

    // export_login_plugin! keeps the login capability LIVE (unlike the verify-only adapter): a
    // begin_login returns a GitHub Authorize URL, not the fail-closed Reject default.
    let begin = BeginLogin {
        redirect_uri: "https://busbar.example/auth/token".to_string(),
        state: "s".to_string(),
        code_challenge: "ch".to_string(),
        nonce: None,
        scopes: vec![],
    };
    match module.begin_login(&begin) {
        LoginOutcome::Authorize(url) => {
            assert!(
                url.starts_with("https://github.com/login/oauth/authorize?"),
                "{url}"
            )
        }
        other => panic!("login capability must be live, got {other:?}"),
    }
}
