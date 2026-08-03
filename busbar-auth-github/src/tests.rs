// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! GitHub-login logic tests. Hermetic — no network: the CORE executes hops in production, so these
//! drive the pure helpers and the `LoginModule` step machine directly with fixture response bodies.

use super::*;
use busbar_api::{BeginLogin, CompleteLogin, LoginHttpResponse, LoginOutcome};

fn cfg() -> GitHubConfig {
    GitHubConfig {
        client_id: "Iv1.client".to_string(),
        scopes: default_scopes(),
        api_base: default_api_base(),
        authorize_base: default_authorize_base(),
        token_base: default_token_base(),
        fetch_orgs: true,
        ca_cert_pem: None,
    }
}

fn resp(status: u16, body: &str) -> LoginHttpResponse {
    LoginHttpResponse {
        status,
        body: body.to_string(),
    }
}

fn expect_exchange(outcome: LoginOutcome) -> LoginHop {
    match outcome {
        LoginOutcome::Exchange(hop) => hop,
        other => panic!("expected Exchange, got {other:?}"),
    }
}

fn expect_identify(outcome: LoginOutcome) -> Principal {
    match outcome {
        LoginOutcome::Identify(p) => p,
        other => panic!("expected Identify, got {other:?}"),
    }
}

// ── authorize URL ───────────────────────────────────────────────────────────────────────────────

#[test]
fn build_github_authorize_url_has_state_scope_no_secret() {
    let url = build_github_authorize_url(
        &cfg(),
        "https://busbar.example/auth/token",
        "state-xyz",
        "challenge-abc",
        &[],
    );
    assert!(url.starts_with("https://github.com/login/oauth/authorize?"), "{url}");
    assert!(url.contains("client_id=Iv1.client"), "{url}");
    assert!(url.contains("state=state-xyz"), "{url}");
    assert!(url.contains("code_challenge=challenge-abc"), "{url}");
    assert!(url.contains("code_challenge_method=S256"), "{url}");
    // scope: default read:org + read:user, space-encoded (%20).
    assert!(url.contains("scope=read%3Aorg%20read%3Auser"), "{url}");
    // redirect_uri present and percent-encoded.
    assert!(
        url.contains("redirect_uri=https%3A%2F%2Fbusbar.example%2Fauth%2Ftoken"),
        "{url}"
    );
    // Structurally NO client secret on the begin path.
    assert!(!url.contains("client_secret") && !url.contains("secret"), "{url}");
}

#[test]
fn begin_login_folds_in_request_time_extra_scopes_deduped() {
    let module = GithubModule::new(cfg());
    let begin = BeginLogin {
        redirect_uri: "https://busbar.example/auth/token".to_string(),
        state: "st".to_string(),
        code_challenge: "ch".to_string(),
        nonce: None,
        scopes: vec!["read:user".to_string(), "repo".to_string()],
    };
    let url = match module.begin_login(&begin) {
        LoginOutcome::Authorize(u) => u,
        other => panic!("expected Authorize, got {other:?}"),
    };
    // read:user is not duplicated; repo is appended.
    assert!(url.contains("scope=read%3Aorg%20read%3Auser%20repo"), "{url}");
}

// ── token-exchange hop ────────────────────────────────────────────────────────────────────────────

#[test]
fn complete_login_first_returns_token_exchange_hop() {
    let module = GithubModule::new(cfg());
    let req = CompleteLogin {
        code: Some("authcode".to_string()),
        redirect_uri: Some("https://busbar.example/auth/token".to_string()),
        code_verifier: Some("verifier".to_string()),
        ..Default::default()
    };
    let hop = expect_exchange(module.complete_login(&req));
    assert_eq!(hop.method, "POST");
    assert_eq!(hop.url, "https://github.com/login/oauth/access_token");
    // The CORE injects the secret into this exact field; the module never writes the value.
    assert_eq!(hop.secret_form_field.as_deref(), Some("client_secret"));
    let form: std::collections::HashMap<_, _> = hop.form.iter().cloned().collect();
    assert_eq!(form.get("client_id").map(String::as_str), Some("Iv1.client"));
    assert_eq!(form.get("code").map(String::as_str), Some("authcode"));
    assert_eq!(
        form.get("redirect_uri").map(String::as_str),
        Some("https://busbar.example/auth/token")
    );
    assert_eq!(form.get("code_verifier").map(String::as_str), Some("verifier"));
    // client_secret is present as an EMPTY placeholder — the value is the CORE's to fill.
    assert_eq!(form.get("client_secret").map(String::as_str), Some(""));
}

#[test]
fn complete_login_first_without_full_triple_rejects() {
    let module = GithubModule::new(cfg());
    let req = CompleteLogin {
        code: Some("authcode".to_string()),
        // missing redirect_uri + code_verifier
        ..Default::default()
    };
    assert_eq!(module.complete_login(&req), LoginOutcome::Reject);
}

// ── /user GET hop (after token) ────────────────────────────────────────────────────────────────────

#[test]
fn complete_login_after_token_returns_userinfo_get_hop() {
    let module = GithubModule::new(cfg());
    let req = CompleteLogin {
        code_verifier: Some("verifier".to_string()),
        token_response: Some(resp(
            200,
            r#"{"access_token":"gho_opaque","token_type":"bearer","scope":"read:org,read:user"}"#,
        )),
        ..Default::default()
    };
    let hop = expect_exchange(module.complete_login(&req));
    assert_eq!(hop.method, "GET");
    assert_eq!(hop.url, "https://api.github.com/user");
    // A userinfo hop carries no secret.
    assert_eq!(hop.secret_form_field, None);
    assert!(hop.form.is_empty());

    // The Authorization: Bearer + User-Agent the CORE must attach (ABI gap: no header slot on LoginHop).
    let headers = userinfo_headers("gho_opaque");
    assert!(headers
        .iter()
        .any(|(k, v)| k == "Authorization" && v == "Bearer gho_opaque"));
    assert!(headers.iter().any(|(k, v)| k == "User-Agent" && v == "busbar"));
}

#[test]
fn token_response_form_encoded_also_yields_userinfo_hop() {
    // GitHub returns x-www-form-urlencoded without an Accept: application/json header — handle it.
    let module = GithubModule::new(cfg());
    let req = CompleteLogin {
        code_verifier: Some("v".to_string()),
        token_response: Some(resp(
            200,
            "access_token=gho_form&scope=read%3Aorg&token_type=bearer",
        )),
        ..Default::default()
    };
    let hop = expect_exchange(module.complete_login(&req));
    assert_eq!(hop.url, "https://api.github.com/user");
    assert_eq!(parse_access_token("access_token=gho_form&x=1").as_deref(), Some("gho_form"));
}

// ── identity (after /user, after /user/orgs) ───────────────────────────────────────────────────────

#[test]
fn complete_login_after_userinfo_identifies() {
    // Direct-helper form: good /user JSON → Identify github:<login>; + orgs JSON → github:org groups.
    let user = r#"{"login":"octocat","id":583231,"name":"The Octocat"}"#;
    let orgs = r#"[{"login":"github"},{"login":"octo-org"}]"#;

    let p = expect_identify(identity_from_user_and_orgs(user, Some(orgs)));
    assert_eq!(p.id, "github:octocat");
    assert_eq!(p.name.as_deref(), Some("The Octocat"));
    assert_eq!(
        p.roles,
        vec!["github:org/github".to_string(), "github:org/octo-org".to_string()]
    );
}

#[test]
fn full_hop_chain_through_the_module_identifies_with_org_groups() {
    // Drive the whole chain through complete_login the way the CORE would, feeding each hop's response
    // back. The correlator (code_verifier) threads the opaque token + /user identity across hops.
    let module = GithubModule::new(cfg());
    let cv = Some("the-verifier".to_string());

    // 1) code → token exchange POST
    let r1 = module.complete_login(&CompleteLogin {
        code: Some("c".into()),
        redirect_uri: Some("https://busbar.example/auth/token".into()),
        code_verifier: cv.clone(),
        ..Default::default()
    });
    assert!(matches!(r1, LoginOutcome::Exchange(h) if h.method == "POST"));

    // 2) token response → /user GET
    let r2 = module.complete_login(&CompleteLogin {
        code_verifier: cv.clone(),
        token_response: Some(resp(200, r#"{"access_token":"gho_x"}"#)),
        ..Default::default()
    });
    assert!(matches!(r2, LoginOutcome::Exchange(ref h) if h.url.ends_with("/user")));

    // 3) /user response → /user/orgs GET
    let r3 = module.complete_login(&CompleteLogin {
        code_verifier: cv.clone(),
        token_response: Some(resp(200, r#"{"login":"octocat","id":1}"#)),
        ..Default::default()
    });
    assert!(matches!(r3, LoginOutcome::Exchange(ref h) if h.url.ends_with("/user/orgs")));

    // 4) /user/orgs response → Identify with org groups
    let r4 = module.complete_login(&CompleteLogin {
        code_verifier: cv.clone(),
        token_response: Some(resp(200, r#"[{"login":"acme"}]"#)),
        ..Default::default()
    });
    let p = expect_identify(r4);
    assert_eq!(p.id, "github:octocat");
    assert_eq!(p.roles, vec!["github:org/acme".to_string()]);
}

#[test]
fn fetch_orgs_false_identifies_after_user_without_org_hop() {
    let mut c = cfg();
    c.fetch_orgs = false;
    let module = GithubModule::new(c);
    let out = module.complete_login(&CompleteLogin {
        code_verifier: Some("v".into()),
        token_response: Some(resp(200, r#"{"login":"solo","id":9}"#)),
        ..Default::default()
    });
    let p = expect_identify(out);
    assert_eq!(p.id, "github:solo");
    assert!(p.roles.is_empty());
}

// ── fail-closed ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn reject_on_non_2xx() {
    let module = GithubModule::new(cfg());
    let out = module.complete_login(&CompleteLogin {
        code_verifier: Some("v".into()),
        token_response: Some(resp(401, r#"{"access_token":"should-be-ignored"}"#)),
        ..Default::default()
    });
    assert_eq!(out, LoginOutcome::Reject);
}

#[test]
fn reject_on_missing_access_token() {
    // GitHub answers HTTP 200 with an {"error":...} body on a bad code — no access_token, and the
    // body is an object without `login`, so it fails closed at the userinfo-parse branch.
    let module = GithubModule::new(cfg());
    let out = module.complete_login(&CompleteLogin {
        code_verifier: Some("v".into()),
        token_response: Some(resp(200, r#"{"error":"bad_verification_code"}"#)),
        ..Default::default()
    });
    assert_eq!(out, LoginOutcome::Reject);
    assert_eq!(parse_access_token(r#"{"error":"bad_verification_code"}"#), None);
}

#[test]
fn reject_on_missing_login() {
    // A /user response lacking `login` (or malformed) is a hard failure.
    let module = GithubModule::new(cfg());
    // Prime the token step so the next response is treated as /user.
    module.complete_login(&CompleteLogin {
        code_verifier: Some("v".into()),
        token_response: Some(resp(200, r#"{"access_token":"gho_x"}"#)),
        ..Default::default()
    });
    let out = module.complete_login(&CompleteLogin {
        code_verifier: Some("v".into()),
        token_response: Some(resp(200, r#"{"id":42,"name":"No Login"}"#)),
        ..Default::default()
    });
    assert_eq!(out, LoginOutcome::Reject);
    assert_eq!(parse_user(r#"{"id":42}"#), None);
}

#[test]
fn reject_on_malformed_user_json() {
    assert_eq!(parse_user("{ not json"), None);
    assert_eq!(identity_from_user_and_orgs("{ not json", None), LoginOutcome::Reject);
}

// ── GHES base URL overrides ────────────────────────────────────────────────────────────────────────

#[test]
fn ghes_base_urls_config() {
    let c = GitHubConfig {
        client_id: "ent-client".to_string(),
        scopes: default_scopes(),
        api_base: "https://ghe.corp.example/api/v3".to_string(),
        authorize_base: "https://ghe.corp.example".to_string(),
        token_base: "https://ghe.corp.example".to_string(),
        fetch_orgs: true,
        ca_cert_pem: Some("-----BEGIN CERTIFICATE-----\n...".to_string()),
    };
    // authorize URL → GHES host
    let url = build_github_authorize_url(&c, "https://busbar/auth/token", "s", "ch", &[]);
    assert!(url.starts_with("https://ghe.corp.example/login/oauth/authorize?"), "{url}");
    // token endpoint → GHES host
    let hop = build_token_exchange(&c, "code", "https://busbar/auth/token", "v");
    assert_eq!(hop.url, "https://ghe.corp.example/login/oauth/access_token");
    // REST endpoints → GHES /api/v3
    assert_eq!(build_userinfo_get(&c).url, "https://ghe.corp.example/api/v3/user");
    assert_eq!(build_orgs_get(&c).url, "https://ghe.corp.example/api/v3/user/orgs");
}

// ── parsing helpers ──────────────────────────────────────────────────────────────────────────────

#[test]
fn parse_org_groups_maps_and_skips_bad_entries() {
    let groups = parse_org_groups(r#"[{"login":"a"},{"id":1},{"login":""},{"login":"b"}]"#);
    assert_eq!(groups, vec!["github:org/a".to_string(), "github:org/b".to_string()]);
    // non-array → empty (login still succeeds with no groups)
    assert!(parse_org_groups(r#"{"message":"Not Found"}"#).is_empty());
}

#[test]
fn authenticate_passes_opaque_bearer() {
    let module = GithubModule::new(cfg());
    assert_eq!(module.authenticate(Some("gho_whatever")), AuthOutcome::Pass);
    assert_eq!(module.authenticate(None), AuthOutcome::Pass);
    assert_eq!(module.name(), "github");
    assert!(!module.cacheable());
}
