// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **GitHub-OAuth login module as a droppable busbar plugin** — a `cdylib` that exports the auth
//! C ABI ([`busbar_plugin_abi::auth`]), LOGIN-CAPABLE (auth ABI v2). Build it, drop the resulting
//! `.so`/`.dll`/`.dylib` into the engine's plugins folder, add `github` to `auth.chain` with a
//! `browser_login` block (holding the confidential-client `client_secret` the CORE injects), and
//! configure the module `config`; the engine loads it in-process at boot over the auth ABI.
//!
//! All the GitHub logic (authorize-URL, the token-exchange + `/user` + `/user/orgs` hop chain, the
//! identity mapping) lives in the `busbar-auth-github` `lib` crate (which a custom build can also link
//! statically). Here we only adapt the engine's JSON config into a [`GithubModule`] and hand the
//! login-capable trait object to the SDK via [`busbar_plugin_sdk::export_login_plugin!`] — the LOGIN
//! export macro (NOT `export_auth_plugin!`, which would mask the browser-login capability behind the
//! verify-only adapter). The macro emits the six extern-C symbols the loader resolves (`busbar_abi`,
//! `busbar_plugin_kind`, `busbar_open`, `busbar_call`, `busbar_free`, `busbar_close`).

use busbar_api::AuthPlugin;
use busbar_auth_github::{GitHubConfig, GithubModule};

/// Construct a GitHub login module from the JSON config the engine passes through `open`. Shape:
///
/// ```json
/// {
///   "client_id": "Iv1.abc123",
///   "scopes": ["read:org", "read:user"],
///   "api_base": "https://api.github.com",
///   "authorize_base": "https://github.com",
///   "token_base": "https://github.com",
///   "fetch_orgs": true
/// }
/// ```
///
/// Only `client_id` is required; every other field defaults (see [`GitHubConfig`]). The
/// confidential-client `client_secret` is NEVER in this config — the CORE holds it
/// (`browser_login.client_secret`) and injects it into the token-exchange hop. For GitHub Enterprise
/// Server, override `api_base` (`https://<host>/api/v3`), `authorize_base`, and `token_base`
/// (`https://<host>`).
fn open(cfg: &str) -> Result<Box<dyn AuthPlugin>, String> {
    if cfg.trim().is_empty() {
        return Err("github plugin requires config (client_id); none provided".to_string());
    }
    let cfg: GitHubConfig =
        serde_json::from_str(cfg).map_err(|e| format!("invalid github plugin config: {e}"))?;
    Ok(Box::new(GithubModule::new(cfg)))
}

busbar_plugin_sdk::export_login_plugin!(open);

#[cfg(test)]
mod tests;
