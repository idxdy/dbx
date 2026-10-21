use crate::connection::{AppState, PoolKind};
use crate::db::ldap_driver::LdapAttributeModification;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

use crate::db::ldap_driver;

/// LDAP search back-end. Native simple bind uses the `ldap3` pool; GSSAPI
/// connections are routed to the Java LDAP agent (JNDI + JAAS) and so
/// dispatch via the generic agent pool.
pub async fn ldap_search_core(
    state: &AppState,
    connection_id: &str,
    base_dn: &str,
    scope: &str,
    filter: &str,
    attributes: Option<&[String]>,
    size_limit: Option<i32>,
) -> Result<Value, String> {
    dispatch_ldap_search(state, connection_id, base_dn, scope, filter, attributes, size_limit).await
}

/// Read the children of a base DN (`scope = one`, `filter = (objectClass=*)`)
/// using the same contract used by the sidebar tree builder.
pub async fn ldap_list_children_core(
    state: &AppState,
    connection_id: &str,
    base_dn: &str,
    size_limit: Option<i32>,
) -> Result<Value, String> {
    dispatch_ldap_search(state, connection_id, base_dn, "one", "(objectClass=*)", None, size_limit).await
}

/// Resolve the connection pool and run the search against whichever backend
/// the pool holds (native `ldap3` client or the Java agent), returning the
/// same JSON shape from both.
async fn dispatch_ldap_search(
    state: &AppState,
    connection_id: &str,
    base_dn: &str,
    scope: &str,
    filter: &str,
    attributes: Option<&[String]>,
    size_limit: Option<i32>,
) -> Result<Value, String> {
    match resolve_ldap_backend(state, connection_id).await? {
        LdapBackend::Native(client) => {
            let result = ldap_driver::search(
                &client,
                base_dn,
                scope,
                filter,
                attributes,
                size_limit,
                Some(Duration::from_secs(60)),
            )
            .await?;
            Ok(ldap_driver::output_to_json(result))
        }
        LdapBackend::Agent(client) => {
            let mut agent = client.lock().await;
            // An empty base DN targets the Root DSE, which is only reachable
            // at base scope (mirrors the native driver's coercion).
            let scope = if base_dn.trim().is_empty() { "base" } else { scope };
            let mut params = serde_json::json!({
                "base_dn": base_dn,
                "scope": scope,
                "filter": filter,
            });
            if let Some(attrs) = attributes {
                params["attributes"] = serde_json::json!(attrs);
            }
            if let Some(limit) = size_limit {
                params["size_limit"] = serde_json::json!(limit);
            }
            let result: Value = agent.call_with_timeout("ldap_search", params, Some(Duration::from_secs(60))).await?;
            Ok(result)
        }
    }
}

/// Add an entry (`dn` + attribute map) on either backend, applying the shared
/// read-only / production write guards first.
pub async fn ldap_add_core(
    state: &AppState,
    connection_id: &str,
    dn: &str,
    attributes: &serde_json::Map<String, Value>,
) -> Result<Value, String> {
    guard_ldap_writes(state, connection_id, "add", dn).await?;
    match resolve_ldap_backend(state, connection_id).await? {
        LdapBackend::Native(client) => ldap_driver::add(&client, dn, attributes, None).await,
        LdapBackend::Agent(client) => {
            let mut agent = client.lock().await;
            let params = serde_json::json!({ "dn": dn, "attributes": attributes });
            agent.call_with_timeout("ldap_add", params, Some(Duration::from_secs(60))).await
        }
    }
}

/// Apply attribute modifications (`modifications: [{op, attribute, values}]`)
/// to an entry on either backend.
pub async fn ldap_modify_core(
    state: &AppState,
    connection_id: &str,
    dn: &str,
    modifications: &[LdapAttributeModification],
) -> Result<Value, String> {
    guard_ldap_writes(state, connection_id, "modify", dn).await?;
    match resolve_ldap_backend(state, connection_id).await? {
        LdapBackend::Native(client) => ldap_driver::modify(&client, dn, modifications, None).await,
        LdapBackend::Agent(client) => {
            let mut agent = client.lock().await;
            let params = serde_json::json!({ "dn": dn, "modifications": modifications });
            agent.call_with_timeout("ldap_modify", params, Some(Duration::from_secs(60))).await
        }
    }
}

/// Delete an entry on either backend.
pub async fn ldap_delete_core(state: &AppState, connection_id: &str, dn: &str) -> Result<Value, String> {
    guard_ldap_writes(state, connection_id, "delete", dn).await?;
    match resolve_ldap_backend(state, connection_id).await? {
        LdapBackend::Native(client) => ldap_driver::delete(&client, dn, None).await,
        LdapBackend::Agent(client) => {
            let mut agent = client.lock().await;
            let params = serde_json::json!({ "dn": dn });
            agent.call_with_timeout("ldap_delete", params, Some(Duration::from_secs(60))).await
        }
    }
}

/// Verify a password for `dn` by performing a one-off bind with those
/// credentials (the LDAP way to check a password; nothing is persisted).
pub async fn ldap_verify_password_core(
    state: &AppState,
    connection_id: &str,
    dn: &str,
    password: &str,
) -> Result<Value, String> {
    let config = {
        let configs = state.configs.read().await;
        configs.get(connection_id).cloned().ok_or_else(|| "Unknown connection".to_string())?
    };
    if config.db_type != crate::models::connection::DatabaseType::Ldap {
        return Err("Not an LDAP connection".to_string());
    }
    match resolve_ldap_backend(state, connection_id).await? {
        LdapBackend::Native(_) => {
            // A fresh short connection: simple bind with the entry's own DN.
            let mut bind_config = config.clone();
            bind_config.username = dn.to_string();
            bind_config.password = password.to_string();
            bind_config.read_only = false;
            bind_config.is_production = false;
            let connect_timeout = Duration::from_secs(10);
            let client =
                crate::db::ldap_driver::connect(&bind_config, &config.host, config.port, connect_timeout).await;
            match client {
                Ok(client) => {
                    crate::db::ldap_driver::close(client).await;
                    Ok(serde_json::json!({ "verified": true, "dn": dn }))
                }
                Err(err) => {
                    if err.to_lowercase().contains("bind rejected") || err.to_lowercase().contains("invalid") {
                        Ok(serde_json::json!({ "verified": false, "dn": dn }))
                    } else {
                        Err(err)
                    }
                }
            }
        }
        LdapBackend::Agent(client) => {
            let mut agent = client.lock().await;
            let params = serde_json::json!({ "dn": dn, "password": password });
            agent.call_with_timeout("ldap_verify_password", params, Some(Duration::from_secs(30))).await
        }
    }
}

/// Rename (and optionally move) an entry on either backend.
pub async fn ldap_rename_core(
    state: &AppState,
    connection_id: &str,
    dn: &str,
    new_rdn: &str,
    delete_old_rdn: bool,
    new_parent_dn: Option<&str>,
) -> Result<Value, String> {
    guard_ldap_writes(state, connection_id, "rename", dn).await?;
    match resolve_ldap_backend(state, connection_id).await? {
        LdapBackend::Native(client) => {
            ldap_driver::rename(&client, dn, new_rdn, delete_old_rdn, new_parent_dn, None).await
        }
        LdapBackend::Agent(client) => {
            let mut agent = client.lock().await;
            let mut params = serde_json::json!({
                "dn": dn,
                "new_rdn": new_rdn,
                "delete_old_rdn": delete_old_rdn,
            });
            if let Some(parent) = new_parent_dn {
                params["new_parent_dn"] = serde_json::json!(parent);
            }
            agent.call_with_timeout("ldap_rename", params, Some(Duration::from_secs(60))).await
        }
    }
}

/// The backend holding an active LDAP connection.
enum LdapBackend {
    Native(Arc<ldap_driver::LdapClient>),
    Agent(Arc<crate::db::agent_driver::PooledAgentClient>),
}

/// Resolve the pooled backend for an LDAP connection, mirroring the pool
/// lookup in `dispatch_ldap_search`.
async fn resolve_ldap_backend(state: &AppState, connection_id: &str) -> Result<LdapBackend, String> {
    state.get_or_create_pool(connection_id, None).await?;
    match state.pool_handle(connection_id).await {
        Some(PoolKind::Ldap(client)) => Ok(LdapBackend::Native(client.clone())),
        Some(PoolKind::Agent(client)) => Ok(LdapBackend::Agent(client.clone())),
        _ => Err("Not an LDAP connection".to_string()),
    }
}

/// Shared write gate for every LDAP write path: refuse when the connection is
/// flagged read-only or marked as production. Checked here (not only in the
/// UI) so Tauri, web and any future caller share one enforcement point.
async fn guard_ldap_writes(state: &AppState, connection_id: &str, operation: &str, dn: &str) -> Result<(), String> {
    let config = {
        let configs = state.configs.read().await;
        match configs.get(connection_id) {
            Some(config) => config.clone(),
            None => return Err("Unknown connection".to_string()),
        }
    };
    let name = if config.name.is_empty() { connection_id } else { config.name.as_str() };
    if config.read_only {
        return Err(format!("LDAP {operation} blocked: connection '{name}' is read-only"));
    }
    if config.is_production {
        return Err(format!(
            "LDAP {operation} blocked: connection '{name}' is marked as production \
             (target dn: {dn}); writes to production directories are disabled"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ldap_driver::{LdapEntryOutput, LdapSearchOutput};
    use serde_json::{Map, Value};

    #[test]
    fn output_to_json_matches_java_agent_shape() {
        // The web layer expects the same JSON the Java agent used to emit:
        // { entries: [{ dn, attributes: {...} }], count, truncated }
        let output = LdapSearchOutput {
            entries: vec![LdapEntryOutput {
                dn: "CN=Alice,DC=corp,DC=com".into(),
                attributes: {
                    let mut map = Map::new();
                    map.insert("cn".into(), Value::String("Alice".into()));
                    map.insert("memberOf".into(), Value::Array(vec![Value::String("admins".into())]));
                    map
                },
            }],
            count: 1,
            truncated: false,
        };
        let value = ldap_driver::output_to_json(output);
        assert_eq!(value["count"], 1);
        assert_eq!(value["truncated"], false);
        assert_eq!(value["entries"][0]["dn"], "CN=Alice,DC=corp,DC=com");
        assert_eq!(value["entries"][0]["attributes"]["cn"], "Alice");
        assert_eq!(value["entries"][0]["attributes"]["memberOf"][0], "admins");
    }

    #[test]
    fn empty_search_returns_zero_count() {
        let value = ldap_driver::output_to_json(LdapSearchOutput { entries: Vec::new(), count: 0, truncated: false });
        assert_eq!(value["count"], 0);
        assert!(value["entries"].as_array().unwrap().is_empty());
    }
}
