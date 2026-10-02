use std::sync::Arc;

use serde_json::Value;
use tauri::State;

use crate::commands::connection::AppState;
use dbx_core::db::ldap_driver::LdapAttributeModification;
use dbx_core::ldap_ops::{
    ldap_add_core, ldap_delete_core, ldap_list_children_core, ldap_modify_core, ldap_rename_core, ldap_search_core,
};

/// Clamp the caller-supplied size limit to a bounded range so a single request
/// can never pull an unbounded result set. Mirrors the web route and the hard
/// cap in the driver (`MAX_LDAP_SEARCH_SIZE`).
fn clamp_size_limit(limit: Option<i32>) -> Option<i32> {
    limit.map(|n| n.clamp(1, 100))
}

#[tauri::command]
pub async fn ldap_search(
    state: State<'_, Arc<AppState>>,
    connection_id: String,
    base_dn: String,
    scope: Option<String>,
    filter: Option<String>,
    attributes: Option<Vec<String>>,
    size_limit: Option<i32>,
) -> Result<Value, String> {
    ldap_search_core(
        &state,
        &connection_id,
        &base_dn,
        scope.as_deref().unwrap_or("sub"),
        filter.as_deref().unwrap_or("(objectClass=*)"),
        attributes.as_deref(),
        clamp_size_limit(size_limit),
    )
    .await
}

#[tauri::command]
pub async fn ldap_list_children(
    state: State<'_, Arc<AppState>>,
    connection_id: String,
    base_dn: String,
    size_limit: Option<i32>,
) -> Result<Value, String> {
    ldap_list_children_core(&state, &connection_id, &base_dn, clamp_size_limit(size_limit)).await
}

#[tauri::command]
pub async fn ldap_add(
    state: State<'_, Arc<AppState>>,
    connection_id: String,
    dn: String,
    attributes: Value,
) -> Result<Value, String> {
    let attributes = attributes.as_object().cloned().unwrap_or_default();
    ldap_add_core(&state, &connection_id, &dn, &attributes).await
}

#[tauri::command]
pub async fn ldap_modify(
    state: State<'_, Arc<AppState>>,
    connection_id: String,
    dn: String,
    modifications: Vec<LdapAttributeModification>,
) -> Result<Value, String> {
    ldap_modify_core(&state, &connection_id, &dn, &modifications).await
}

#[tauri::command]
pub async fn ldap_delete(state: State<'_, Arc<AppState>>, connection_id: String, dn: String) -> Result<Value, String> {
    ldap_delete_core(&state, &connection_id, &dn).await
}

#[tauri::command]
pub async fn ldap_rename(
    state: State<'_, Arc<AppState>>,
    connection_id: String,
    dn: String,
    new_rdn: String,
    delete_old_rdn: Option<bool>,
    new_parent_dn: Option<String>,
) -> Result<Value, String> {
    ldap_rename_core(&state, &connection_id, &dn, &new_rdn, delete_old_rdn.unwrap_or(true), new_parent_dn.as_deref())
        .await
}

/// One-off bind with the given DN/password — the LDAP way to verify a password.
#[tauri::command]
pub async fn ldap_verify_password(
    state: State<'_, Arc<AppState>>,
    connection_id: String,
    dn: String,
    password: String,
) -> Result<Value, String> {
    dbx_core::ldap_ops::ldap_verify_password_core(&state, &connection_id, &dn, &password).await
}

#[tauri::command]
pub async fn ldap_get_config() -> Result<Value, String> {
    let config: Value =
        serde_json::from_str(include_str!("../../../crates/dbx-core/assets/ldap.json")).map_err(|e| e.to_string())?;
    Ok(config)
}

/// Schema from the connection's own server (subschemaSubentry), falling back
/// to the bundled static asset when the server does not cooperate.
#[tauri::command]
pub async fn ldap_get_config_for_connection(
    state: State<'_, Arc<AppState>>,
    connection_id: String,
) -> Result<Value, String> {
    dbx_core::ldap_schema::ldap_schema_core(&state, &connection_id).await
}
