use axum::{
    extract::{Query, State},
    Json,
};
use dbx_core::db::ldap_driver::LdapAttributeModification;
use serde::Deserialize;
use std::sync::Arc;

use crate::error::AppError;
use crate::state::WebState;

#[derive(Debug, Deserialize)]
pub struct LdapSearchRequest {
    pub connection_id: String,
    pub base_dn: String,
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(default = "default_filter")]
    pub filter: String,
    #[serde(default)]
    pub attributes: Option<Vec<String>>,
    #[serde(default)]
    pub size_limit: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct LdapListChildrenRequest {
    pub connection_id: String,
    pub base_dn: String,
    #[serde(default)]
    pub size_limit: Option<i32>,
}

fn default_scope() -> String {
    "sub".to_string()
}

fn default_filter() -> String {
    "(objectClass=*)".to_string()
}

/// Clamp the caller-supplied size limit to a bounded range so a single
/// request can never pull an unbounded result set. Mirrors the hard cap in
/// the driver (`MAX_LDAP_SEARCH_SIZE`).
fn clamp_size_limit(limit: Option<i32>) -> Option<i32> {
    limit.map(|n| n.clamp(1, 1000))
}

pub async fn search(
    State(state): State<Arc<WebState>>,
    Json(request): Json<LdapSearchRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result = dbx_core::ldap_ops::ldap_search_core(
        &state.app,
        &request.connection_id,
        &request.base_dn,
        &request.scope,
        &request.filter,
        request.attributes.as_deref(),
        clamp_size_limit(request.size_limit),
    )
    .await
    .map_err(AppError::from)?;
    Ok(Json(result))
}

/// Children of a base DN (`scope = one`, `filter = (objectClass=*)`) used by
/// the sidebar tree-builder. Mirrors the existing `ldap_search` request
/// shape so the frontend can drop it in without code changes.
pub async fn list_children(
    State(state): State<Arc<WebState>>,
    Json(request): Json<LdapListChildrenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result = dbx_core::ldap_ops::ldap_list_children_core(
        &state.app,
        &request.connection_id,
        &request.base_dn,
        clamp_size_limit(request.size_limit),
    )
    .await
    .map_err(AppError::from)?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
pub struct LdapAddRequest {
    pub connection_id: String,
    pub dn: String,
    #[serde(default)]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
pub struct LdapModifyRequest {
    pub connection_id: String,
    pub dn: String,
    pub modifications: Vec<LdapAttributeModification>,
}

#[derive(Debug, Deserialize)]
pub struct LdapDeleteRequest {
    pub connection_id: String,
    pub dn: String,
}

#[derive(Debug, Deserialize)]
pub struct LdapRenameRequest {
    pub connection_id: String,
    pub dn: String,
    pub new_rdn: String,
    #[serde(default = "default_true")]
    pub delete_old_rdn: bool,
    #[serde(default)]
    pub new_parent_dn: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Add a new LDAP entry. Write access is gated in the core layer
/// (read-only / production connections are rejected there).
pub async fn add(
    State(state): State<Arc<WebState>>,
    Json(request): Json<LdapAddRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let attributes = request.attributes.unwrap_or_default();
    let result = dbx_core::ldap_ops::ldap_add_core(&state.app, &request.connection_id, &request.dn, &attributes)
        .await
        .map_err(AppError::from)?;
    Ok(Json(result))
}

/// Apply attribute modifications to an existing entry.
pub async fn modify(
    State(state): State<Arc<WebState>>,
    Json(request): Json<LdapModifyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result =
        dbx_core::ldap_ops::ldap_modify_core(&state.app, &request.connection_id, &request.dn, &request.modifications)
            .await
            .map_err(AppError::from)?;
    Ok(Json(result))
}

/// Delete an entry.
pub async fn delete(
    State(state): State<Arc<WebState>>,
    Json(request): Json<LdapDeleteRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result = dbx_core::ldap_ops::ldap_delete_core(&state.app, &request.connection_id, &request.dn)
        .await
        .map_err(AppError::from)?;
    Ok(Json(result))
}

/// Rename (and optionally move) an entry.
pub async fn rename(
    State(state): State<Arc<WebState>>,
    Json(request): Json<LdapRenameRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result = dbx_core::ldap_ops::ldap_rename_core(
        &state.app,
        &request.connection_id,
        &request.dn,
        &request.new_rdn,
        request.delete_old_rdn,
        request.new_parent_dn.as_deref(),
    )
    .await
    .map_err(AppError::from)?;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
pub struct LdapVerifyPasswordRequest {
    pub connection_id: String,
    pub dn: String,
    pub password: String,
}

/// One-off bind with the given DN/password — the LDAP way to verify a password.
pub async fn verify_password(
    State(state): State<Arc<WebState>>,
    Json(request): Json<LdapVerifyPasswordRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let result = dbx_core::ldap_ops::ldap_verify_password_core(
        &state.app,
        &request.connection_id,
        &request.dn,
        &request.password,
    )
    .await
    .map_err(AppError::from)?;
    Ok(Json(result))
}

/// Serve the LDAP schema configuration. Without a connection (or when the
/// server's schema cannot be read) the bundled static asset is served;
/// with a connection the schema comes from the server's own subschema entry.
pub async fn get_config(
    State(state): State<Arc<WebState>>,
    Query(query): Query<LdapConfigQuery>,
) -> Json<serde_json::Value> {
    let schema = match query.connection_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(connection_id) => dbx_core::ldap_schema::ldap_schema_core(&state.app, connection_id)
            .await
            .unwrap_or_else(|_| dbx_core::ldap_schema::static_schema()),
        None => dbx_core::ldap_schema::static_schema(),
    };
    Json(schema)
}

#[derive(Debug, Deserialize)]
pub struct LdapConfigQuery {
    pub connection_id: Option<String>,
}
