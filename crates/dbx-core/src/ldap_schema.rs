//! LDAP server schema retrieval and RFC 4512 parsing.
//!
//! The entry editor is driven by the server's own schema: the Root DSE's
//! `subschemaSubentry` points at the entry holding `objectClasses` and
//! `attributeTypes` definitions. Those are parsed here into the same shape as
//! the bundled static fallback (`assets/ldap.json`) plus typed attribute
//! descriptions, so the frontend can drive type-aware value editors.

use crate::connection::AppState;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

/// Static fallback served when the server's schema cannot be retrieved.
pub const STATIC_SCHEMA_JSON: &str = include_str!("../assets/ldap.json");

/// Fetch the schema for a connection from its own server, falling back to the
/// bundled static schema when the server (or network) does not cooperate.
/// The result also carries `"source": "server" | "static"` so the UI can tell
/// the difference.
pub async fn ldap_schema_core(state: &AppState, connection_id: &str) -> Result<Value, String> {
    match fetch_server_schema(state, connection_id).await {
        Ok(schema) => Ok(schema),
        Err(err) => {
            log::warn!("LDAP schema fetch for '{connection_id}' failed, falling back to static schema: {err}");
            Ok(static_schema())
        }
    }
}

/// The bundled schema, without any server round trip.
pub fn static_schema() -> Value {
    serde_json::from_str(STATIC_SCHEMA_JSON).expect("static LDAP schema asset is valid JSON")
}

async fn fetch_server_schema(state: &AppState, connection_id: &str) -> Result<Value, String> {
    // 1. Root DSE → subschemaSubentry DN.
    let dse = crate::ldap_ops::ldap_search_core(
        state,
        connection_id,
        "",
        "base",
        "(objectClass=*)",
        Some(&["subschemaSubentry".to_string()]),
        None,
    )
    .await?;
    let subschema_dn = dse
        .get("entries")
        .and_then(Value::as_array)
        .and_then(|entries| entries.first())
        .and_then(|entry| entry.get("attributes"))
        .and_then(|attrs| attrs.get("subschemaSubentry"))
        .and_then(subschema_value_to_string)
        .filter(|dn| !dn.trim().is_empty())
        .ok_or_else(|| "Root DSE does not expose subschemaSubentry".to_string())?;

    // 2. Subschema entry → objectClasses + attributeTypes definitions.
    let result = crate::ldap_ops::ldap_search_core(
        state,
        connection_id,
        &subschema_dn,
        "base",
        "(objectClass=subschema)",
        Some(&["objectClasses".to_string(), "attributeTypes".to_string()]),
        None,
    )
    .await?;
    let attributes = result
        .get("entries")
        .and_then(Value::as_array)
        .and_then(|entries| entries.first())
        .and_then(|entry| entry.get("attributes"))
        .and_then(Value::as_object)
        .ok_or_else(|| "subschema entry not found".to_string())?;

    let raw_object_classes = attribute_values(attributes.get("objectClasses"));
    let raw_attribute_types = attribute_values(attributes.get("attributeTypes"));
    if raw_object_classes.is_empty() {
        return Err("subschema entry has no objectClasses".to_string());
    }

    let mut object_classes = parsed_object_classes_to_json(&raw_object_classes);
    let attribute_types = parsed_attribute_types_to_json(&raw_attribute_types);
    let mut schema = static_schema();
    merge_static_metadata(&mut object_classes, &schema);
    if let Some(object) = schema.as_object_mut() {
        object.insert("objectClasses".to_string(), object_classes);
        object.insert("attributeTypes".to_string(), attribute_types);
        object.insert("source".to_string(), json!("server"));
    }
    Ok(schema)
}

/// Carry the curated static metadata (UI icon, note, supported systems) over
/// to the dynamically parsed classes that share the name.
fn merge_static_metadata(parsed: &mut Value, static_schema: &Value) {
    let Some(parsed_entries) = parsed.as_array_mut() else { return };
    let static_entries = static_schema["objectClasses"].as_array();
    for entry in parsed_entries {
        let Some(name) = entry.get("name").and_then(Value::as_str) else { continue };
        let Some(static_entry) = static_entries.and_then(|entries| {
            entries
                .iter()
                .find(|e| e.get("name").and_then(Value::as_str).map(|n| n.eq_ignore_ascii_case(name)).unwrap_or(false))
        }) else {
            continue;
        };
        let object = match entry.as_object_mut() {
            Some(object) => object,
            None => continue,
        };
        for field in ["icon", "note", "system"] {
            if let Some(value) = static_entry.get(field) {
                object.insert(field.to_string(), value.clone());
            }
        }
    }
}

fn subschema_value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Array(items) => items.first().and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

fn attribute_values(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        Some(Value::String(text)) => vec![text.clone()],
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// RFC 4512 definition parsing
// ---------------------------------------------------------------------------

/// Tokenize an RFC 4512 schema definition into parens, quoted strings and
/// bare words. Quoted strings keep their quotes so the caller can tell them
/// apart from bare keywords.
fn tokenize_schema(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = value.chars().peekable();
    while let Some(&ch) = chars.peek() {
        match ch {
            '(' | ')' => {
                tokens.push(ch.to_string());
                chars.next();
            }
            '\'' => {
                let mut quoted = String::from("'");
                chars.next();
                for c in chars.by_ref() {
                    if c == '\'' {
                        break;
                    }
                    quoted.push(c);
                }
                quoted.push('\'');
                tokens.push(quoted);
            }
            c if c.is_whitespace() => {
                chars.next();
            }
            _ => {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || c == '(' || c == ')' {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
                tokens.push(word);
            }
        }
    }
    tokens
}

fn unquote(token: &str) -> String {
    token.trim_matches('\'').to_string()
}

/// One parsed schema definition: the common subset the editor needs.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SchemaDefinition {
    pub oid: String,
    pub names: Vec<String>,
    pub description: String,
    pub superior: Vec<String>,
    pub must: Vec<String>,
    pub may: Vec<String>,
    pub kind: Option<String>, // ABSTRACT | STRUCTURAL | AUXILIARY for classes
    pub equality: String,
    pub syntax_oid: String,
    pub single_value: bool,
    pub obsolete: bool,
    pub no_user_modification: bool,
    pub operational: bool,
}

/// Parse a single RFC 4512 definition (`( OID NAME ... )`). Tolerant of AD /
/// OpenLDAP dialect differences: unknown keywords and X- extensions are
/// skipped, and malformed values never panic (fields stay empty).
pub fn parse_schema_definition(value: &str) -> Option<SchemaDefinition> {
    let tokens = tokenize_schema(value);
    let mut index = 0;
    if tokens.get(index)?.as_str() != "(" {
        return None;
    }
    index += 1;
    let oid = tokens.get(index)?.clone();
    if oid == ")" {
        return None;
    }
    let mut definition = SchemaDefinition { oid, ..Default::default() };
    index += 1;

    // A list of keywords is consumed as either a single value or a
    // parenthesized list of quoted/unquoted values.
    fn read_value_list(tokens: &[String], index: &mut usize) -> Vec<String> {
        let mut values = Vec::new();
        if tokens.get(*index).map(String::as_str) == Some("(") {
            *index += 1;
            while *index < tokens.len() && tokens[*index] != ")" {
                let value = unquote(&tokens[*index]);
                if value != "$" {
                    values.push(value);
                }
                *index += 1;
            }
            if tokens.get(*index).map(String::as_str) == Some(")") {
                *index += 1;
            }
        } else if let Some(token) = tokens.get(*index) {
            let value = unquote(token);
            if value != "$" && value != ")" {
                values.push(value);
                *index += 1;
            }
        }
        values
    }

    while index < tokens.len() && tokens[index] != ")" {
        let keyword = tokens[index].to_ascii_uppercase();
        index += 1;
        match keyword.as_str() {
            "NAME" => definition.names = read_value_list(&tokens, &mut index),
            "DESC" => {
                definition.description = read_value_list(&tokens, &mut index).first().cloned().unwrap_or_default()
            }
            "OBSOLETE" => definition.obsolete = true,
            "SUP" => definition.superior = read_value_list(&tokens, &mut index),
            "MUST" => definition.must = read_value_list(&tokens, &mut index),
            "MAY" => definition.may = read_value_list(&tokens, &mut index),
            "EQUALITY" => {
                definition.equality = read_value_list(&tokens, &mut index).first().cloned().unwrap_or_default()
            }
            "ABSTRACT" => definition.kind = Some("ABSTRACT".to_string()),
            "STRUCTURAL" => definition.kind = Some("STRUCTURAL".to_string()),
            "AUXILIARY" => definition.kind = Some("AUXILIARY".to_string()),
            "SYNTAX" => {
                // Strip the optional `{len}` hint: `1.2.3{64}` → `1.2.3`.
                let oid = read_value_list(&tokens, &mut index).first().cloned().unwrap_or_default();
                definition.syntax_oid = oid.split('{').next().unwrap_or(&oid).to_string();
            }
            "SINGLE-VALUE" => definition.single_value = true,
            "NO-USER-MODIFICATION" => definition.no_user_modification = true,
            "USAGE" => {
                let usage = read_value_list(&tokens, &mut index).first().cloned().unwrap_or_default();
                definition.operational = !usage.is_empty() && !usage.eq_ignore_ascii_case("userApplications");
            }
            // Unknown keywords (extensions, APPLIES, ORDERING, SUBSTR,
            // AD-specific X- fields, …) consume their value/list, if any, so
            // the loop can continue at the next keyword.
            _ => {
                let mut lookahead = index;
                let _ = read_value_list(&tokens, &mut lookahead);
                // Only skip ahead when a value was actually present; bare
                // flags (e.g. OBSOLETE handled above) must not swallow the
                // next keyword.
                if lookahead == index {
                    // No value: nothing to skip.
                } else {
                    index = lookahead;
                }
            }
        }
    }
    if definition.names.is_empty() {
        // NAME may be omitted for some entries; use the OID as name so the
        // definition is still addressable.
        if definition.oid.is_empty() {
            return None;
        }
        definition.names.push(definition.oid.clone());
    }
    Some(definition)
}

/// Map an RFC 4517 syntax OID to the editor's value kind. Unmapped syntaxes
/// fall back to plain text.
fn syntax_kind(syntax_oid: &str) -> &'static str {
    const P: &str = "1.3.6.1.4.1.1466.115.121.1.";
    let Some(suffix) = syntax_oid.strip_prefix(P) else {
        return "string";
    };
    match suffix {
        // Boolean
        "7" => "boolean",
        // Generalized Time
        "24" => "generalizedTime",
        // Integer
        "27" => "integer",
        // DN, Name And Optional UID
        "12" | "34" => "dn",
        // Binary-ish: Audio, Binary, Certificate, Certificate List,
        // Certificate Pair, Octet String, Bit String
        "4" | "5" | "8" | "9" | "10" | "40" | "6" => "binary",
        // JPEG
        "28" => "jpeg",
        _ => "string",
    }
}

/// Convert parsed objectClass definitions into the frontend schema shape,
/// computing `inheritanceChain` (top-first) from the SUP links.
pub fn parsed_object_classes_to_json(definitions: &[String]) -> Value {
    let parsed: Vec<SchemaDefinition> = definitions.iter().filter_map(|d| parse_schema_definition(d)).collect();
    let by_name: HashMap<String, &SchemaDefinition> =
        parsed.iter().flat_map(|d| d.names.iter().map(move |name| (name.to_ascii_lowercase(), d))).collect();

    let inheritance_chain = |definition: &SchemaDefinition| -> Vec<String> {
        let mut chain: Vec<String> = definition.names.first().cloned().into_iter().collect();
        let mut seen: Vec<String> = chain.iter().cloned().collect();
        let mut cursor = Some(definition);
        while let Some(current) = cursor {
            let superior = current.superior.first().map(|s| s.to_ascii_lowercase());
            let Some(superior) = superior else { break };
            if seen.iter().any(|name| name.to_ascii_lowercase() == superior) {
                break;
            }
            let Some(next) = by_name.get(&superior) else { break };
            seen.push(next.names[0].clone());
            chain.push(next.names[0].clone());
            cursor = Some(next);
        }
        chain.reverse();
        chain
    };

    let entries: Vec<Value> = parsed
        .iter()
        .map(|definition| {
            let mut entry = Map::new();
            entry.insert("name".to_string(), json!(definition.names[0]));
            entry.insert("aliases".to_string(), json!(definition.names[1..]));
            entry.insert("description".to_string(), json!(definition.description));
            entry.insert("superior".to_string(), json!(definition.superior));
            entry.insert("inheritanceChain".to_string(), json!(inheritance_chain(definition)));
            entry.insert("must".to_string(), json!(definition.must));
            entry.insert("may".to_string(), json!(definition.may));
            entry
                .insert("type".to_string(), json!(definition.kind.clone().unwrap_or_else(|| "STRUCTURAL".to_string())));
            entry.insert("obsolete".to_string(), json!(definition.obsolete));
            Value::Object(entry)
        })
        .collect();
    Value::Array(entries)
}

/// Convert parsed attributeType definitions into typed descriptors for the
/// value editors.
pub fn parsed_attribute_types_to_json(definitions: &[String]) -> Value {
    let entries: Vec<Value> = definitions
        .iter()
        .filter_map(|d| parse_schema_definition(d))
        .map(|definition| {
            let mut entry = Map::new();
            entry.insert("name".to_string(), json!(definition.names[0]));
            entry.insert("aliases".to_string(), json!(definition.names[1..]));
            entry.insert("description".to_string(), json!(definition.description));
            entry.insert("syntaxOid".to_string(), json!(definition.syntax_oid));
            entry.insert("syntax".to_string(), json!(syntax_kind(&definition.syntax_oid)));
            entry.insert("singleValue".to_string(), json!(definition.single_value));
            entry.insert("noUserModification".to_string(), json!(definition.no_user_modification));
            entry.insert("operational".to_string(), json!(definition.operational));
            entry.insert("equality".to_string(), json!(definition.equality));
            Value::Object(entry)
        })
        .collect();
    Value::Array(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn parses_openldap_object_class() {
        let definition = parse_schema_definition(
            "( 2.5.6.5 NAME 'organization' SUP top STRUCTURAL MUST o MAY ( userPassword $ searchGuide $ description ) )",
        )
        .expect("parses");
        assert_eq!(definition.names, vec!["organization"]);
        assert_eq!(definition.superior, vec!["top"]);
        assert_eq!(definition.kind.as_deref(), Some("STRUCTURAL"));
        assert_eq!(definition.must, vec!["o"]);
        assert_eq!(definition.may, vec!["userPassword", "searchGuide", "description"]);
    }

    #[test]
    fn parses_ad_attribute_type() {
        let definition = parse_schema_definition(
            "(1.2.840.113556.1.4.2 NAME 'objectClass' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 NO-USER-MODIFICATION X-AD-FLAGS '1')",
        )
        .expect("parses");
        assert_eq!(definition.names, vec!["objectClass"]);
        assert!(definition.no_user_modification);
        assert_eq!(definition.syntax_oid, "1.3.6.1.4.1.1466.115.121.1.38");
    }

    #[test]
    fn parses_single_value_and_usage() {
        let definition = parse_schema_definition(
            "( 2.5.18.1 NAME 'createTimestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
        )
        .expect("parses");
        assert!(definition.single_value);
        assert!(definition.no_user_modification);
        assert!(definition.operational);
        assert_eq!(definition.syntax_oid, "1.3.6.1.4.1.1466.115.121.1.24");
    }

    #[test]
    fn syntax_strips_length_hint() {
        let definition =
            parse_schema_definition("( 2.5.4.3 NAME 'cn' SUP name SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )")
                .expect("parses");
        assert_eq!(definition.syntax_oid, "1.3.6.1.4.1.1466.115.121.1.15");
    }

    #[test]
    fn unquoted_lists_are_supported() {
        // Some servers emit MUST/MAY without $ separators or quotes.
        let definition = parse_schema_definition("( 1.1 NAME 'test' MUST ( a b ) MAY c )").expect("parses");
        assert_eq!(definition.must, vec!["a", "b"]);
        assert_eq!(definition.may, vec!["c"]);
    }

    #[test]
    fn malformed_definitions_do_not_panic() {
        assert!(parse_schema_definition("garbage").is_none());
        assert!(parse_schema_definition("( )").is_none());
        assert!(parse_schema_definition("( 1.2.3 )").is_some(), "bare OID gets OID as name");
    }

    #[test]
    fn syntax_kind_mapping() {
        assert_eq!(syntax_kind("1.3.6.1.4.1.1466.115.121.1.7"), "boolean");
        assert_eq!(syntax_kind("1.3.6.1.4.1.1466.115.121.1.24"), "generalizedTime");
        assert_eq!(syntax_kind("1.3.6.1.4.1.1466.115.121.1.27"), "integer");
        assert_eq!(syntax_kind("1.3.6.1.4.1.1466.115.121.1.12"), "dn");
        assert_eq!(syntax_kind("1.3.6.1.4.1.1466.115.121.1.8"), "binary");
        assert_eq!(syntax_kind("1.3.6.1.4.1.1466.115.121.1.28"), "jpeg");
        assert_eq!(syntax_kind("1.3.6.1.4.1.1466.115.121.1.15"), "string");
        assert_eq!(syntax_kind("9.9.9"), "string");
    }

    #[test]
    fn inheritance_chain_walks_superiors() {
        let definitions = vec![
            "( 2.5.6.0 NAME 'top' ABSTRACT )".to_string(),
            "( 2.5.6.4 NAME 'organization' SUP top STRUCTURAL MUST o )".to_string(),
            "( 1.3.6.1.4.1.11.1.3.1 NAME 'inetOrgPerson' SUP ( organizationalPerson ) STRUCTURAL )".to_string(),
            "( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL )".to_string(),
            "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) )".to_string(),
        ];
        let json = parsed_object_classes_to_json(&definitions);
        let entries = json.as_array().unwrap();
        let iop = entries.iter().find(|entry| entry["name"] == "inetOrgPerson").expect("inetOrgPerson present");
        let chain = iop["inheritanceChain"].as_array().unwrap();
        let names: Vec<&str> = chain.iter().filter_map(Value::as_str).collect();
        assert_eq!(names, vec!["top", "person", "organizationalPerson", "inetOrgPerson"]);
    }

    #[test]
    fn attribute_types_json_carries_editor_hints() {
        let json = parsed_attribute_types_to_json(&[
            "( 2.5.4.35 NAME 'userPassword' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
                .to_string(),
        ]);
        let entry = json.as_array().unwrap()[0].clone();
        assert_eq!(entry["name"], "userPassword");
        assert_eq!(entry["syntax"], "binary");
        assert_eq!(entry["singleValue"], false);
        assert_eq!(entry["noUserModification"], false);
    }

    #[test]
    fn static_schema_is_valid_and_has_source_shape() {
        let schema = static_schema();
        assert!(schema["objectClasses"].as_array().unwrap().len() > 0);
        assert!(schema["attributesEditor"].is_object());
    }

    // -----------------------------------------------------------------------
    // Integration tests — gated by DBX_LDAP_INTEGRATION (see ldap_driver).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn integration_parses_live_server_subschema() {
        if std::env::var("DBX_LDAP_INTEGRATION").is_err() {
            eprintln!("skipping integration test (set DBX_LDAP_INTEGRATION=1 to enable)");
            return;
        }
        let host = std::env::var("DBX_LDAP_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port = std::env::var("DBX_LDAP_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(389);
        let username = std::env::var("DBX_LDAP_USER").unwrap_or_else(|_| "cn=admin,dc=example,dc=com".into());
        let password = std::env::var("DBX_LDAP_PASSWORD").unwrap_or_else(|_| "123456".into());
        let mut config = crate::db::ldap_driver::test_connection_config();
        config.host = host;
        config.port = port;
        config.username = username;
        config.password = password;
        let client =
            crate::db::ldap_driver::connect(&config, &config.host, config.port, std::time::Duration::from_secs(15))
                .await
                .expect("connect should succeed");

        // Root DSE → subschemaSubentry.
        let dse = crate::db::ldap_driver::search(
            &client,
            "",
            "base",
            "(objectClass=*)",
            Some(&["subschemaSubentry".to_string()]),
            Some(10),
            Some(std::time::Duration::from_secs(15)),
        )
        .await
        .expect("Root DSE search should succeed");
        assert_eq!(dse.count, 1);
        let subschema_dn = match dse.entries[0].attributes.get("subschemaSubentry") {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Array(items)) => items[0].as_str().expect("string").to_string(),
            other => panic!("unexpected subschemaSubentry: {other:?}"),
        };
        assert!(!subschema_dn.is_empty());

        // Subschema entry → definitions.
        let result = crate::db::ldap_driver::search(
            &client,
            &subschema_dn,
            "base",
            "(objectClass=subschema)",
            Some(&["objectClasses".to_string(), "attributeTypes".to_string()]),
            None,
            Some(std::time::Duration::from_secs(15)),
        )
        .await
        .expect("subschema search should succeed");
        assert_eq!(result.count, 1);
        let object_class_values = result.entries[0].attributes.get("objectClasses").expect("objectClasses present");
        let raw = match object_class_values {
            Value::Array(items) => items.iter().map(|v| v.as_str().expect("string").to_string()).collect::<Vec<_>>(),
            Value::String(text) => vec![text.clone()],
            other => panic!("unexpected objectClasses: {other:?}"),
        };
        assert!(raw.len() > 10, "expected many objectClasses, got {}", raw.len());

        let parsed = parsed_object_classes_to_json(&raw);
        let entries = parsed.as_array().unwrap();
        let names: Vec<&str> = entries.iter().filter_map(|e| e["name"].as_str()).collect();
        assert!(names.iter().any(|n| n.eq_ignore_ascii_case("top")), "top should be parsed, got: {names:?}");
        let org = entries.iter().find(|e| e["name"] == "organizationalUnit").expect("organizationalUnit parsed");
        assert_eq!(org["must"], serde_json::json!(["ou"]));
        assert_eq!(org["inheritanceChain"], serde_json::json!(["top", "organizationalUnit"]));
    }
}
