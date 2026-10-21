import { getLdapConfig, getLdapConfigForConnection } from "@/lib/backend/api";
import type { LdapAttributeType, LdapObjectClass, LdapSchemaConfig } from "@/lib/backend/http";

// Cache is keyed per connection (the schema comes from each server's own
// subschema entry); the empty key serves the bundled static schema.
const cache = new Map<string, LdapSchemaConfig>();

export async function getOrFetchLdapConfig(connectionId?: string): Promise<LdapSchemaConfig> {
  const key = connectionId ?? "";
  const cached = cache.get(key);
  if (cached) return cached;
  let config: LdapSchemaConfig;
  if (connectionId) {
    try {
      config = await getLdapConfigForConnection(connectionId);
    } catch {
      // Server schema unavailable (offline, unsupported server) — static fallback.
      config = await getLdapConfig();
    }
  } else {
    config = await getLdapConfig();
  }
  cache.set(key, config);
  return config;
}

export function getLdapAttributeType(config: LdapSchemaConfig, attributeName: string): LdapAttributeType | undefined {
  const key = attributeName.toLowerCase();
  return config.attributeTypes?.find((attr) => attr.name.toLowerCase() === key || attr.aliases.some((alias) => alias.toLowerCase() === key));
}

/**
 * Attributes whose values hold entry DNs even when the server schema does not
 * declare them (AD's memberOf, operational attributes, …). Memberships,
 * references, and the DN-bearing operational/Root DSE attributes.
 */
const DN_ATTRIBUTE_NAME_HINTS = new Set(["member", "memberof", "uniquemember", "owner", "manager", "managedby", "seealso", "secretary", "memberurl", "distinguishedname", "aliasedobjectname", "entrydn", "creatorsname", "modifiersname", "subschemasubentry", "namingcontexts", "dynamicsubtrees"]);

/** Whether values of this attribute are entry DNs (schema syntax first, known names as fallback). */
export function isLdapDnAttribute(attributeName: string, schema?: LdapSchemaConfig | null): boolean {
  if (schema) {
    const attr = getLdapAttributeType(schema, attributeName);
    if (attr) return attr.syntax === "dn";
  }
  return DN_ATTRIBUTE_NAME_HINTS.has(attributeName.toLowerCase());
}

/** Loose shape check for a DN value (at least one `attr=value` RDN). */
export function looksLikeLdapDn(value: string): boolean {
  return /[^=]+=[^=]/.test(value);
}

/** Resolve an attribute name to its schema name (alias-aware), lowercased for comparisons. */
export function resolveAttributeName(config: LdapSchemaConfig, attributeName: string): string | undefined {
  const attr = getLdapAttributeType(config, attributeName);
  if (attr) return attr.name.toLowerCase();
  const lower = attributeName.toLowerCase();
  return config.attributeTypes?.some((attr) => attr.name.toLowerCase() === lower) ? lower : undefined;
}

export function getStructuralObjectClasses(config: LdapSchemaConfig): LdapObjectClass[] {
  return config.objectClasses.filter((oc) => oc.type === "STRUCTURAL");
}

/** AUXILIARY classes are the only ones an existing entry may gain or drop. */
export function getAuxiliaryObjectClasses(config: LdapSchemaConfig): LdapObjectClass[] {
  return config.objectClasses.filter((oc) => oc.type === "AUXILIARY");
}

export function getObjectClassByName(config: LdapSchemaConfig, name: string): LdapObjectClass | undefined {
  return config.objectClasses.find((c) => c.name.toLowerCase() === name.toLowerCase());
}

export function getObjectClassIcon(config: LdapSchemaConfig, objectClass: string | string[]): string | undefined {
  const names = Array.isArray(objectClass) ? objectClass : [objectClass];
  for (const name of names) {
    const oc = getObjectClassByName(config, name);
    if (oc?.icon) return oc.icon;
  }
  return undefined;
}

/** Collect all `must` attributes from the full inheritance chain. */
export function getRequiredAttributes(config: LdapSchemaConfig, objectClass: string | string[]): string[] {
  const names = Array.isArray(objectClass) ? objectClass : [objectClass];
  const seen = new Set<string>();
  const result: string[] = [];

  for (const name of names) {
    collectMustRecursive(config, name, seen, result);
  }
  return result;
}

function collectMustRecursive(config: LdapSchemaConfig, className: string, seen: Set<string>, result: string[]): void {
  const oc = getObjectClassByName(config, className);
  if (!oc) return;
  for (const attr of oc.must) {
    const lower = attr.toLowerCase();
    if (!seen.has(lower)) {
      seen.add(lower);
      result.push(attr);
    }
  }
  for (const sup of oc.superior) {
    collectMustRecursive(config, sup, seen, result);
  }
}

/** Collect all `may` attributes from the full inheritance chain. */
export function getOptionalAttributes(config: LdapSchemaConfig, objectClass: string | string[]): string[] {
  const names = Array.isArray(objectClass) ? objectClass : [objectClass];
  const seen = new Set<string>();
  const result: string[] = [];

  for (const name of names) {
    collectMayRecursive(config, name, seen, result);
  }
  return result;
}

function collectMayRecursive(config: LdapSchemaConfig, className: string, seen: Set<string>, result: string[]): void {
  const oc = getObjectClassByName(config, className);
  if (!oc) return;
  for (const attr of oc.may) {
    const lower = attr.toLowerCase();
    if (!seen.has(lower)) {
      seen.add(lower);
      result.push(attr);
    }
  }
  for (const sup of oc.superior) {
    collectMayRecursive(config, sup, seen, result);
  }
}
