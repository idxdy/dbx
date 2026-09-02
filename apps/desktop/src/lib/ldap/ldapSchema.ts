import { getLdapConfig } from "@/lib/backend/api";
import type { LdapObjectClass, LdapSchemaConfig } from "@/lib/backend/http";

let cachedConfig: LdapSchemaConfig | null = null;

export async function getOrFetchLdapConfig(): Promise<LdapSchemaConfig> {
  if (!cachedConfig) {
    cachedConfig = await getLdapConfig();
  }
  return cachedConfig;
}

export function getStructuralObjectClasses(config: LdapSchemaConfig): LdapObjectClass[] {
  return config.objectClasses.filter((oc) => oc.type === "STRUCTURAL");
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
