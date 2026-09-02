import type { LdapSchemaConfig } from "@/lib/backend/http";

export interface LdapAttributeEditor {
  /** Transform raw value from server to display value */
  deserialize(value: string): string;
  /** Transform display value to raw value for server */
  serialize(value: string): string;
}

const StringEditor: LdapAttributeEditor = {
  deserialize: (v) => v,
  serialize: (v) => v,
};

function isFormattedGuid(v: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

/** Convert 16-byte GUID (AD mixed-endian) to visual string */
function bytesToGuid(bytes: Uint8Array): string {
  if (bytes.length !== 16) return "";
  const h = (b: number) => b.toString(16).padStart(2, "0");
  const guid = [h(bytes[3]) + h(bytes[2]) + h(bytes[1]) + h(bytes[0]), h(bytes[5]) + h(bytes[4]), h(bytes[7]) + h(bytes[6]), h(bytes[8]) + h(bytes[9]), h(bytes[10]) + h(bytes[11]) + h(bytes[12]) + h(bytes[13]) + h(bytes[14]) + h(bytes[15])];
  return guid.join("-");
}

/** Convert visual GUID string to 16-byte array (AD mixed-endian) */
function guidToBytes(guid: string): Uint8Array {
  const hex = guid.replace(/-/g, "");
  if (hex.length !== 32) return new Uint8Array(0);
  const bytes = new Uint8Array(16);
  // Data1 (4 bytes LE)
  bytes[0] = parseInt(hex.substring(6, 8), 16);
  bytes[1] = parseInt(hex.substring(4, 6), 16);
  bytes[2] = parseInt(hex.substring(2, 4), 16);
  bytes[3] = parseInt(hex.substring(0, 2), 16);
  // Data2 (2 bytes LE)
  bytes[4] = parseInt(hex.substring(10, 12), 16);
  bytes[5] = parseInt(hex.substring(8, 10), 16);
  // Data3 (2 bytes LE)
  bytes[6] = parseInt(hex.substring(14, 16), 16);
  bytes[7] = parseInt(hex.substring(12, 14), 16);
  // Data4 (8 bytes BE)
  bytes[8] = parseInt(hex.substring(16, 18), 16);
  bytes[9] = parseInt(hex.substring(18, 20), 16);
  for (let i = 0; i < 6; i++) {
    bytes[10 + i] = parseInt(hex.substring(20 + i * 2, 22 + i * 2), 16);
  }
  return bytes;
}

const GuidEditor: LdapAttributeEditor = {
  deserialize: (raw: string) => {
    if (isFormattedGuid(raw)) return raw;
    try {
      const bytes = base64ToBytes(raw);
      return bytesToGuid(bytes);
    } catch {
      return raw;
    }
  },
  serialize: (visual: string) => {
    const bytes = guidToBytes(visual);
    return bytesToBase64(bytes);
  },
};

function resolveEditor(name: string): LdapAttributeEditor {
  switch (name) {
    case "GuidEditor":
      return GuidEditor;
    case "StringEditor":
    default:
      return StringEditor;
  }
}

const editorCache = new Map<string, LdapAttributeEditor>();

export function getLdapEditor(attributeName: string, config: LdapSchemaConfig): LdapAttributeEditor {
  const key = attributeName.toLowerCase();
  const cached = editorCache.get(key);
  if (cached) return cached;

  for (const [pattern, editorName] of Object.entries(config.attributesEditor)) {
    if (pattern === "*" || pattern.toLowerCase() === key) {
      const editor = resolveEditor(editorName);
      editorCache.set(key, editor);
      return editor;
    }
  }
  editorCache.set(key, StringEditor);
  return StringEditor;
}
