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

// ---------------------------------------------------------------------------
// SidEditor — AD objectSid: base64 binary ⇄ "S-1-5-21-…" readable form.
// Layout: byte0 revision, byte1 subauthority count, 6-byte big-endian
// authority, then count × 32-bit little-endian subauthorities.
// ---------------------------------------------------------------------------

function bytesToSid(bytes: Uint8Array): string {
  if (bytes.length < 8) return "";
  const revision = bytes[0];
  const count = bytes[1];
  if (count === 0 || bytes.length < 8 + count * 4) return "";
  let authority = 0n;
  for (let i = 2; i < 8; i++) authority = (authority << 8n) | BigInt(bytes[i]);
  const parts: string[] = [`S-${revision}-${authority}`];
  for (let i = 0; i < count; i++) {
    const off = 8 + i * 4;
    const sub = (bytes[off] | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24)) >>> 0;
    parts.push(String(sub));
  }
  return parts.join("-");
}

function sidToBytes(sid: string): Uint8Array {
  const parts = sid.trim().split("-");
  if (parts.length < 3 || parts[0].toUpperCase() !== "S" || !/^\d+$/.test(parts[1]) || !/^\d+$/.test(parts[2])) {
    return new Uint8Array(0);
  }
  const subs = parts.slice(3);
  if (subs.some((s) => !/^\d+$/.test(s))) return new Uint8Array(0);
  const bytes = new Uint8Array(8 + subs.length * 4);
  bytes[0] = Number(parts[1]);
  bytes[1] = subs.length;
  let authority = BigInt(parts[2]);
  for (let i = 5; i >= 0; i--) {
    bytes[2 + i] = Number(authority & 0xffn);
    authority >>= 8n;
  }
  subs.forEach((sub, i) => {
    const value = Number(sub);
    const off = 8 + i * 4;
    bytes[off] = value & 0xff;
    bytes[off + 1] = (value >>> 8) & 0xff;
    bytes[off + 2] = (value >>> 16) & 0xff;
    bytes[off + 3] = (value >>> 24) & 0xff;
  });
  return bytes;
}

const SidEditor: LdapAttributeEditor = {
  deserialize: (raw: string) => {
    if (/^s-\d+/i.test(raw.trim())) return raw.trim();
    try {
      const sid = bytesToSid(base64ToBytes(raw));
      return sid || raw;
    } catch {
      return raw;
    }
  },
  serialize: (visual: string) => {
    if (!/^s-\d+/i.test(visual.trim())) return visual;
    const bytes = sidToBytes(visual);
    return bytes.length ? bytesToBase64(bytes) : visual;
  },
};

// ---------------------------------------------------------------------------
// FileTimeEditor — AD FILETIME attributes (accountExpires, lastLogonTimestamp,
// pwdLastSet, …): 64-bit count of 100ns intervals since 1601-01-01 UTC.
// Displayed as a `datetime-local` string interpreted in UTC so the conversion
// is timezone-independent. The "never" sentinels (0 and the Int64 max) pass
// through unchanged, as does any raw integer the user typed directly.
// ---------------------------------------------------------------------------

const FILETIME_OFFSET = 116444736000000000n;
/** Largest FILETIME still representable as a datetime (~year 60000). */
const FILETIME_MAX_DISPLAYABLE = 2650467743999999999n;

function fileTimeToDateTimeLocal(value: string): string {
  const trimmed = value.trim();
  if (!/^\d+$/.test(trimmed)) return value;
  const fileTime = BigInt(trimmed);
  if (fileTime < FILETIME_OFFSET || fileTime > FILETIME_MAX_DISPLAYABLE) return value;
  const ms = Number((fileTime - FILETIME_OFFSET) / 10000n);
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return value;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}T${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`;
}

function dateTimeLocalToFileTime(value: string): string {
  const trimmed = value.trim();
  // A raw FILETIME integer (or anything non-datetime) passes through so a
  // hand-typed 18-digit value or a "never" sentinel survives editing.
  if (/^\d+$/.test(trimmed) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(trimmed)) return trimmed || value;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(trimmed)!;
  const ms = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6] ?? "0"));
  if (Number.isNaN(ms) || ms < 0) return value;
  return (BigInt(Math.floor(ms / 1000)) * 10000000n + FILETIME_OFFSET).toString();
}

const FileTimeEditor: LdapAttributeEditor = {
  deserialize: fileTimeToDateTimeLocal,
  serialize: dateTimeLocalToFileTime,
};

// ---------------------------------------------------------------------------
// FlagEditor — AD bitmasks (userAccountControl, systemFlags): numeric value ⇄
// comma-separated flag names. Unknown set bits surface as a single `0x…` hex
// token so they survive a round trip; serialize accepts the flag names, hex
// tokens and plain numbers (all OR-ed together).
// ---------------------------------------------------------------------------

const USER_ACCOUNT_CONTROL_FLAGS: Array<[number, string]> = [
  [0x1, "SCRIPT"],
  [0x2, "ACCOUNTDISABLE"],
  [0x8, "HOMEDIR_REQUIRED"],
  [0x10, "LOCKOUT"],
  [0x20, "PASSWD_NOTREQD"],
  [0x40, "PASSWD_CANT_CHANGE"],
  [0x80, "ENCRYPTED_TEXT_PWD_ALLOWED"],
  [0x100, "TEMP_DUPLICATE_ACCOUNT"],
  [0x200, "NORMAL_ACCOUNT"],
  [0x800, "INTERDOMAIN_TRUST_ACCOUNT"],
  [0x1000, "WORKSTATION_TRUST_ACCOUNT"],
  [0x2000, "SERVER_TRUST_ACCOUNT"],
  [0x10000, "DONT_EXPIRE_PASSWORD"],
  [0x20000, "MNS_LOGON_ACCOUNT"],
  [0x40000, "SMARTCARD_REQUIRED"],
  [0x80000, "TRUSTED_FOR_DELEGATION"],
  [0x100000, "NOT_DELEGATED"],
  [0x200000, "USE_DES_KEY_ONLY"],
  [0x400000, "DONT_REQ_PREAUTH"],
  [0x800000, "PASSWORD_EXPIRED"],
  [0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"],
  [0x2000000, "PARTIAL_SECRETS_ACCOUNT"],
];

const UAC_BIT_BY_NAME = new Map(USER_ACCOUNT_CONTROL_FLAGS.map(([bit, name]) => [name.toLowerCase(), bit] as const));

function numberToFlagNames(value: number): string {
  const names: string[] = [];
  for (const [bit, name] of USER_ACCOUNT_CONTROL_FLAGS) {
    if ((value & bit) !== 0) names.push(name);
  }
  const unknown = value & ~USER_ACCOUNT_CONTROL_FLAGS.reduce((acc, [bit]) => acc | bit, 0);
  if (unknown !== 0) names.push(`0x${unknown.toString(16)}`);
  return names.join(", ");
}

const FlagEditor: LdapAttributeEditor = {
  deserialize: (raw: string) => {
    const trimmed = raw.trim();
    if (!/^\d+$/.test(trimmed)) return raw;
    return numberToFlagNames(Number(trimmed));
  },
  serialize: (visual: string) => {
    const tokens = visual
      .split(",")
      .map((token) => token.trim())
      .filter(Boolean);
    if (tokens.length === 0) return "0";
    let result = 0;
    let recognized = false;
    for (const token of tokens) {
      const named = UAC_BIT_BY_NAME.get(token.toLowerCase());
      if (named != null) {
        result |= named;
        recognized = true;
        continue;
      }
      if (/^0x[0-9a-f]+$/i.test(token) || /^\d+$/.test(token)) {
        result |= Number(token);
        recognized = true;
      }
    }
    // Nothing recognizable: leave the value untouched rather than wiping it.
    if (!recognized) return visual;
    return String(result);
  },
};

// ---------------------------------------------------------------------------
// HexEditor — binary attributes (userCertificate, …): base64 ⇄ hex string.
// Accepts colon/space separated hex for display-friendliness.
// ---------------------------------------------------------------------------

const HexEditor: LdapAttributeEditor = {
  deserialize: (raw: string) => {
    try {
      const bytes = base64ToBytes(raw.trim());
      let hex = "";
      for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
      return hex || raw;
    } catch {
      return raw;
    }
  },
  serialize: (visual: string) => {
    const hex = visual.replace(/[:\s]/g, "");
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) return visual;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytesToBase64(bytes);
  },
};

function resolveEditor(name: string): LdapAttributeEditor {
  switch (name) {
    case "GuidEditor":
      return GuidEditor;
    case "SidEditor":
      return SidEditor;
    case "FileTimeEditor":
      return FileTimeEditor;
    case "FlagEditor":
      return FlagEditor;
    case "HexEditor":
      return HexEditor;
    case "StringEditor":
    default:
      return StringEditor;
  }
}

/**
 * Name-known editors applied even when the server-served attributesEditor map
 * does not list them yet (e.g. before the bundled static schema is rebuilt).
 * An explicit entry in `attributesEditor` always wins over these defaults.
 */
const DEFAULT_ATTRIBUTE_EDITORS: Record<string, string> = {
  objectguid: "GuidEditor",
  objectsid: "SidEditor",
  accountexpires: "FileTimeEditor",
  lastlogontimestamp: "FileTimeEditor",
  lastlogon: "FileTimeEditor",
  pwdlastset: "FileTimeEditor",
  badpasswordtime: "FileTimeEditor",
  useraccountcontrol: "FlagEditor",
  usercertificate: "HexEditor",
};

const editorCache = new Map<string, LdapAttributeEditor>();

export function getLdapEditor(attributeName: string, config: LdapSchemaConfig): LdapAttributeEditor {
  const key = attributeName.toLowerCase();
  const cached = editorCache.get(key);
  if (cached) return cached;

  const entries = Object.entries(config.attributesEditor);
  for (const [pattern, editorName] of entries) {
    if (pattern !== "*" && pattern.toLowerCase() === key) {
      const editor = resolveEditor(editorName);
      editorCache.set(key, editor);
      return editor;
    }
  }
  const defaultName = DEFAULT_ATTRIBUTE_EDITORS[key];
  if (defaultName) {
    const editor = resolveEditor(defaultName);
    editorCache.set(key, editor);
    return editor;
  }
  for (const [pattern, editorName] of entries) {
    if (pattern === "*") {
      const editor = resolveEditor(editorName);
      editorCache.set(key, editor);
      return editor;
    }
  }
  editorCache.set(key, StringEditor);
  return StringEditor;
}

/** Attributes whose values are passwords (masked + verifiable via one-off bind). */
export function isPasswordAttribute(attributeName: string): boolean {
  const key = attributeName.toLowerCase();
  return key === "userpassword" || key === "unicodepwd" || key === "clearpassword";
}

const GENERALIZED_TIME_RE = /^(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?(?:[.,](\d+))?(Z|[+-]\d{4})?$/;

/** Generalized Time (`199412161032Z`) → `datetime-local` string in local time. */
export function generalizedTimeToDateTimeLocal(value: string): string {
  const match = GENERALIZED_TIME_RE.exec(value.trim());
  if (!match) return value;
  const [, year, month, day, hour = "00", minute = "00", second = "00", , timezone] = match;
  let offsetMs = 0;
  if (timezone && timezone !== "Z") {
    const sign = timezone[0] === "-" ? -1 : 1;
    offsetMs = sign * (Number(timezone.slice(1, 3)) * 60 + Number(timezone.slice(3, 5))) * 60000;
  }
  // Fractional seconds are truncated; datetime-local has second resolution.
  const date = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second)) - offsetMs);
  if (Number.isNaN(date.getTime())) return value;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/** `datetime-local` string → Generalized Time in UTC (`199412161032Z`). */
export function dateTimeLocalToGeneralizedTime(value: string): string {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(value.trim());
  if (!match) return value;
  const [, year, month, day, hour, minute, second = "00"] = match;
  const date = new Date(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second));
  if (Number.isNaN(date.getTime())) return value;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
}

// ---------------------------------------------------------------------------
// OpenLDAP {SSHA} password hashing (pure JS SHA-1 so it works synchronously
// and stays unit-testable; the browser's crypto.subtle is async-only).
// ---------------------------------------------------------------------------

function sha1(message: Uint8Array): Uint8Array {
  const bitLength = message.length * 8;
  const padded = new Uint8Array((((message.length + 8) >> 6) + 1) * 64);
  padded.set(message);
  padded[message.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(bitLength / 2 ** 32));
  view.setUint32(padded.length - 4, bitLength >>> 0);
  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);
  for (let block = 0; block < padded.length; block += 64) {
    for (let j = 0; j < 16; j++) w[j] = view.getUint32(block + j * 4);
    for (let j = 16; j < 80; j++) {
      const x = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16];
      w[j] = (x << 1) | (x >>> 31);
    }
    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    for (let j = 0; j < 80; j++) {
      let f: number;
      let k: number;
      if (j < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (j < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (j < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }
      const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[j]) | 0;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = temp;
    }
    h0 = (h0 + a) | 0;
    h1 = (h1 + b) | 0;
    h2 = (h2 + c) | 0;
    h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0;
  }
  const digest = new Uint8Array(20);
  const digestView = new DataView(digest.buffer);
  digestView.setUint32(0, h0);
  digestView.setUint32(4, h1);
  digestView.setUint32(8, h2);
  digestView.setUint32(12, h3);
  digestView.setUint32(16, h4);
  return digest;
}

/** Lowercase hex SHA-1 of the UTF-8 text (exposed mainly for tests). */
export function sha1Hex(text: string): string {
  let hex = "";
  for (const byte of sha1(new TextEncoder().encode(text))) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

/** Generate an OpenLDAP `{SSHA}` hash. Omit `salt` for a random 4-byte salt. */
export function generateSshaPassword(password: string, salt?: string): string {
  const saltBytes = salt != null ? new TextEncoder().encode(salt) : crypto.getRandomValues(new Uint8Array(4));
  const message = new Uint8Array([...new TextEncoder().encode(password), ...saltBytes]);
  const digest = sha1(message);
  return `{SSHA}${bytesToBase64(new Uint8Array([...digest, ...saltBytes]))}`;
}

/** Verify a plaintext password against an `{SSHA}` (or `{SHA}`) hash. */
export function verifySshaPassword(hash: string, password: string): boolean {
  const match = /^\{SSHA\}(.+)$/is.exec(hash.trim());
  if (!match) return false;
  let decoded: Uint8Array;
  try {
    decoded = base64ToBytes(match[1]);
  } catch {
    return false;
  }
  if (decoded.length <= 20) return false;
  const salt = decoded.slice(20);
  const expected = sha1(new Uint8Array([...new TextEncoder().encode(password), ...salt]));
  for (let i = 0; i < 20; i++) if (expected[i] !== decoded[i]) return false;
  return true;
}
