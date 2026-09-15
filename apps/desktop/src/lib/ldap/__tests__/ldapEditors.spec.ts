import { describe, expect, it } from "vitest";
import { dateTimeLocalToGeneralizedTime, generateSshaPassword, generalizedTimeToDateTimeLocal, getLdapEditor, isPasswordAttribute, sha1Hex, verifySshaPassword } from "../ldapEditors";
import type { LdapSchemaConfig } from "@/lib/backend/http";

/** Config exposing GuidEditor via the same attributesEditor map the backend serves. */
const guidConfig = { objectClasses: [], attributesEditor: { objectGUID: "GuidEditor", "*": "StringEditor" } } as unknown as LdapSchemaConfig;

describe("GuidEditor", () => {
  const editor = getLdapEditor("objectGUID", guidConfig);

  // Independent known-good vectors, hand-computed from the AD mixed-endian
  // GUID layout: Data1/Data2/Data3 are little-endian, Data4 big-endian.
  // GUID 00112233-4455-6677-8899-aabbccddeeff
  //   → bytes 33 22 11 00 55 44 77 66 88 99 aa bb cc dd ee ff
  //   → base64 MyIRAFVEd2aImaq7zN3u/w==
  // GUID 4e4b2f18-3f5b-4a1d-9c8f-1a2b3c4d5e6f
  //   → bytes 18 2f 4b 4e 5b 3f 1d 4a 9c 8f 1a 2b 3c 4d 5e 6f
  //   → base64 GC9LTls/HUqcjxorPE1ebw==
  const VECTORS: Array<[string, string]> = [
    ["00112233-4455-6677-8899-aabbccddeeff", "MyIRAFVEd2aImaq7zN3u/w=="],
    ["4e4b2f18-3f5b-4a1d-9c8f-1a2b3c4d5e6f", "GC9LTls/HUqcjxorPE1ebw=="],
  ];
  const VISUAL = VECTORS[0][0];
  const RAW = VECTORS[0][1];

  it("resolves GuidEditor for objectGUID via attributesEditor", () => {
    expect(editor.deserialize(RAW)).toBe(VISUAL);
  });

  it("deserialize converts AD base64 GUID to the visual mixed-endian form", () => {
    for (const [visual, raw] of VECTORS) expect(editor.deserialize(raw)).toBe(visual);
  });

  it("deserialize leaves an already-formatted GUID untouched (any case)", () => {
    expect(editor.deserialize(VISUAL)).toBe(VISUAL);
    expect(editor.deserialize(VISUAL.toUpperCase())).toBe(VISUAL.toUpperCase());
  });

  it("serialize converts the visual GUID back to AD base64", () => {
    for (const [visual, raw] of VECTORS) expect(editor.serialize(visual)).toBe(raw);
  });

  it("serialize is case-insensitive on the visual form", () => {
    for (const [visual, raw] of VECTORS) expect(editor.serialize(visual.toUpperCase())).toBe(raw);
  });

  it("round trips raw → visual → raw", () => {
    expect(editor.serialize(editor.deserialize(RAW))).toBe(RAW);
  });

  it("round trips visual → raw → visual", () => {
    expect(editor.deserialize(editor.serialize(VISUAL))).toBe(VISUAL);
  });

  it("round trips the all-zeros and all-fs GUIDs", () => {
    for (const guid of ["00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff"]) {
      expect(editor.deserialize(editor.serialize(guid))).toBe(guid);
    }
  });

  it("deserialize falls back to the raw value for malformed input", () => {
    expect(editor.deserialize("not-base64!!")).toBe("not-base64!!");
  });

  it("serialize of a malformed visual GUID yields an empty value (not garbage)", () => {
    expect(editor.serialize("not-a-guid")).toBe("");
  });

  it("attributes without an editor mapping resolve to the identity StringEditor", () => {
    const stringEditor = getLdapEditor("cn", guidConfig);
    expect(stringEditor.deserialize("Alice")).toBe("Alice");
    expect(stringEditor.serialize("Alice")).toBe("Alice");
  });
});

describe("generalizedTime conversions", () => {
  it("parses UTC generalized time with all components", () => {
    const local = generalizedTimeToDateTimeLocal("199412161032Z");
    expect(local).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/);
    // Round trip: serialized form may add explicit ":00" seconds — same instant.
    const roundTripped = generalizedTimeToDateTimeLocal(dateTimeLocalToGeneralizedTime(local));
    expect(roundTripped).toBe(local);
  });

  it("treats omitted seconds as zero", () => {
    expect(generalizedTimeToDateTimeLocal("199412161032Z")).toBe(generalizedTimeToDateTimeLocal("19941216103200Z"));
  });

  it("round trips a local datetime with seconds", () => {
    const generalized = dateTimeLocalToGeneralizedTime("2026-09-06T08:30:15");
    expect(generalized).toMatch(/^\d{14}Z$/);
    expect(generalizedTimeToDateTimeLocal(generalized)).toBe("2026-09-06T08:30:15");
  });

  it("returns the input unchanged for malformed values", () => {
    expect(generalizedTimeToDateTimeLocal("not-a-time")).toBe("not-a-time");
    expect(dateTimeLocalToGeneralizedTime("nope")).toBe("nope");
  });

  it("handles timezone offsets", () => {
    // 1994-12-16 10:32 +0500 === 05:32 UTC.
    const withOffset = generalizedTimeToDateTimeLocal("199412161032+0500");
    const utc = generalizedTimeToDateTimeLocal("199412160532Z");
    expect(withOffset).toBe(utc);
  });
});

describe("isPasswordAttribute", () => {
  it("detects password attributes case-insensitively", () => {
    expect(isPasswordAttribute("userPassword")).toBe(true);
    expect(isPasswordAttribute("unicodePwd")).toBe(true);
    expect(isPasswordAttribute("cn")).toBe(false);
  });
});

describe("SidEditor", () => {
  const editor = getLdapEditor("objectSid", guidConfig);

  // Hand-computed from the SID wire format: byte0 revision, byte1 count,
  // 6-byte BIG-endian authority, count × 32-bit LE subauthorities.
  const VECTORS: Array<[string, string]> = [
    // Everyone (well-known): revision 1, count 1, authority 1, sub [0]
    ["S-1-1-0", "AQEAAAAAAAEAAAAA"],
    // BUILTIN\Administrators: revision 1, count 2, authority 5, subs [32, 544]
    ["S-1-5-32-544", "AQIAAAAAAAUgAAAAIAIAAA=="],
  ];

  it("deserialize converts AD base64 SID to the readable form", () => {
    for (const [sid, raw] of VECTORS) expect(editor.deserialize(raw)).toBe(sid);
  });

  it("deserialize leaves an already-readable SID untouched", () => {
    expect(editor.deserialize("S-1-5-21-1-2-3")).toBe("S-1-5-21-1-2-3");
  });

  it("serialize converts the readable SID back to base64", () => {
    for (const [sid, raw] of VECTORS) expect(editor.serialize(sid)).toBe(raw);
  });

  it("round trips raw → SID → raw and SID → raw → SID", () => {
    for (const [sid, raw] of VECTORS) {
      expect(editor.serialize(editor.deserialize(raw))).toBe(raw);
      expect(editor.deserialize(editor.serialize(sid))).toBe(sid);
    }
  });

  it("handles subauthority values above 2^31 without sign issues", () => {
    // revision 1, count 1, authority 5, subauthority 0x80000000 stored LE
    const bytes = new Uint8Array([1, 1, 0, 0, 0, 0, 0, 5, 0, 0, 0, 128]);
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    const raw = btoa(bin);
    expect(editor.deserialize(raw)).toBe("S-1-5-2147483648");
  });

  it("deserialize falls back to the raw value for malformed input", () => {
    expect(editor.deserialize("not-base64!!")).toBe("not-base64!!");
  });
});

describe("FileTimeEditor", () => {
  const editor = getLdapEditor("accountExpires", guidConfig);

  it("deserialize converts FILETIME (100ns since 1601) to a UTC datetime-local string", () => {
    // 1788652800 unix seconds = 2026-09-06T00:00:00Z
    expect(editor.deserialize("134331264000000000")).toBe("2026-09-06T00:00:00");
  });

  it("maps the Unix epoch", () => {
    expect(editor.deserialize("116444736000000000")).toBe("1970-01-01T00:00:00");
  });

  it("serialize converts a datetime-local string back to FILETIME", () => {
    expect(editor.serialize("2026-09-06T00:00:00")).toBe("134331264000000000");
    expect(editor.serialize("1970-01-01T00:00:00")).toBe("116444736000000000");
  });

  it("round trips in both directions", () => {
    expect(editor.deserialize(editor.serialize("2026-09-06T08:30:15"))).toBe("2026-09-06T08:30:15");
    expect(editor.serialize(editor.deserialize("133917888000000000"))).toBe("133917888000000000");
  });

  it("passes the never/sentinel values through unchanged", () => {
    expect(editor.deserialize("0")).toBe("0");
    expect(editor.deserialize("9223372036854775807")).toBe("9223372036854775807");
  });

  it("serialize passes hand-typed raw integers through unchanged", () => {
    expect(editor.serialize("9223372036854775807")).toBe("9223372036854775807");
  });

  it("returns malformed values unchanged", () => {
    expect(editor.deserialize("not-a-number")).toBe("not-a-number");
    expect(editor.serialize("nope")).toBe("nope");
  });
});

describe("FlagEditor (userAccountControl)", () => {
  const editor = getLdapEditor("userAccountControl", guidConfig);

  it("deserialize decodes a value into ascending flag names", () => {
    // 546 = ACCOUNTDISABLE(2) + PASSWD_NOTREQD(32) + NORMAL_ACCOUNT(512)
    expect(editor.deserialize("546")).toBe("ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT");
    // 66048 = NORMAL_ACCOUNT + DONT_EXPIRE_PASSWORD
    expect(editor.deserialize("66048")).toBe("NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD");
  });

  it("deserialize surfaces unknown bits as a hex token", () => {
    const value = 0x10000000;
    expect(editor.deserialize(String(value))).toBe("0x10000000");
  });

  it("serialize recomputes the numeric value from flag names", () => {
    expect(editor.serialize("ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT")).toBe("546");
    expect(editor.serialize("normal_account")).toBe("512");
  });

  it("serialize ORs hex tokens and numbers", () => {
    expect(editor.serialize("0x10000000")).toBe("268435456");
    expect(editor.serialize("512, 65536")).toBe("66048");
  });

  it("round trips in both directions, preserving unknown bits", () => {
    for (const value of ["512", "546", "66048", "66050", String(0x1000000 | 0x202)]) {
      expect(editor.serialize(editor.deserialize(value))).toBe(value);
    }
  });

  it("serializes an empty flag list to zero", () => {
    expect(editor.serialize("")).toBe("0");
  });
});

describe("HexEditor", () => {
  const editor = getLdapEditor("userCertificate", guidConfig);

  it("deserialize converts base64 to hex", () => {
    expect(editor.deserialize("SGVsbG8=")).toBe("48656c6c6f");
  });

  it("serialize converts hex back to base64, tolerating separators", () => {
    expect(editor.serialize("48656c6c6f")).toBe("SGVsbG8=");
    expect(editor.serialize("48:65:6C:6C:6F")).toBe("SGVsbG8=");
    expect(editor.serialize("48 65 6c 6c 6f")).toBe("SGVsbG8=");
  });

  it("round trips in both directions", () => {
    expect(editor.deserialize(editor.serialize("deadbeef00ff"))).toBe("deadbeef00ff");
    expect(editor.serialize(editor.deserialize("SGVsbG8="))).toBe("SGVsbG8=");
  });

  it("returns malformed values unchanged", () => {
    expect(editor.deserialize("!!!not-base64")).toBe("!!!not-base64");
    expect(editor.serialize("xyz")).toBe("xyz");
    expect(editor.serialize("abc")).toBe("abc"); // odd-length hex
  });
});

describe("sha1Hex", () => {
  it("matches the official SHA-1 test vectors", () => {
    expect(sha1Hex("abc")).toBe("a9993e364706816aba3e25717850c26c9cd0d89d");
    expect(sha1Hex("")).toBe("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect(sha1Hex("The quick brown fox jumps over the lazy dog")).toBe("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
  });
});

describe("SSHA password helpers", () => {
  it("generates a {SSHA} hash that verifies against the plaintext", () => {
    const hash = generateSshaPassword("secret", "salt1");
    expect(hash).toMatch(/^\{SSHA\}[A-Za-z0-9+/=]+$/);
    expect(verifySshaPassword(hash, "secret")).toBe(true);
    expect(verifySshaPassword(hash, "wrong")).toBe(false);
  });

  it("is deterministic for a fixed salt", () => {
    expect(generateSshaPassword("secret", "salt1")).toBe(generateSshaPassword("secret", "salt1"));
    expect(generateSshaPassword("secret", "salt1")).not.toBe(generateSshaPassword("secret", "salt2"));
  });

  it("supports a random salt when none is given", () => {
    const hash = generateSshaPassword("secret");
    expect(hash).toMatch(/^\{SSHA\}[A-Za-z0-9+/=]+$/);
    expect(verifySshaPassword(hash, "secret")).toBe(true);
  });

  it("rejects non-SSHA or malformed hashes", () => {
    expect(verifySshaPassword("{MD5}dGVzdA==", "secret")).toBe(false);
    expect(verifySshaPassword("{SSHA}tooshort", "secret")).toBe(false);
    expect(verifySshaPassword("plaintext", "secret")).toBe(false);
  });
});
