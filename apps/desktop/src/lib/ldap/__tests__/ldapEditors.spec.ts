import { describe, expect, it } from "vitest";
import { dateTimeLocalToGeneralizedTime, generalizedTimeToDateTimeLocal, isPasswordAttribute } from "../ldapEditors";

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
