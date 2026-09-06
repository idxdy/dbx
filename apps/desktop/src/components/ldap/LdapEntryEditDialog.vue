<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Lock, Plus, X } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/composables/useToast";
import * as api from "@/lib/backend/api";
import { getOrFetchLdapConfig, getOptionalAttributes, getRequiredAttributes } from "@/lib/ldap/ldapSchema";
import { getLdapEditor } from "@/lib/ldap/ldapEditors";
import type { LdapSchemaConfig } from "@/lib/backend/http";

interface LdapModification {
  op: "add" | "replace" | "delete";
  attribute: string;
  values: string[];
}

const { t } = useI18n();
const { toast } = useToast();

const open = defineModel<boolean>("open", { default: false });

const props = defineProps<{
  connectionId: string;
  entry: { dn: string; attributes: Record<string, string | string[]> } | null;
}>();

const emit = defineEmits<{
  saved: [newDn: string];
}>();

interface AttributeRow {
  name: string;
  values: string[];
  /** Original serialized values for diffing. */
  originalSerialized: string[];
}

const rows = ref<AttributeRow[]>([]);
const saving = ref(false);
const ldapConfig = ref<LdapSchemaConfig | null>(null);

watch(open, async (value) => {
  if (value) {
    saving.value = false;
    try {
      ldapConfig.value = await getOrFetchLdapConfig(props.connectionId);
    } catch {
      ldapConfig.value = null;
    }
    rows.value = Object.entries(props.entry?.attributes ?? {}).map(([name, attrValue]) => {
      const rawValues = Array.isArray(attrValue) ? [...attrValue] : [String(attrValue)];
      const editor = ldapConfig.value ? getLdapEditor(name, ldapConfig.value) : undefined;
      const displayValues = editor ? rawValues.map((v) => editor.deserialize(v)) : rawValues;
      return {
        name,
        values: displayValues,
        originalSerialized: rawValues,
      };
    });
  }
});

function addValue(rowIndex: number) {
  rows.value[rowIndex]?.values.push("");
}

function removeValue(rowIndex: number, valueIndex: number) {
  rows.value[rowIndex]?.values.splice(valueIndex, 1);
}

function removeRow(rowIndex: number) {
  rows.value.splice(rowIndex, 1);
}

function addRow() {
  rows.value.push({ name: "", values: [""], originalSerialized: [] });
}

const currentNames = computed(() => new Set(rows.value.map((r) => r.name.trim()).filter(Boolean)));

/**
 * The structural objectClass cannot be changed after creation — the server
 * rejects structural-class modifications, so the row is rendered read-only
 * and never produces a modification.
 */
function isLockedAttribute(name: string): boolean {
  return name.trim().toLowerCase() === "objectclass";
}

const entryObjectClasses = computed<string[]>(() => {
  const raw = props.entry?.attributes["objectClass"];
  if (!raw) return [];
  return Array.isArray(raw) ? raw : [String(raw)];
});

/** Attributes allowed by the entry's objectClass chain (MUST + MAY), or null when the schema is unavailable. */
const allowedAttributeNames = computed<Set<string> | null>(() => {
  if (!ldapConfig.value || entryObjectClasses.value.length === 0) return null;
  const set = new Set<string>(["objectclass"]);
  for (const attr of getRequiredAttributes(ldapConfig.value, entryObjectClasses.value)) set.add(attr.toLowerCase());
  for (const attr of getOptionalAttributes(ldapConfig.value, entryObjectClasses.value)) set.add(attr.toLowerCase());
  return set;
});

/** Optional (MAY) attributes offered as suggestions for user-added rows. */
const optionalAttributeNames = computed<string[]>(() => {
  const allowed = allowedAttributeNames.value;
  if (!allowed) return [];
  const required = new Set(getRequiredAttributes(ldapConfig.value!, entryObjectClasses.value).map((attr) => attr.toLowerCase()));
  return [...allowed].filter((attr) => !required.has(attr) && attr !== "objectclass").sort();
});

function isRowInvalid(row: { name: string }): boolean {
  const name = row.name.trim();
  if (!name || !allowedAttributeNames.value) return false;
  // Attributes already on the entry were accepted by the server; only
  // validate names that would introduce a new attribute.
  if (props.entry?.attributes[name] !== undefined) return false;
  return !allowedAttributeNames.value.has(name.toLowerCase());
}

const invalidAttributeNames = computed<string[]>(() => [...new Set(rows.value.filter(isRowInvalid).map((r) => r.name.trim()))]);

/** Diff the edited rows against the original attributes into Modify operations. */
function buildModifications(): LdapModification[] {
  const modifications: LdapModification[] = [];
  const original = props.entry?.attributes ?? {};

  for (const row of rows.value) {
    const name = row.name.trim();
    if (!name || isLockedAttribute(name)) continue;
    const editor = ldapConfig.value ? getLdapEditor(name, ldapConfig.value) : undefined;
    const serializedValues = row.values.filter((v) => v.length > 0).map((v) => (editor ? editor.serialize(v) : v));
    const beforeList = row.originalSerialized;

    if (beforeList.length === 0) {
      if (serializedValues.length > 0) modifications.push({ op: "add", attribute: name, values: serializedValues });
    } else {
      const changed = serializedValues.length !== beforeList.length || serializedValues.some((v, i) => v !== beforeList[i]);
      if (changed) modifications.push({ op: "replace", attribute: name, values: serializedValues });
    }
  }

  for (const name of Object.keys(original)) {
    if (isLockedAttribute(name)) continue;
    if (!currentNames.value.has(name)) {
      modifications.push({ op: "delete", attribute: name, values: [] });
    }
  }
  return modifications;
}

/** First RDN component of a DN, e.g. `ou=jaime.su` from `ou=jaime.su,ou=users,dc=example,dc=com`. */
function splitDnRdn(dn: string): { attribute: string; value: string } | null {
  const first = dn.split(",")[0] ?? "";
  const eq = first.indexOf("=");
  if (eq <= 0) return null;
  return { attribute: first.slice(0, eq).trim(), value: first.slice(eq + 1).trim() };
}

async function save() {
  if (!props.entry) return;
  // The server rejects attributes outside the objectClass's MUST/MAY sets
  // with objectClassViolation (rc=65); surface that before submitting.
  if (invalidAttributeNames.value.length > 0) {
    toast(t("ldap.attributeNotAllowed", { attribute: invalidAttributeNames.value.join(", ") }), 5000);
    return;
  }
  let modifications = buildModifications();

  // The naming attribute's value cannot be changed or removed via Modify —
  // the server rejects it with a namingViolation (rc=64) because the entry
  // would no longer match its DN. Route RDN value changes through a rename
  // (MODDN) instead.
  let renameNewValue: string | null = null;
  const rdn = splitDnRdn(props.entry.dn);
  if (rdn) {
    const rdnLower = rdn.attribute.toLowerCase();
    const rdnRow = rows.value.find((row) => row.name.trim().toLowerCase() === rdnLower);
    const editor = rdnRow && ldapConfig.value ? getLdapEditor(rdnRow.name, ldapConfig.value) : undefined;
    const serializedValues = rdnRow ? rdnRow.values.filter((v) => v.length > 0).map((v) => (editor ? editor.serialize(v) : v)) : [];
    if (serializedValues.length === 0) {
      toast(t("ldap.rdnAttributeLocked", { attribute: rdn.attribute }), 5000);
      return;
    }
    if (!serializedValues.includes(rdn.value)) {
      renameNewValue = serializedValues[0];
      modifications = modifications.filter((m) => m.attribute.toLowerCase() !== rdnLower);
    }
  }

  if (modifications.length === 0 && !renameNewValue) {
    open.value = false;
    return;
  }
  saving.value = true;
  try {
    if (modifications.length > 0) {
      await api.ldapModify(props.connectionId, props.entry.dn, modifications);
    }
    let resultDn = props.entry.dn;
    if (renameNewValue) {
      const renamed = await api.ldapRename(props.connectionId, props.entry.dn, `${rdn!.attribute}=${renameNewValue}`, true);
      resultDn = renamed.dn;
      // After the rename removed the old RDN value, sync the remaining
      // values of the naming attribute (only needed for multi-valued RDNs).
      const rdnRow = rows.value.find((row) => row.name.trim().toLowerCase() === rdn!.attribute.toLowerCase());
      const editor = rdnRow && ldapConfig.value ? getLdapEditor(rdnRow.name, ldapConfig.value) : undefined;
      const serializedValues = rdnRow!.values.filter((v) => v.length > 0).map((v) => (editor ? editor.serialize(v) : v));
      if (serializedValues.length > 1) {
        await api.ldapModify(props.connectionId, resultDn, [{ op: "replace", attribute: rdn!.attribute, values: serializedValues }]);
      }
    }
    toast(t("ldap.writeSuccess"), 2500);
    emit("saved", resultDn);
    open.value = false;
  } catch (e: unknown) {
    toast(e instanceof Error ? e.message : String(e), 5000);
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-[640px]">
      <DialogHeader>
        <DialogTitle>{{ t("ldap.editTitle") }}</DialogTitle>
      </DialogHeader>

      <div v-if="entry" class="py-2 space-y-3">
        <div class="grid grid-cols-4 items-center gap-2">
          <Label class="text-right text-xs">DN</Label>
          <div class="col-span-3 text-xs font-mono break-all bg-muted rounded px-2 py-1">{{ entry.dn }}</div>
        </div>

        <div class="space-y-1.5 max-h-[45vh] overflow-auto pr-1">
          <div v-for="(row, rowIndex) in rows" :key="rowIndex" class="rounded border border-border/60 px-2 py-1.5 space-y-1">
            <div class="flex items-center gap-2">
              <Input
                v-model="row.name"
                class="h-6 w-40 text-xs font-mono"
                :class="{ 'text-muted-foreground': entry.attributes[row.name.trim()] !== undefined, 'border-destructive': isRowInvalid(row) }"
                list="ldap-edit-optional-attrs"
                :disabled="isLockedAttribute(row.name)"
                :title="isLockedAttribute(row.name) ? t('ldap.objectClassLocked') : isRowInvalid(row) ? t('ldap.attributeNotAllowed', { attribute: row.name.trim() }) : undefined"
              />
              <Lock v-if="isLockedAttribute(row.name)" class="size-3 shrink-0 text-muted-foreground" />
              <Button v-else variant="ghost" size="icon-sm" class="shrink-0 text-muted-foreground" :title="t('ldap.removeAttribute')" @click="removeRow(rowIndex)">
                <X class="size-3.5" />
              </Button>
            </div>
            <div v-for="(_, valueIndex) in row.values" :key="valueIndex" class="flex items-center gap-1.5">
              <Input v-model="row.values[valueIndex]" class="h-6 flex-1 min-w-0 text-xs" :disabled="isLockedAttribute(row.name)" :title="isLockedAttribute(row.name) ? t('ldap.objectClassLocked') : undefined" />
              <Button v-if="!isLockedAttribute(row.name)" variant="ghost" size="icon-xs" class="shrink-0 text-muted-foreground" :title="t('ldap.removeValue')" @click="removeValue(rowIndex, valueIndex)">
                <X class="size-3" />
              </Button>
            </div>
            <Button v-if="!isLockedAttribute(row.name)" variant="ghost" size="sm" class="h-5 px-1.5 text-xs text-muted-foreground" @click="addValue(rowIndex)"> <Plus class="size-3 mr-1" />{{ t("ldap.addValue") }} </Button>
          </div>
        </div>

        <Button variant="outline" size="sm" class="h-7 px-2 text-xs" @click="addRow"> <Plus class="size-3 mr-1" />{{ t("ldap.addAttribute") }} </Button>
        <datalist id="ldap-edit-optional-attrs">
          <option v-for="attr in optionalAttributeNames" :key="attr" :value="attr" />
        </datalist>
      </div>

      <DialogFooter>
        <Button variant="outline" :disabled="saving" @click="open = false">{{ t("ldap.cancel") }}</Button>
        <Button :disabled="saving || invalidAttributeNames.length > 0" @click="save">{{ t("ldap.save") }}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
