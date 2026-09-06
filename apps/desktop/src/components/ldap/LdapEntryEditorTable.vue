<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Loader2, Lock, Pencil, Plus, ShieldCheck, X } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/composables/useToast";
import * as api from "@/lib/backend/api";
import { dateTimeLocalToGeneralizedTime, generalizedTimeToDateTimeLocal, getLdapEditor, isPasswordAttribute } from "@/lib/ldap/ldapEditors";
import { getLdapAttributeType, getOptionalAttributes, getRequiredAttributes } from "@/lib/ldap/ldapSchema";
import type { LdapSchemaConfig } from "@/lib/backend/http";
import LdapObjectClassEditorDialog from "@/components/ldap/LdapObjectClassEditorDialog.vue";

const { t } = useI18n();
const { toast } = useToast();

const props = defineProps<{
  connectionId: string;
  entry: { dn: string; attributes: Record<string, string | string[]> } | null;
  readOnly?: boolean;
  schema: LdapSchemaConfig | null;
}>();

const emit = defineEmits<{
  updated: [dn: string];
  /** Structural change (e.g. objectClass set) — parent should refetch the entry. */
  entryChanged: [dn: string];
}>();

const objectClassEditorOpen = ref(false);

interface ValueCell {
  /** Local editing value (deserialized display form). */
  text: string;
  /** Display form of the committed value; used for Escape revert. */
  committedText: string;
  /** Serialized (server form) committed value; empty marks a not-yet-committed new value. */
  original: string;
  isNew: boolean;
}

interface AttributeRow {
  name: string;
  kind: "must" | "may";
  description: string;
  locked: boolean;
  pending: boolean;
  /** True for a synthesized MUST row that the entry does not have yet. */
  missing: boolean;
  cells: ValueCell[];
  /** Password attributes: inline verify-password state. */
  verifyOpen?: boolean;
  verifyText?: string;
  verifying?: boolean;
}

const rows = ref<AttributeRow[]>([]);
/** dn of the entry the current rows were built from (guards stale async commits). */
let rowsDn = "";
/** Authoritative attribute map for the entry under edit; updated on every commit. */
const currentAttributes = ref<Record<string, string | string[]>>({});
const showAddAttribute = ref(false);

function entryObjectClasses(): string[] {
  const raw = props.entry?.attributes["objectClass"];
  if (!raw) return [];
  return Array.isArray(raw) ? raw.map(String) : [String(raw)];
}

/** Editor kind for an attribute: schema syntax, with password name overrides. */
function attributeKind(name: string): string {
  if (isPasswordAttribute(name)) return "password";
  return props.schema ? (getLdapAttributeType(props.schema, name)?.syntax ?? "string") : "string";
}

/** Operational/system-maintained attributes render read-only. */
function isSystemAttribute(name: string): boolean {
  const attr = props.schema ? getLdapAttributeType(props.schema, name) : undefined;
  return Boolean(attr && (attr.noUserModification || attr.operational));
}

function serializeValue(name: string, text: string): string {
  if (!text) return "";
  if (attributeKind(name) === "generalizedTime") return dateTimeLocalToGeneralizedTime(text);
  const editor = props.schema ? getLdapEditor(name, props.schema) : undefined;
  return editor ? editor.serialize(text) : text;
}

function deserializeValue(name: string, value: string): string {
  if (attributeKind(name) === "generalizedTime") return generalizedTimeToDateTimeLocal(value);
  const editor = props.schema ? getLdapEditor(name, props.schema) : undefined;
  return editor ? editor.deserialize(value) : value;
}

const missingMustAttributes = computed<string[]>(() => {
  if (!props.schema || !props.entry) return [];
  const required = getRequiredAttributes(props.schema, entryObjectClasses());
  const existing = new Set(Object.keys(currentAttributes.value).map((name) => name.toLowerCase()));
  return required.filter((name) => name.toLowerCase() !== "objectclass" && !existing.has(name.toLowerCase()));
});

const addableAttributes = computed<{ name: string; missing: boolean }[]>(() => {
  if (!props.schema || !props.entry) return [];
  const existing = new Set(Object.keys(currentAttributes.value).map((name) => name.toLowerCase()));
  const missing = missingMustAttributes.value.filter((name) => !rows.value.some((row) => row.name.toLowerCase() === name.toLowerCase()));
  const optional = getOptionalAttributes(props.schema, entryObjectClasses()).filter((name) => name.toLowerCase() !== "objectclass" && !existing.has(name.toLowerCase()) && !missing.some((m) => m.toLowerCase() === name.toLowerCase()));
  return [...missing.map((name) => ({ name, missing: true })), ...[...new Set(optional)].sort((a, b) => a.localeCompare(b)).map((name) => ({ name, missing: false }))];
});

function buildRows() {
  const entry = props.entry;
  rowsDn = entry?.dn ?? "";
  showAddAttribute.value = false;
  currentAttributes.value = entry ? { ...entry.attributes } : {};
  if (!entry || !entry.dn) {
    // The Root DSE is shown read-only elsewhere; nothing editable here.
    rows.value = [];
    return;
  }
  const mustNames = new Set(getRequiredAttributes(props.schema ?? { objectClasses: [], attributesEditor: {} }, entryObjectClasses()).map((name) => name.toLowerCase()));
  const built: AttributeRow[] = [];
  for (const [name, raw] of Object.entries(entry.attributes)) {
    const locked = name.toLowerCase() === "objectclass" || isSystemAttribute(name);
    const attr = props.schema ? getLdapAttributeType(props.schema, name) : undefined;
    const kind: AttributeRow["kind"] = mustNames.has(name.toLowerCase()) ? "must" : "may";
    const values = Array.isArray(raw) ? raw.map(String) : [String(raw)];
    built.push({
      name,
      kind,
      description: attr?.description ?? "",
      locked,
      pending: false,
      missing: false,
      cells: values.map((value) => ({ text: deserializeValue(name, value), committedText: deserializeValue(name, value), original: value, isNew: false })),
    });
  }
  built.sort((a, b) => {
    const rank = (row: AttributeRow) => (row.locked ? 0 : row.kind === "must" ? 1 : 2);
    return rank(a) - rank(b) || a.name.localeCompare(b.name);
  });
  // Synthesized rows for MUST attributes the entry is missing.
  for (const name of missingMustAttributes.value) {
    if (built.some((row) => row.name.toLowerCase() === name.toLowerCase())) continue;
    const attr = props.schema ? getLdapAttributeType(props.schema, name) : undefined;
    built.push({
      name,
      kind: "must",
      description: attr?.description ?? "",
      locked: false,
      pending: false,
      missing: true,
      cells: [{ text: "", committedText: "", original: "", isNew: true }],
    });
  }
  rows.value = built;
}

watch([() => props.entry, () => props.schema], buildRows, { immediate: true });

function rowEditable(row: AttributeRow): boolean {
  return !props.readOnly && !row.locked && !!props.entry?.dn;
}

async function commitAttribute(row: AttributeRow, mutateCell?: ValueCell) {
  if (!rowEditable(row) || row.pending) return;
  const dn = props.entry?.dn ?? "";
  if (dn !== rowsDn) return;

  const changedCell = mutateCell ?? row.cells.find((cell) => cell.isNew && cell.text);
  let serializedChanged = "";
  if (mutateCell) {
    serializedChanged = serializeValue(row.name, mutateCell.text);
    if (!mutateCell.isNew && serializedChanged === mutateCell.original) return;
    if (mutateCell.isNew && !serializedChanged) return;
  } else if (!changedCell) {
    return;
  } else {
    serializedChanged = serializeValue(row.name, changedCell.text);
    if (!serializedChanged) return;
  }

  const newValues = row.cells.map((cell) => (cell === changedCell ? serializedChanged : cell.isNew ? "" : cell.original)).filter((value) => value !== "");

  row.pending = true;
  try {
    await api.ldapModify(props.connectionId, dn, [{ op: "replace", attribute: row.name, values: newValues }]);
    if (newValues.length === 0) {
      delete currentAttributes.value[row.name];
      rows.value = rows.value.filter((r) => r !== row);
    } else {
      currentAttributes.value[row.name] = [...newValues];
      row.cells = newValues.map((value) => ({ text: deserializeValue(row.name, value), committedText: deserializeValue(row.name, value), original: value, isNew: false }));
      row.missing = false;
    }
    emit("updated", dn);
  } catch (e: unknown) {
    if (mutateCell) mutateCell.text = mutateCell.committedText;
    toast(e instanceof Error ? e.message : String(e), 5000);
  } finally {
    row.pending = false;
  }
}

function onCellBlur(row: AttributeRow, cell: ValueCell) {
  // A touched-but-empty new cell is discarded; otherwise commit changes.
  if (cell.isNew && !cell.text) return;
  commitAttribute(row, cell);
}

function onCellKeydown(event: KeyboardEvent, row: AttributeRow, cell: ValueCell) {
  if (event.key === "Enter") {
    event.preventDefault();
    commitAttribute(row, cell);
    (event.target as HTMLElement)?.blur();
  } else if (event.key === "Escape") {
    event.preventDefault();
    cell.text = cell.committedText;
    (event.target as HTMLElement)?.blur();
  }
}

async function removeCell(row: AttributeRow, cell: ValueCell) {
  if (!rowEditable(row) || row.pending || cell.isNew) return;
  const dn = props.entry?.dn ?? "";
  if (dn !== rowsDn) return;
  const remaining = row.cells.filter((c) => c !== cell && !c.isNew).map((c) => c.original);
  row.pending = true;
  try {
    if (remaining.length === 0) {
      await api.ldapModify(props.connectionId, dn, [{ op: "delete", attribute: row.name, values: [] }]);
      delete currentAttributes.value[row.name];
      rows.value = rows.value.filter((r) => r !== row);
    } else {
      await api.ldapModify(props.connectionId, dn, [{ op: "replace", attribute: row.name, values: remaining }]);
      currentAttributes.value[row.name] = [...remaining];
      row.cells = remaining.map((value) => ({ text: deserializeValue(row.name, value), committedText: deserializeValue(row.name, value), original: value, isNew: false }));
    }
    emit("updated", dn);
  } catch (e: unknown) {
    toast(e instanceof Error ? e.message : String(e), 5000);
  } finally {
    row.pending = false;
  }
}

async function removeRow(row: AttributeRow) {
  if (!rowEditable(row) || row.pending || row.missing) return;
  const dn = props.entry?.dn ?? "";
  if (dn !== rowsDn) return;
  row.pending = true;
  try {
    await api.ldapModify(props.connectionId, dn, [{ op: "delete", attribute: row.name, values: [] }]);
    delete currentAttributes.value[row.name];
    rows.value = rows.value.filter((r) => r !== row);
    emit("updated", dn);
  } catch (e: unknown) {
    toast(e instanceof Error ? e.message : String(e), 5000);
  } finally {
    row.pending = false;
  }
}

function addValueCell(row: AttributeRow) {
  if (!rowEditable(row)) return;
  row.cells.push({ text: "", committedText: "", original: "", isNew: true });
}

function addAttributeRow(name: string) {
  showAddAttribute.value = false;
  if (!name || rows.value.some((row) => row.name.toLowerCase() === name.toLowerCase())) return;
  const attr = props.schema ? getLdapAttributeType(props.schema, name) : undefined;
  rows.value.push({
    name,
    kind: missingMustAttributes.value.some((m) => m.toLowerCase() === name.toLowerCase()) ? "must" : "may",
    description: attr?.description ?? "",
    locked: false,
    pending: false,
    missing: false,
    cells: [{ text: "", committedText: "", original: "", isNew: true }],
  });
}

async function verifyRowPassword(row: AttributeRow) {
  const dn = props.entry?.dn ?? "";
  if (!dn || !row.verifyText || row.verifying) return;
  row.verifying = true;
  try {
    const result = await api.ldapVerifyPassword(props.connectionId, dn, row.verifyText);
    if (result.verified) {
      toast(t("ldap.passwordVerified"), 2500);
    } else {
      toast(t("ldap.passwordNotVerified"), 4000);
    }
  } catch (e: unknown) {
    toast(e instanceof Error ? e.message : String(e), 5000);
  } finally {
    row.verifying = false;
    row.verifyOpen = false;
    row.verifyText = "";
  }
}

function onObjectClassesSaved(newValues: string[]) {
  currentAttributes.value["objectClass"] = [...newValues];
  // Refetching rebuilds the rows, surfacing MUST attributes required by a
  // newly added auxiliary class.
  emit("entryChanged", props.entry?.dn ?? "");
}
</script>

<template>
  <div class="space-y-1.5">
    <div v-for="row in rows" :key="row.name" class="rounded border border-border/60 px-2 py-1.5 space-y-1" :class="{ 'border-destructive/50': row.kind === 'must' && row.missing }">
      <div class="flex items-center gap-2">
        <span class="w-44 shrink-0 text-xs font-mono" :class="{ 'text-muted-foreground': row.kind !== 'must' }" :title="row.description || row.name"> <span v-if="row.kind === 'must'" class="text-destructive mr-0.5">*</span>{{ row.name }} </span>
        <Badge v-if="row.kind === 'must'" variant="secondary" class="text-[10px] px-1 py-0">MUST</Badge>
        <Loader2 v-if="row.pending" class="size-3 animate-spin text-muted-foreground" />
        <template v-else-if="row.locked">
          <Button v-if="row.name.toLowerCase() === 'objectclass' && !props.readOnly" variant="ghost" size="icon-sm" class="text-muted-foreground" :title="t('ldap.objectClassEditorTitle')" @click="objectClassEditorOpen = true">
            <Pencil class="size-3.5" />
          </Button>
          <Lock v-else class="size-3 text-muted-foreground" :title="t('ldap.objectClassLocked')" />
        </template>
        <span class="flex-1" />
        <Button v-if="rowEditable(row) && !row.missing" variant="ghost" size="icon-sm" class="text-muted-foreground" :title="t('ldap.removeAttribute')" @click="removeRow(row)">
          <X class="size-3.5" />
        </Button>
      </div>
      <div v-for="(cell, cellIndex) in row.cells" :key="cellIndex" class="flex items-center gap-1.5">
        <select v-if="attributeKind(row.name) === 'boolean'" v-model="cell.text" class="h-6 flex-1 min-w-0 text-xs font-mono rounded-md border border-input bg-background px-2" :disabled="!rowEditable(row)" @change="commitAttribute(row, cell)" @blur="onCellBlur(row, cell)">
          <option v-if="!cell.text" value=""></option>
          <option value="TRUE">TRUE</option>
          <option value="FALSE">FALSE</option>
        </select>
        <Input v-else-if="attributeKind(row.name) === 'generalizedTime'" v-model="cell.text" type="datetime-local" class="h-6 flex-1 min-w-0 text-xs" :disabled="!rowEditable(row)" @keydown="onCellKeydown($event, row, cell)" @blur="onCellBlur(row, cell)" />
        <Input v-else-if="attributeKind(row.name) === 'integer'" v-model="cell.text" type="number" step="1" class="h-6 flex-1 min-w-0 text-xs font-mono" :disabled="!rowEditable(row)" @keydown="onCellKeydown($event, row, cell)" @blur="onCellBlur(row, cell)" />
        <Input v-else-if="attributeKind(row.name) === 'password'" v-model="cell.text" type="password" class="h-6 flex-1 min-w-0 text-xs font-mono" autocomplete="new-password" :disabled="!rowEditable(row)" @keydown="onCellKeydown($event, row, cell)" @blur="onCellBlur(row, cell)" />
        <Input v-else-if="attributeKind(row.name) === 'binary' || attributeKind(row.name) === 'jpeg'" :model-value="cell.text" class="h-6 flex-1 min-w-0 text-xs font-mono" disabled :title="t('ldap.binaryReadonlyHint')" />
        <Input
          v-else
          v-model="cell.text"
          class="h-6 flex-1 min-w-0 text-xs"
          :class="{ 'border-destructive': row.kind === 'must' && row.missing && !cell.text }"
          :disabled="!rowEditable(row)"
          :placeholder="row.missing ? t('ldap.missingMustHint') : ''"
          @keydown="onCellKeydown($event, row, cell)"
          @blur="onCellBlur(row, cell)"
        />
        <Button v-if="attributeKind(row.name) === 'password' && rowEditable(row) && !cell.isNew && !row.missing" variant="ghost" size="icon-xs" class="text-muted-foreground" :title="t('ldap.verifyPasswordTooltip')" @click="row.verifyOpen = !row.verifyOpen">
          <ShieldCheck class="size-3" />
        </Button>
        <Button v-if="rowEditable(row) && !cell.isNew" variant="ghost" size="icon-xs" class="text-muted-foreground" :title="t('ldap.removeValue')" @click="removeCell(row, cell)">
          <X class="size-3" />
        </Button>
      </div>
      <div v-if="row.verifyOpen" class="flex items-center gap-1.5 pl-1">
        <Input v-model="row.verifyText" type="password" class="h-6 flex-1 min-w-0 text-xs font-mono" autocomplete="off" :placeholder="t('ldap.verifyPasswordPlaceholder')" @keydown.enter="verifyRowPassword(row)" />
        <Button variant="ghost" size="icon-xs" class="text-muted-foreground" :disabled="row.verifying" :title="t('ldap.verifyPasswordTooltip')" @click="verifyRowPassword(row)">
          <Loader2 v-if="row.verifying" class="size-3 animate-spin" />
          <ShieldCheck v-else class="size-3" />
        </Button>
      </div>
      <Button v-if="rowEditable(row)" variant="ghost" size="sm" class="h-5 px-1.5 text-xs text-muted-foreground" @click="addValueCell(row)"> <Plus class="size-3 mr-1" />{{ t("ldap.addValue") }} </Button>
    </div>

    <div v-if="addableAttributes.length > 0 && !readOnly && entry?.dn" class="flex items-center gap-2 pt-1">
      <Button v-if="!showAddAttribute" variant="outline" size="sm" class="h-7 px-2 text-xs" @click="showAddAttribute = true"> <Plus class="size-3 mr-1" />{{ t("ldap.addAttribute") }} </Button>
      <template v-else>
        <select class="h-7 flex-1 min-w-0 text-xs font-mono rounded-md border border-input bg-background px-2" @change="addAttributeRow(($event.target as HTMLSelectElement).value)">
          <option value="">{{ t("ldap.addAttribute") }}…</option>
          <option v-for="attr in addableAttributes" :key="attr.name" :value="attr.name">{{ attr.missing ? "* " : "" }}{{ attr.name }}</option>
        </select>
        <Button variant="ghost" size="icon-sm" class="text-muted-foreground" @click="showAddAttribute = false">
          <X class="size-3.5" />
        </Button>
      </template>
    </div>

    <LdapObjectClassEditorDialog v-model:open="objectClassEditorOpen" :connection-id="connectionId" :dn="entry?.dn ?? ''" :object-classes="entryObjectClasses()" :schema="schema" :read-only="readOnly" @saved="onObjectClassesSaved" />
  </div>
</template>
