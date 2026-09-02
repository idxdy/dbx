<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Plus, X } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/composables/useToast";
import * as api from "@/lib/backend/api";
import { getOrFetchLdapConfig, getStructuralObjectClasses, getOptionalAttributes, getRequiredAttributes } from "@/lib/ldap/ldapSchema";
import { getLdapEditor } from "@/lib/ldap/ldapEditors";
import type { LdapSchemaConfig, LdapObjectClass } from "@/lib/backend/http";

const { t } = useI18n();
const { toast } = useToast();

const open = defineModel<boolean>("open", { default: false });

const props = defineProps<{
  connectionId: string;
  /** Parent DN under which the new entry is created. */
  parentDn: string;
}>();

const emit = defineEmits<{
  created: [dn: string];
}>();

interface AttributeRow {
  name: string;
  value: string;
  required?: boolean;
}

const rdnAttr = ref("");
const rdnValue = ref("");
const rdn = computed(() => `${rdnAttr.value.trim()}=${rdnValue.value.trim()}`);
const selectedObjectClass = ref("");
const rows = ref<AttributeRow[]>([]);
const saving = ref(false);
const ldapConfig = ref<LdapSchemaConfig | null>(null);
const structuralClasses = ref<LdapObjectClass[]>([]);

watch(open, async (value) => {
  if (value) {
    rdnAttr.value = "";
    rdnValue.value = "";
    selectedObjectClass.value = "";
    rows.value = [];
    saving.value = false;
    try {
      ldapConfig.value = await getOrFetchLdapConfig();
      structuralClasses.value = getStructuralObjectClasses(ldapConfig.value);
      if (structuralClasses.value.length > 0) {
        selectedObjectClass.value = structuralClasses.value[0].name;
      }
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), 5000);
    }
  }
});

/** Rebuild required rows when objectClass or RDN changes. */
function rebuildRequiredRows() {
  if (!ldapConfig.value || !selectedObjectClass.value) return;
  const rdnAttrLower = rdnAttr.value.trim().toLowerCase();
  const rdnVal = rdnValue.value.trim();
  if (!rdnAttrLower || !rdnVal) {
    rows.value = [];
    return;
  }
  const required = getRequiredAttributes(ldapConfig.value, selectedObjectClass.value);
  // Keep user-added rows that are not required or not the RDN attr
  const userRows = rows.value.filter((r) => !r.required);
  const requiredRows: AttributeRow[] = required
    .filter((a) => a.toLowerCase() !== rdnAttrLower && a.toLowerCase() !== "objectclass")
    .map((a) => ({
      name: a,
      value: userRows.find((r) => r.name.toLowerCase() === a.toLowerCase())?.value ?? "",
      required: true,
    }));
  rows.value = [...requiredRows, ...userRows.filter((r) => !r.required)];
}

watch(selectedObjectClass, rebuildRequiredRows);
watch(rdnAttr, rebuildRequiredRows);
watch(rdnValue, rebuildRequiredRows);

const hasMissingRequired = computed(() => {
  if (!rdnAttr.value.trim() || !rdnValue.value.trim()) return true;
  return rows.value.some((r) => r.required && !r.value.trim());
});

/** Attributes allowed by the selected objectClass chain (MUST + MAY), or null when the schema is unavailable. */
const allowedAttributeNames = computed<Set<string> | null>(() => {
  if (!ldapConfig.value || !selectedObjectClass.value) return null;
  const set = new Set<string>(["objectclass"]);
  for (const attr of getRequiredAttributes(ldapConfig.value, selectedObjectClass.value)) set.add(attr.toLowerCase());
  for (const attr of getOptionalAttributes(ldapConfig.value, selectedObjectClass.value)) set.add(attr.toLowerCase());
  return set;
});

const requiredAttributeNames = computed<Set<string>>(() => {
  if (!ldapConfig.value || !selectedObjectClass.value) return new Set<string>();
  return new Set(getRequiredAttributes(ldapConfig.value, selectedObjectClass.value).map((attr) => attr.toLowerCase()));
});

/** Optional (MAY) attributes offered as suggestions for user-added rows. */
const optionalAttributeNames = computed<string[]>(() => {
  const allowed = allowedAttributeNames.value;
  if (!allowed) return [];
  const required = requiredAttributeNames.value;
  return [...allowed].filter((attr) => !required.has(attr) && attr !== "objectclass").sort();
});

const rdnAttrInvalid = computed(() => {
  const name = rdnAttr.value.trim();
  if (!name || !allowedAttributeNames.value) return false;
  return !allowedAttributeNames.value.has(name.toLowerCase());
});

function isRowInvalid(row: AttributeRow): boolean {
  const name = row.name.trim();
  if (!name || !allowedAttributeNames.value) return false;
  return !allowedAttributeNames.value.has(name.toLowerCase());
}

const invalidAttributeNames = computed<string[]>(() => {
  if (rdnAttrInvalid.value && rdnAttr.value.trim()) return [rdnAttr.value.trim()];
  return [...new Set(rows.value.filter(isRowInvalid).map((r) => r.name.trim()))];
});

const hasInvalidAttributes = computed(() => invalidAttributeNames.value.length > 0);

function addRow() {
  rows.value.push({ name: "", value: "" });
}

function removeRow(index: number) {
  rows.value.splice(index, 1);
}

function buildAttributes(): Record<string, string | string[]> | null {
  const attributes: Record<string, string | string[]> = {};
  const oc = ldapConfig.value?.objectClasses.find((c) => c.name === selectedObjectClass.value);
  attributes.objectClass = oc ? oc.inheritanceChain : selectedObjectClass.value;
  const rdnAttrName = rdnAttr.value.trim();
  const rdnVal = rdnValue.value.trim();
  if (rdnAttrName && rdnVal) {
    attributes[rdnAttrName] = rdnVal;
  }
  for (const row of rows.value) {
    const name = row.name.trim();
    if (!name || name === "objectClass") continue;
    const value = row.value;
    if (!value) continue;
    const editor = ldapConfig.value ? getLdapEditor(name, ldapConfig.value) : undefined;
    const serialized = editor ? editor.serialize(value) : value;
    const existing = attributes[name];
    if (existing === undefined) {
      attributes[name] = serialized;
    } else if (Array.isArray(existing)) {
      existing.push(serialized);
    } else {
      attributes[name] = [existing, serialized];
    }
  }
  return Object.keys(attributes).length > 0 ? attributes : null;
}

async function save() {
  const rdnTrimmed = rdn.value;
  if (!rdnAttr.value.trim() || !rdnValue.value.trim()) {
    toast(t("ldap.invalidRdn"), 3000);
    return;
  }
  // The server rejects attributes outside the objectClass's MUST/MAY sets
  // with objectClassViolation (rc=65); surface that before submitting.
  if (hasInvalidAttributes.value) {
    toast(t("ldap.attributeNotAllowed", { attribute: invalidAttributeNames.value.join(", ") }), 5000);
    return;
  }
  const attributes = buildAttributes();
  if (!attributes) {
    toast(t("ldap.attributesRequired"), 3000);
    return;
  }
  const dn = `${rdnTrimmed},${props.parentDn}`;
  saving.value = true;
  try {
    await api.ldapAdd(props.connectionId, dn, attributes);
    toast(t("ldap.writeSuccess"), 2500);
    emit("created", dn);
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
    <DialogContent class="sm:max-w-[560px]">
      <DialogHeader>
        <DialogTitle>{{ t("ldap.createTitle") }}</DialogTitle>
      </DialogHeader>

      <div class="py-2 space-y-3">
        <div class="grid grid-cols-4 items-center gap-2">
          <Label class="text-right text-xs">{{ t("ldap.parentDn") }}</Label>
          <div class="col-span-3 text-xs font-mono break-all bg-muted rounded px-2 py-1">{{ parentDn }}</div>
        </div>
        <div class="grid grid-cols-4 items-center gap-2">
          <Label class="text-right text-xs">{{ t("ldap.rdn") }}</Label>
          <div class="col-span-3 flex items-center gap-1.5">
            <Input v-model="rdnAttr" class="h-7 w-28 text-xs font-mono" :class="{ 'border-destructive': !rdnAttr.trim() || rdnAttrInvalid }" placeholder="cn" />
            <span class="text-muted-foreground">=</span>
            <Input v-model="rdnValue" class="h-7 flex-1 min-w-0 text-xs font-mono" :class="{ 'border-destructive': !rdnValue.trim() }" placeholder="new-user" />
          </div>
        </div>
        <div class="grid grid-cols-4 items-center gap-2">
          <Label for="ldap-create-objectclass" class="text-right text-xs">{{ t("ldap.objectClass") }}</Label>
          <select id="ldap-create-objectclass" v-model="selectedObjectClass" class="col-span-3 h-7 text-xs font-mono rounded-md border border-input bg-background px-2">
            <option v-for="oc in structuralClasses" :key="oc.name" :value="oc.name">{{ oc.name }} — {{ oc.description }}</option>
          </select>
        </div>
        <div class="grid grid-cols-4 items-center gap-2">
          <Label class="text-right text-xs">DN</Label>
          <div class="col-span-3 text-xs font-mono break-all text-muted-foreground">
            {{ rdnAttr.trim() && rdnValue.trim() ? rdn + "," + parentDn : parentDn }}
          </div>
        </div>

        <div class="space-y-1.5">
          <div class="flex items-center justify-between">
            <Label class="text-xs">{{ t("ldap.attributes") }}</Label>
            <Button variant="ghost" size="sm" class="h-6 px-2 text-xs" @click="addRow"> <Plus class="size-3 mr-1" />{{ t("ldap.addAttribute") }} </Button>
          </div>
          <div v-for="(row, index) in rows" :key="index" class="flex items-center gap-2">
            <Input v-model="row.name" class="h-7 w-40 text-xs font-mono" placeholder="sn" list="ldap-optional-attrs" :disabled="row.required" :class="{ 'border-destructive': isRowInvalid(row) }" :title="isRowInvalid(row) ? t('ldap.attributeNotAllowed', { attribute: row.name.trim() }) : undefined" />
            <Input v-model="row.value" class="h-7 flex-1 min-w-0 text-xs" :class="{ 'border-destructive': row.required && !row.value }" @keydown.enter="save" />
            <Button v-if="!row.required" variant="ghost" size="icon-sm" class="shrink-0 text-muted-foreground" @click="removeRow(index)">
              <X class="size-3.5" />
            </Button>
          </div>
          <datalist id="ldap-optional-attrs">
            <option v-for="attr in optionalAttributeNames" :key="attr" :value="attr" />
          </datalist>
        </div>
      </div>

      <DialogFooter>
        <Button variant="outline" :disabled="saving" @click="open = false">{{ t("ldap.cancel") }}</Button>
        <Button :disabled="saving || hasMissingRequired || hasInvalidAttributes" @click="save">{{ t("ldap.create") }}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
