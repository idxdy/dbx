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
import { getOrFetchLdapConfig } from "@/lib/ldap/ldapSchema";
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
  saved: [];
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
      ldapConfig.value = await getOrFetchLdapConfig();
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

/** Diff the edited rows against the original attributes into Modify operations. */
function buildModifications(): LdapModification[] {
  const modifications: LdapModification[] = [];
  const original = props.entry?.attributes ?? {};

  for (const row of rows.value) {
    const name = row.name.trim();
    if (!name) continue;
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
    if (!currentNames.value.has(name)) {
      modifications.push({ op: "delete", attribute: name, values: [] });
    }
  }
  return modifications;
}

async function save() {
  if (!props.entry) return;
  const modifications = buildModifications();
  if (modifications.length === 0) {
    open.value = false;
    return;
  }
  saving.value = true;
  try {
    await api.ldapModify(props.connectionId, props.entry.dn, modifications);
    toast(t("ldap.writeSuccess"), 2500);
    emit("saved");
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
              <Input v-model="row.name" class="h-6 w-40 text-xs font-mono" :class="{ 'text-muted-foreground': entry.attributes[row.name.trim()] !== undefined }" />
              <Button variant="ghost" size="icon-sm" class="shrink-0 text-muted-foreground" :title="t('ldap.removeAttribute')" @click="removeRow(rowIndex)">
                <X class="size-3.5" />
              </Button>
            </div>
            <div v-for="(_, valueIndex) in row.values" :key="valueIndex" class="flex items-center gap-1.5">
              <Input v-model="row.values[valueIndex]" class="h-6 flex-1 min-w-0 text-xs" />
              <Button variant="ghost" size="icon-xs" class="shrink-0 text-muted-foreground" :title="t('ldap.removeValue')" @click="removeValue(rowIndex, valueIndex)">
                <X class="size-3" />
              </Button>
            </div>
            <Button variant="ghost" size="sm" class="h-5 px-1.5 text-xs text-muted-foreground" @click="addValue(rowIndex)"> <Plus class="size-3 mr-1" />{{ t("ldap.addValue") }} </Button>
          </div>
        </div>

        <Button variant="outline" size="sm" class="h-7 px-2 text-xs" @click="addRow"> <Plus class="size-3 mr-1" />{{ t("ldap.addAttribute") }} </Button>
      </div>

      <DialogFooter>
        <Button variant="outline" :disabled="saving" @click="open = false">{{ t("ldap.cancel") }}</Button>
        <Button :disabled="saving" @click="save">{{ t("ldap.save") }}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
