<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Lock, Plus, X } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { useToast } from "@/composables/useToast";
import * as api from "@/lib/backend/api";
import { getAuxiliaryObjectClasses } from "@/lib/ldap/ldapSchema";
import type { LdapSchemaConfig } from "@/lib/backend/http";

const { t } = useI18n();
const { toast } = useToast();

const open = defineModel<boolean>("open", { default: false });

const props = defineProps<{
  connectionId: string;
  dn: string;
  objectClasses: string[];
  schema: LdapSchemaConfig | null;
  readOnly?: boolean;
}>();

const emit = defineEmits<{
  saved: [objectClasses: string[]];
}>();

const working = ref<string[]>([]);
const adding = ref("");
const saving = ref(false);

watch(open, (value) => {
  if (value) {
    working.value = [...props.objectClasses];
    adding.value = "";
    saving.value = false;
  }
});

function classInfo(name: string) {
  return props.schema?.objectClasses.find((oc) => oc.name.toLowerCase() === name.toLowerCase());
}

function classType(name: string): string {
  return classInfo(name)?.type ?? "STRUCTURAL";
}

const availableAuxiliary = computed(() => {
  const current = new Set(working.value.map((name) => name.toLowerCase()));
  return getAuxiliaryObjectClasses(props.schema ?? { objectClasses: [], attributesEditor: {} })
    .filter((oc) => !current.has(oc.name.toLowerCase()))
    .map((oc) => oc.name);
});

function addClass(name: string) {
  if (!name || working.value.some((existing) => existing.toLowerCase() === name.toLowerCase())) return;
  working.value.push(name);
  adding.value = "";
}

function removeClass(name: string) {
  // Only AUXILIARY classes may be dropped from an existing entry —
  // structural/abstract classes define what the entry is.
  if (classType(name) !== "AUXILIARY") return;
  working.value = working.value.filter((existing) => existing.toLowerCase() !== name.toLowerCase());
}

async function save() {
  if (props.readOnly) return;
  saving.value = true;
  try {
    await api.ldapModify(props.connectionId, props.dn, [{ op: "replace", attribute: "objectClass", values: working.value }]);
    toast(t("ldap.writeSuccess"), 2500);
    emit("saved", [...working.value]);
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
    <DialogContent class="sm:max-w-[520px]">
      <DialogHeader>
        <DialogTitle>{{ t("ldap.objectClassEditorTitle") }}</DialogTitle>
      </DialogHeader>

      <div class="py-2 space-y-3">
        <div class="grid grid-cols-4 items-center gap-2">
          <Label class="text-right text-xs">DN</Label>
          <div class="col-span-3 text-xs font-mono break-all bg-muted rounded px-2 py-1">{{ dn }}</div>
        </div>

        <div class="space-y-1.5">
          <div v-for="name in working" :key="name" class="flex items-center gap-2 rounded border border-border/60 px-2 py-1.5">
            <span class="text-xs font-mono flex-1 min-w-0 truncate">{{ name }}</span>
            <Badge variant="secondary" class="text-[10px] px-1 py-0">{{ classType(name) }}</Badge>
            <Button v-if="classType(name) === 'AUXILIARY' && !readOnly" variant="ghost" size="icon-xs" class="text-muted-foreground" :title="t('ldap.removeClass')" @click="removeClass(name)">
              <X class="size-3" />
            </Button>
            <Lock v-else class="size-3 text-muted-foreground" />
          </div>
        </div>

        <div v-if="!readOnly" class="flex items-center gap-2">
          <select v-model="adding" class="h-7 flex-1 min-w-0 text-xs font-mono rounded-md border border-input bg-background px-2">
            <option value="">{{ t("ldap.addAuxiliaryClass") }}…</option>
            <option v-for="name in availableAuxiliary" :key="name" :value="name">{{ name }}</option>
          </select>
          <Button variant="outline" size="sm" class="h-7 px-2 text-xs" :disabled="!adding" @click="addClass(adding)"> <Plus class="size-3 mr-1" />{{ t("ldap.addAttribute") }} </Button>
        </div>
        <p class="text-xs text-muted-foreground">{{ t("ldap.objectClassEditorHint") }}</p>
      </div>

      <DialogFooter>
        <Button variant="outline" :disabled="saving" @click="open = false">{{ t("ldap.cancel") }}</Button>
        <Button :disabled="saving" @click="save">{{ t("ldap.save") }}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
