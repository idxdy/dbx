<script setup lang="ts">
import { ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Plus, X } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/composables/useToast";
import * as api from "@/lib/backend/api";

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
}

const rdn = ref("");
const objectClass = ref("inetOrgPerson");
const rows = ref<AttributeRow[]>([{ name: "", value: "" }]);
const saving = ref(false);

watch(open, (value) => {
  if (value) {
    rdn.value = "";
    objectClass.value = "inetOrgPerson";
    rows.value = [{ name: "", value: "" }];
    saving.value = false;
  }
});

function addRow() {
  rows.value.push({ name: "", value: "" });
}

function removeRow(index: number) {
  rows.value.splice(index, 1);
}

function buildAttributes(): Record<string, string | string[]> | null {
  const attributes: Record<string, string | string[]> = {};
  const classes = objectClass.value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (classes.length > 0) attributes.objectClass = classes.length === 1 ? classes[0] : classes;
  for (const row of rows.value) {
    const name = row.name.trim();
    if (!name || name === "objectClass") continue;
    const value = row.value;
    if (!value) continue;
    const existing = attributes[name];
    if (existing === undefined) {
      attributes[name] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      attributes[name] = [existing, value];
    }
  }
  return Object.keys(attributes).length > 0 ? attributes : null;
}

async function save() {
  const rdnTrimmed = rdn.value.trim();
  if (!rdnTrimmed || !rdnTrimmed.includes("=")) {
    toast(t("ldap.invalidRdn"), 3000);
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
          <Label for="ldap-create-rdn" class="text-right text-xs">{{ t("ldap.rdn") }}</Label>
          <Input id="ldap-create-rdn" v-model="rdn" class="col-span-3 h-7 text-xs font-mono" placeholder="uid=new-user" />
        </div>
        <div class="grid grid-cols-4 items-center gap-2">
          <Label for="ldap-create-objectclass" class="text-right text-xs">{{ t("ldap.objectClass") }}</Label>
          <Input id="ldap-create-objectclass" v-model="objectClass" class="col-span-3 h-7 text-xs font-mono" placeholder="inetOrgPerson" />
        </div>

        <div class="space-y-1.5">
          <div class="flex items-center justify-between">
            <Label class="text-xs">{{ t("ldap.attributes") }}</Label>
            <Button variant="ghost" size="sm" class="h-6 px-2 text-xs" @click="addRow"> <Plus class="size-3 mr-1" />{{ t("ldap.addAttribute") }} </Button>
          </div>
          <div v-for="(row, index) in rows" :key="index" class="flex items-center gap-2">
            <Input v-model="row.name" class="h-7 w-40 text-xs font-mono" placeholder="sn" />
            <Input v-model="row.value" class="h-7 flex-1 min-w-0 text-xs" @keydown.enter="save" />
            <Button variant="ghost" size="icon-sm" class="shrink-0 text-muted-foreground" @click="removeRow(index)">
              <X class="size-3.5" />
            </Button>
          </div>
        </div>
      </div>

      <DialogFooter>
        <Button variant="outline" :disabled="saving" @click="open = false">{{ t("ldap.cancel") }}</Button>
        <Button :disabled="saving" @click="save">{{ t("ldap.create") }}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
