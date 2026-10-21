<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/composables/useToast";
import { useConnectionStore } from "@/stores/connectionStore";
import * as api from "@/lib/backend/api";

const { t } = useI18n();
const { toast } = useToast();

const open = defineModel<boolean>("open", { default: false });

const props = defineProps<{
  connectionId: string;
  dn: string;
}>();

const connectionStore = useConnectionStore();

// Defense-in-depth: the toolbar buttons and sidebar menu items that open this
// dialog are already disabled for read-only connections; guard here too so a
// stale menu state or a future caller cannot bypass the flag.
const readOnly = computed(() => Boolean((connectionStore.getConfig(props.connectionId) as any)?.read_only));

const emit = defineEmits<{
  renamed: [newDn: string];
}>();

const newRdn = ref("");
const newParentDn = ref("");
const saving = ref(false);

watch(open, (value) => {
  if (value) {
    newRdn.value = props.dn.split(",")[0] ?? "";
    newParentDn.value = "";
    saving.value = false;
  }
});

async function save() {
  if (readOnly.value) {
    toast(t("ldap.readOnly"), 4000);
    return;
  }
  const rdn = newRdn.value.trim();
  if (!rdn || !rdn.includes("=")) {
    toast(t("ldap.invalidRdn"), 3000);
    return;
  }
  saving.value = true;
  try {
    const parent = newParentDn.value.trim();
    const result = await api.ldapRename(props.connectionId, props.dn, rdn, true, parent || undefined);
    toast(t("ldap.writeSuccess"), 2500);
    emit("renamed", result.dn);
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
        <DialogTitle>{{ t("ldap.renameTitle") }}</DialogTitle>
      </DialogHeader>

      <div class="py-2 space-y-3">
        <div class="grid grid-cols-4 items-center gap-2">
          <Label class="text-right text-xs">{{ t("ldap.currentDn") }}</Label>
          <div class="col-span-3 text-xs font-mono break-all bg-muted rounded px-2 py-1">{{ dn }}</div>
        </div>
        <div class="grid grid-cols-4 items-center gap-2">
          <Label for="ldap-rename-rdn" class="text-right text-xs">{{ t("ldap.newRdn") }}</Label>
          <Input id="ldap-rename-rdn" v-model="newRdn" class="col-span-3 h-7 text-xs font-mono" placeholder="cn=new-name" />
        </div>
        <div class="grid grid-cols-4 items-center gap-2">
          <Label for="ldap-rename-parent" class="text-right text-xs">{{ t("ldap.newParentDn") }}</Label>
          <Input id="ldap-rename-parent" v-model="newParentDn" class="col-span-3 h-7 text-xs font-mono" :placeholder="t('ldap.newParentDnHint')" />
        </div>
      </div>

      <DialogFooter>
        <Button variant="outline" :disabled="saving" @click="open = false">{{ t("ldap.cancel") }}</Button>
        <Button :disabled="saving || readOnly" @click="save">{{ t("ldap.rename") }}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
