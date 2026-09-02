<template>
  <div class="flex flex-col h-full">
    <!-- Toolbar -->
    <div class="flex items-center gap-2 px-3 py-1.5 border-b border-border shrink-0">
      <span v-if="baseDn" class="text-xs font-mono text-muted-foreground truncate flex-1 min-w-0" :title="baseDn">{{ baseDn }}</span>
      <Badge v-if="readOnly" variant="secondary" class="shrink-0">{{ t("connection.readOnly") }}</Badge>
      <template v-if="baseDn">
        <Button variant="outline" size="sm" class="h-6 px-2 text-xs" :disabled="readOnly" @click="showCreateDialog = true"> <Plus class="size-3 mr-1" />{{ t("ldap.addEntry") }} </Button>
        <Button variant="outline" size="sm" class="h-6 px-2 text-xs" :disabled="readOnly" @click="showEditDialog = true"> <Pencil class="size-3 mr-1" />{{ t("ldap.editEntry") }} </Button>
        <Button variant="outline" size="sm" class="h-6 px-2 text-xs" :disabled="readOnly" @click="showRenameDialog = true"> <Replace class="size-3 mr-1" />{{ t("ldap.renameEntry") }} </Button>
        <Button variant="outline" size="sm" class="h-6 px-2 text-xs text-destructive hover:text-destructive" :disabled="readOnly" @click="showDeleteDialog = true"> <Trash2 class="size-3 mr-1" />{{ t("ldap.deleteEntry") }} </Button>
      </template>
      <Button size="sm" variant="secondary" class="h-7 px-2" @click="reloadEntryDetail" :disabled="entryDetailLoading" title="Refresh">
        <Loader2 v-if="entryDetailLoading" class="size-3.5 animate-spin" />
        <RefreshCw v-else class="size-3.5" />
      </Button>
      <span class="text-xs text-muted-foreground shrink-0">Copy as:</span>
      <Button v-if="baseDn" variant="outline" size="sm" class="h-6 px-2 text-xs font-mono" :title="t('ldap.copyLdapsearchTooltip')" @click="copyAsLdapSearch"> <Copy class="size-3 mr-1" />ldapsearch </Button>
      <Button v-if="baseDn" variant="outline" size="sm" class="h-6 px-2 text-xs font-mono" :title="t('ldap.copyGetAdObjectTooltip')" @click="copyAsPowershellGetAdObject"> <Copy class="size-3 mr-1" />Get-ADObject </Button>
      <span v-if="copiedFlash" class="text-xs text-green-600 dark:text-green-400">Copied</span>
    </div>

    <!-- Detail panel -->
    <div class="flex-1 min-w-0 overflow-auto p-4">
      <div v-if="entryDetailLoading" class="flex items-center justify-center h-full">
        <Loader2 class="size-5 animate-spin text-muted-foreground" />
      </div>
      <div v-else-if="!entryDetail" class="flex flex-col items-center justify-center h-full text-muted-foreground gap-2">
        <FileSearch class="size-10 opacity-20" />
        <p class="text-sm">Select an entry to view its attributes</p>
      </div>
      <div v-else class="space-y-4">
        <div>
          <h3 class="text-sm font-semibold mb-1">DN</h3>
          <p class="text-sm font-mono bg-muted rounded px-2 py-1 break-all">{{ entryDetail.dn }}</p>
        </div>
        <div>
          <h3 class="text-sm font-semibold mb-2">Attributes</h3>
          <div class="border rounded-md overflow-hidden">
            <table class="w-full text-sm">
              <thead class="bg-muted/50">
                <tr>
                  <th class="text-left px-3 py-1.5 font-medium w-48">Name</th>
                  <th class="text-left px-3 py-1.5 font-medium">Value</th>
                </tr>
              </thead>
              <tbody class="divide-y">
                <tr v-for="(value, name) in entryDetail.attributes" :key="name" class="hover:bg-muted/30">
                  <td class="px-3 py-1 font-mono text-xs whitespace-nowrap align-top">{{ name }}</td>
                  <td class="px-3 py-1 font-mono text-xs max-w-md">
                    <span :class="{ 'cursor-pointer hover:text-primary hover:underline': isLongValue(value) }" @click="isLongValue(value) && openValuePopup(name, value)">{{ formatCellValue(value, name) }}</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- Value Popup Dialog -->
    <div v-if="popupOpen" class="fixed inset-0 z-50 flex items-center justify-center bg-black/40" @click.self="popupOpen = false">
      <div class="bg-background border rounded-lg shadow-xl max-w-lg w-full mx-4 max-h-[80vh] flex flex-col">
        <div class="flex items-center justify-between px-4 py-3 border-b shrink-0">
          <h3 class="font-semibold text-sm">{{ popupAttrName }}</h3>
          <button class="size-6 flex items-center justify-center rounded hover:bg-muted" @click="popupOpen = false">
            <X class="size-4" />
          </button>
        </div>
        <div class="overflow-auto p-4">
          <template v-if="Array.isArray(popupValues)">
            <div v-for="(v, i) in popupValues" :key="i" class="py-1 px-2 rounded text-xs font-mono break-all hover:bg-muted/50">{{ v }}</div>
          </template>
          <template v-else>
            <div class="text-xs font-mono break-all whitespace-pre-wrap">{{ popupValues }}</div>
          </template>
        </div>
        <div class="px-4 py-2 border-t text-xs text-muted-foreground shrink-0">
          {{ Array.isArray(popupValues) ? `${popupValues.length} value(s)` : `${String(popupValues).length} chars` }}
        </div>
      </div>
    </div>

    <!-- Write dialogs -->
    <LdapEntryCreateDialog v-model:open="showCreateDialog" :connection-id="connectionId" :parent-dn="baseDn || ''" @created="reloadEntryDetail" />
    <LdapEntryEditDialog v-model:open="showEditDialog" :connection-id="connectionId" :entry="entryDetail" @saved="onEntrySaved" />
    <LdapEntryRenameDialog v-model:open="showRenameDialog" :connection-id="connectionId" :dn="baseDn || ''" @renamed="onEntryRenamed" />
    <DangerConfirmDialog v-model:open="showDeleteDialog" :title="t('ldap.deleteTitle')" :message="t('ldap.deleteConfirmMessage')" :details="baseDn" :confirm-label="t('ldap.deleteEntry')" :loading="deleting" @confirm="deleteEntry" />
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { Loader2, FileSearch, X, Copy, Plus, Pencil, Trash2, Replace, RefreshCw } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useI18n } from "vue-i18n";
import * as api from "@/lib/backend/api";
import { useConnectionStore } from "@/stores/connectionStore";
import { useQueryStore } from "@/stores/queryStore";
import { useToast } from "@/composables/useToast";
import { copyToClipboard } from "@/lib/common/clipboard";
import { buildGetAdObjectIdentityCommand, buildLdapSearchByDnCommand } from "@/lib/ldap/ldapSearchSyntax";
import { getOrFetchLdapConfig } from "@/lib/ldap/ldapSchema";
import { getLdapEditor } from "@/lib/ldap/ldapEditors";
import type { LdapSchemaConfig } from "@/lib/backend/http";
import DangerConfirmDialog from "@/components/editor/DangerConfirmDialog.vue";
import LdapEntryCreateDialog from "@/components/ldap/LdapEntryCreateDialog.vue";
import LdapEntryEditDialog from "@/components/ldap/LdapEntryEditDialog.vue";
import LdapEntryRenameDialog from "@/components/ldap/LdapEntryRenameDialog.vue";

const { t } = useI18n();
const { toast } = useToast();

const props = defineProps<{
  connectionId: string;
  baseDn?: string;
}>();

const connectionStore = useConnectionStore();
const queryStore = useQueryStore();

const entryDetail = ref<{ dn: string; attributes: Record<string, string | string[]> } | null>(null);
const entryDetailLoading = ref(false);
const ldapConfig = ref<LdapSchemaConfig | null>(null);

const readOnly = computed(() => Boolean((connectionStore.getConfig(props.connectionId) as any)?.read_only));

const showCreateDialog = ref(false);
const showEditDialog = ref(false);
const showRenameDialog = ref(false);
const showDeleteDialog = ref(false);
const deleting = ref(false);

const popupOpen = ref(false);
const popupAttrName = ref("");
const popupValues = ref<string | string[]>("");

const copiedFlash = ref(false);
let copiedTimer: number | null = null;
function flashCopied() {
  copiedFlash.value = true;
  if (copiedTimer !== null) clearTimeout(copiedTimer);
  copiedTimer = window.setTimeout(() => {
    copiedFlash.value = false;
  }, 1500);
}

async function copyAsLdapSearch() {
  if (!props.baseDn) return;
  const config = connectionStore.getConfig(props.connectionId) as any;
  const cmd = buildLdapSearchByDnCommand(props.baseDn, config?.host, config?.port, !!config?.ssl);
  const attrs = entryDetail.value ? Object.keys(entryDetail.value.attributes) : [];
  await copyToClipboard(attrs.length > 0 ? `${cmd} ${attrs.join(" ")}` : cmd);
  flashCopied();
}

async function copyAsPowershellGetAdObject() {
  if (!props.baseDn) return;
  const config = connectionStore.getConfig(props.connectionId) as any;
  const cmd = buildGetAdObjectIdentityCommand(props.baseDn, config?.host);
  await copyToClipboard(cmd);
  flashCopied();
}

function isLongValue(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 1 || (value.length === 1 && String(value[0]).length > 120);
  return String(value).length > 120;
}

function formatCellValue(value: unknown, attrName?: string): string {
  const deserialize = (v: string) => {
    if (!ldapConfig.value || !attrName) return v;
    return getLdapEditor(attrName, ldapConfig.value).deserialize(v);
  };
  if (Array.isArray(value)) {
    const joined = value.map(deserialize).join(", ");
    return joined.length <= 120 ? joined : joined.slice(0, 117) + "...";
  }
  const str = deserialize(String(value));
  return str.length <= 120 ? str : str.slice(0, 117) + "...";
}

function openValuePopup(name: string, value: unknown) {
  popupAttrName.value = name;
  const deserialize = (v: string) => {
    if (!ldapConfig.value) return v;
    return getLdapEditor(name, ldapConfig.value).deserialize(v);
  };
  popupValues.value = Array.isArray(value) ? value.map(deserialize) : deserialize(String(value));
  popupOpen.value = true;
}

async function reloadEntryDetail() {
  if (!props.baseDn || !props.connectionId) return;
  entryDetailLoading.value = true;
  try {
    const [result, config] = await Promise.all([api.ldapSearch(props.connectionId, props.baseDn, "(objectClass=*)", "base"), getOrFetchLdapConfig()]);
    entryDetail.value = result.entries.length > 0 ? result.entries[0] : null;
    ldapConfig.value = config;
  } catch (_e: unknown) {
    entryDetail.value = null;
  } finally {
    entryDetailLoading.value = false;
  }
}

function followTabDn(newDn: string) {
  // The tab's base DN must follow the renamed entry, otherwise the panel
  // would reload a DN that no longer exists.
  const oldDn = props.baseDn;
  const tab = queryStore.tabs.find((tab) => tab.connectionId === props.connectionId && tab.mode === "ldap" && tab.database === oldDn);
  if (tab) {
    tab.database = newDn;
    tab.title = `${newDn.split(",")[0] ?? newDn} - ${connectionStore.getConfig(props.connectionId)?.name || "LDAP"}`;
  }
  entryDetail.value = null;
}

function onEntryRenamed(newDn: string) {
  followTabDn(newDn);
}

function onEntrySaved(newDn: string) {
  // An edit can rename the entry when the RDN attribute's value changed.
  if (newDn && newDn !== props.baseDn) {
    followTabDn(newDn);
  } else {
    reloadEntryDetail();
  }
}

async function deleteEntry() {
  if (!props.baseDn || deleting.value) return;
  deleting.value = true;
  try {
    await api.ldapDelete(props.connectionId, props.baseDn);
    toast(t("ldap.writeSuccess"), 2500);
    // Close the LDAP browser tab for the deleted entry.
    const tab = queryStore.tabs.find((tab) => tab.connectionId === props.connectionId && tab.mode === "ldap" && tab.database === props.baseDn);
    if (tab) queryStore.closeTab(tab.id);
    entryDetail.value = null;
  } catch (e: unknown) {
    toast(e instanceof Error ? e.message : String(e), 5000);
  } finally {
    deleting.value = false;
    showDeleteDialog.value = false;
  }
}

watch(
  () => props.baseDn,
  async (dn) => {
    if (!dn || !props.connectionId) {
      entryDetail.value = null;
      return;
    }
    await reloadEntryDetail();
  },
  { immediate: true },
);

defineExpose({ refresh: reloadEntryDetail });
</script>
