<template>
  <div class="flex flex-col h-full">
    <!-- Toolbar -->
    <div class="flex items-center gap-2 px-3 py-1.5 border-b border-border shrink-0">
      <span v-if="baseDn" class="text-xs font-mono text-muted-foreground truncate flex-1 min-w-0" :title="baseDn">{{ baseDn }}</span>
      <Badge v-if="readOnly" variant="secondary" class="shrink-0">{{ t("connection.readOnly") }}</Badge>
      <template v-if="baseDn">
        <Button variant="outline" size="sm" class="h-6 px-2 text-xs" :disabled="readOnly" @click="showCreateDialog = true"> <Plus class="size-3 mr-1" />{{ t("ldap.addEntry") }} </Button>
        <Button variant="outline" size="sm" class="h-6 px-2 text-xs" :disabled="readOnly" @click="showRenameDialog = true"> <Replace class="size-3 mr-1" />{{ t("ldap.renameEntry") }} </Button>
        <Button variant="outline" size="sm" class="h-6 px-2 text-xs text-destructive hover:text-destructive" :disabled="readOnly" @click="showDeleteDialog = true"> <Trash2 class="size-3 mr-1" />{{ t("ldap.deleteEntry") }} </Button>
      </template>
      <Button size="sm" variant="secondary" class="h-7 px-2" @click="reloadEntryDetail" :disabled="entryDetailLoading" title="Refresh">
        <Loader2 v-if="entryDetailLoading" class="size-3.5 animate-spin" />
        <RefreshCw v-else class="size-3.5" />
      </Button>
      <Button size="sm" :variant="showOperational ? 'default' : 'secondary'" class="h-7 px-2" :title="t('ldap.showOperational')" @click="toggleOperational">
        <Eye class="size-3.5" />
      </Button>
      <span class="text-xs text-muted-foreground shrink-0">Copy as:</span>
      <Button v-if="baseDn" variant="outline" size="sm" class="h-6 px-2 text-xs font-mono" :title="t('ldap.copyLdapsearchTooltip')" @click="copyAsLdapSearch"> <Copy class="size-3 mr-1" />ldapsearch </Button>
      <Button v-if="baseDn" variant="outline" size="sm" class="h-6 px-2 text-xs font-mono" :title="t('ldap.copyGetAdObjectTooltip')" @click="copyAsPowershellGetAdObject"> <Copy class="size-3 mr-1" />Get-ADObject </Button>
      <span v-if="copiedFlash" class="text-xs text-green-600 dark:text-green-400">Copied</span>
    </div>

    <!-- Detail panel: inline entry editor (immediate commit per value) -->
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
          <p class="text-sm font-mono bg-muted rounded px-2 py-1 break-all">{{ entryDetail.dn || "Root DSE" }}</p>
        </div>
        <div>
          <h3 class="text-sm font-semibold mb-2">Attributes</h3>
          <LdapEntryEditorTable :connection-id="connectionId" :entry="entryDetail" :read-only="readOnly || !entryDetail.dn" :schema="ldapConfig" @entry-changed="reloadEntryDetail" />
        </div>
      </div>
    </div>

    <!-- Write dialogs -->
    <LdapEntryCreateDialog v-model:open="showCreateDialog" :connection-id="connectionId" :parent-dn="baseDn || ''" @created="reloadEntryDetail" />
    <LdapEntryRenameDialog v-model:open="showRenameDialog" :connection-id="connectionId" :dn="baseDn || ''" @renamed="onEntryRenamed" />
    <DangerConfirmDialog v-model:open="showDeleteDialog" :title="t('ldap.deleteTitle')" :message="t('ldap.deleteConfirmMessage')" :details="baseDn" :confirm-label="t('ldap.deleteEntry')" :loading="deleting" @confirm="deleteEntry" />
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { Loader2, FileSearch, Copy, Plus, Trash2, Replace, RefreshCw, Eye } from "@lucide/vue";
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
import type { LdapSchemaConfig } from "@/lib/backend/http";
import DangerConfirmDialog from "@/components/editor/DangerConfirmDialog.vue";
import LdapEntryCreateDialog from "@/components/ldap/LdapEntryCreateDialog.vue";
import LdapEntryRenameDialog from "@/components/ldap/LdapEntryRenameDialog.vue";
import LdapEntryEditorTable from "@/components/ldap/LdapEntryEditorTable.vue";

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
const showRenameDialog = ref(false);
const showDeleteDialog = ref(false);
const deleting = ref(false);

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

async function reloadEntryDetail() {
  if (!props.connectionId) return;
  // An empty base DN shows the Root DSE (read-only; the write buttons are
  // hidden for it).
  entryDetailLoading.value = true;
  try {
    // Operational attributes must be requested explicitly; `+` covers
    // servers implementing RFC 4512, the explicit names cover JNDI-based
    // agents that do not understand the extension.
    const attributes = showOperational.value ? ["*", "+", "createTimestamp", "modifyTimestamp", "creatorsName", "modifiersName", "entryUUID", "entryDN"] : undefined;
    const [result, config] = await Promise.all([api.ldapSearch(props.connectionId, props.baseDn || "", "(objectClass=*)", "base", attributes), getOrFetchLdapConfig(props.connectionId)]);
    entryDetail.value = result.entries.length > 0 ? result.entries[0] : null;
    ldapConfig.value = config;
  } catch (_e: unknown) {
    entryDetail.value = null;
  } finally {
    entryDetailLoading.value = false;
  }
}

const OPERATIONAL_TOGGLE_KEY = "ldap.showOperational";
const showOperational = ref(localStorage.getItem(OPERATIONAL_TOGGLE_KEY) === "1");

function toggleOperational() {
  showOperational.value = !showOperational.value;
  localStorage.setItem(OPERATIONAL_TOGGLE_KEY, showOperational.value ? "1" : "0");
  reloadEntryDetail();
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
    // An empty DN is valid: it shows the Root DSE.
    if (!props.connectionId) {
      entryDetail.value = null;
      return;
    }
    void dn;
    await reloadEntryDetail();
  },
  { immediate: true },
);

defineExpose({ refresh: reloadEntryDetail });
</script>
