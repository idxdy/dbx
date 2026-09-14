<template>
  <div class="flex flex-col h-full">
    <!-- Search toolbar -->
    <div class="flex flex-col shrink-0 border-b border-border">
      <div class="flex items-center gap-2 px-3 py-1.5">
        <span class="text-xs text-muted-foreground shrink-0">Base DN:</span>
        <Input v-model="searchBaseDn" class="h-7 flex-1 min-w-0 text-xs font-mono" placeholder="DC=corp,DC=int,DC=kn" @keydown.enter="executeSearch" />
        <span class="text-xs text-muted-foreground shrink-0">Scope:</span>
        <select v-model="scope" class="h-7 rounded border border-border bg-background px-2 text-xs">
          <option value="base">base</option>
          <option value="one">one</option>
          <option value="sub">sub</option>
        </select>
        <Button size="sm" variant="secondary" class="h-7 px-2" @click="executeSearch" :disabled="loading">
          <Search class="size-3.5" />
        </Button>
        <span v-if="resultCount > 0" class="text-xs text-muted-foreground tabular-nums">{{ resultCount }} results</span>
      </div>
      <div class="flex items-center gap-2 px-3 pb-1.5">
        <span class="text-xs text-muted-foreground shrink-0">Filter:</span>
        <Input v-model="filter" class="h-7 flex-1 min-w-0 text-xs font-mono" placeholder="(objectClass=*)" @keydown.enter="executeSearch" />
        <span class="text-xs text-muted-foreground shrink-0">Attrs:</span>
        <Input v-model="attributes" class="h-7 w-40 text-xs" placeholder="* (comma separated)" />
        <span class="text-xs text-muted-foreground shrink-0">Limit:</span>
        <Input v-model.number="sizeLimit" type="number" class="h-7 w-20 text-xs" min="1" />
      </div>
      <div class="flex items-center gap-2 px-3 pb-1.5 shrink-0">
        <Button size="sm" variant="secondary" class="h-7 px-2" @click="executeSearch" :disabled="loading" title="Refresh">
          <Loader2 v-if="loading" class="size-3.5 animate-spin" />
          <RefreshCw v-else class="size-3.5" />
        </Button>
        <span class="text-xs text-muted-foreground shrink-0">Copy as:</span>
        <Button variant="outline" size="sm" class="h-7 px-2 text-xs font-mono" :disabled="!searchBaseDn" @click="copyAsLdapSearch"> <Copy class="size-3.5 mr-1" />ldapsearch </Button>
        <Button variant="outline" size="sm" class="h-7 px-2 text-xs font-mono" :disabled="!searchBaseDn" @click="copyAsPowershellGetAdObject"> <Copy class="size-3.5 mr-1" />Get-ADObject </Button>
        <span v-if="toastCopied" class="text-xs text-green-600 dark:text-green-400">Copied</span>
        <span v-if="selectedResult" class="ml-2 text-xs text-muted-foreground shrink-0">Selected entry:</span>
        <Button v-if="selectedResult" variant="outline" size="sm" class="h-7 px-2 text-xs font-mono" @click="copySelectedAsLdapSearch"> <Copy class="size-3.5 mr-1" />ldapsearch by DN </Button>
        <Button v-if="selectedResult" variant="outline" size="sm" class="h-7 px-2 text-xs font-mono" @click="copySelectedAsPowershellGetAdObject"> <Copy class="size-3.5 mr-1" />Get-ADObject -Identity </Button>
      </div>
    </div>

    <!-- Results -->
    <div class="flex flex-1 min-h-0">
      <!-- Result list -->
      <div class="w-80 border-r border-border flex flex-col min-h-0 shrink-0">
        <div v-if="loading" class="flex items-center justify-center py-8">
          <Loader2 class="size-5 animate-spin text-muted-foreground" />
        </div>
        <div v-else-if="entries.length === 0" class="flex-1" />
        <div v-else class="flex-1 overflow-auto">
          <div v-for="entry in entries" :key="entry.dn" class="flex items-center h-7 px-3 cursor-pointer hover:bg-accent text-sm select-none gap-1.5" :class="{ 'bg-accent': selectedDn === entry.dn }" @click="selectedDn = entry.dn">
            <FileText class="size-3.5 text-blue-500 shrink-0" />
            <span class="truncate text-xs">{{ entry.dn ? entry.dn.split(",")[0] : "Root DSE" }}</span>
          </div>
        </div>
      </div>

      <!-- Detail panel -->
      <div class="flex-1 min-w-0 overflow-auto p-4">
        <div v-if="!selectedResult" class="flex flex-col items-center justify-center h-full text-muted-foreground gap-2">
          <FileSearch class="size-10 opacity-20" />
          <p class="text-sm">Search or select an entry to view attributes</p>
        </div>
        <div v-else class="space-y-4">
          <div>
            <div class="flex items-center justify-between gap-2 mb-1">
              <h3 class="text-sm font-semibold">DN</h3>
              <div class="flex items-center gap-1.5">
                <Button variant="outline" size="sm" class="h-6 px-2 text-xs" @click="openSelectedInBrowser"> <ExternalLink class="size-3 mr-1" />{{ t("ldap.openInBrowser") }} </Button>
                <Button variant="outline" size="sm" class="h-6 px-2 text-xs text-destructive hover:text-destructive" :disabled="readOnly" @click="showDeleteDialog = true"> <Trash2 class="size-3 mr-1" />{{ t("ldap.deleteEntry") }} </Button>
              </div>
            </div>
            <p class="text-sm font-mono bg-muted rounded px-2 py-1 break-all">{{ selectedResult.dn }}</p>
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
                  <tr v-for="(value, name) in selectedResult.attributes" :key="name" class="hover:bg-muted/30">
                    <td class="px-3 py-1 font-mono text-xs whitespace-nowrap align-top">{{ name }}</td>
                    <td class="px-3 py-1 font-mono text-xs max-w-md">
                      <template v-if="isDnAttribute(name) && dnValues(value).length > 0">
                        <div v-for="(v, i) in dnValues(value)" :key="i">
                          <span class="cursor-pointer text-primary hover:underline" :title="t('ldap.openDnTooltip')" @click="openDnInBrowser(v)">{{ v }}</span>
                        </div>
                      </template>
                      <span v-else :class="{ 'cursor-pointer hover:text-primary hover:underline': isLongValue(value) }" @click="isLongValue(value) && openValuePopup(name, value)">{{ formatCellValue(value) }}</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
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
            <div v-for="(v, i) in popupValues" :key="i" class="py-1 px-2 rounded text-xs font-mono break-all hover:bg-muted/50">
              {{ v }}
            </div>
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
    <DangerConfirmDialog v-model:open="showDeleteDialog" :title="t('ldap.deleteTitle')" :message="t('ldap.deleteConfirmMessage')" :details="selectedResult?.dn" :confirm-label="t('ldap.deleteEntry')" :loading="deleting" @confirm="deleteSelected" />
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from "vue";
import { Search, Loader2, FileText, FileSearch, X, Copy, ExternalLink, Trash2, RefreshCw } from "@lucide/vue";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useI18n } from "vue-i18n";
import * as api from "@/lib/backend/api";
import { useConnectionStore } from "@/stores/connectionStore";
import { useQueryStore } from "@/stores/queryStore";
import { useToast } from "@/composables/useToast";
import { copyToClipboard } from "@/lib/common/clipboard";
import { buildGetAdObjectCommand, buildGetAdObjectIdentityCommand, buildLdapSearchByDnCommand, buildLdapSearchCommand, parseScope } from "@/lib/ldap/ldapSearchSyntax";
import { isLdapDnAttribute, looksLikeLdapDn } from "@/lib/ldap/ldapSchema";
import DangerConfirmDialog from "@/components/editor/DangerConfirmDialog.vue";

const { t } = useI18n();
const { toast } = useToast();

const props = defineProps<{
  connectionId: string;
}>();

const connectionStore = useConnectionStore();
const queryStore = useQueryStore();
const config = computed(() => connectionStore.getConfig(props.connectionId));
const readOnly = computed(() => Boolean((config.value as any)?.read_only));

const showDeleteDialog = ref(false);
const deleting = ref(false);

/** Open the given entry in the LDAP browser tab, where the inline editor lives. */
function openDnInBrowser(dn: string) {
  if (!dn) return;
  const existingTab = queryStore.tabs.find((tab) => tab.connectionId === props.connectionId && tab.mode === "ldap" && tab.database === dn);
  if (existingTab) {
    queryStore.switchTab(existingTab.id);
  } else {
    queryStore.createTab(props.connectionId, dn, `${dn.split(",")[0] ?? dn} - ${config.value?.name || "LDAP"}`, "ldap");
  }
}

function openSelectedInBrowser() {
  const dn = selectedResult.value?.dn;
  if (dn) openDnInBrowser(dn);
}

async function deleteSelected() {
  const dn = selectedResult.value?.dn;
  if (!dn || deleting.value) return;
  deleting.value = true;
  try {
    await api.ldapDelete(props.connectionId, dn);
    toast(t("ldap.writeSuccess"), 2500);
    entries.value = entries.value.filter((entry) => entry.dn !== dn);
    selectedDn.value = "";
  } catch (e: unknown) {
    toast(e instanceof Error ? e.message : String(e), 5000);
  } finally {
    deleting.value = false;
    showDeleteDialog.value = false;
  }
}

const searchBaseDn = ref((config.value as any)?.ldap_base_dn ?? "");
const scope = ref("sub");
const filter = ref("(objectClass=*)");
const attributes = ref("");
const sizeLimit = ref(100);
const loading = ref(false);
const selectedDn = ref<string>("");

interface SearchEntry {
  dn: string;
  attributes: Record<string, string | string[]>;
}
const entries = ref<SearchEntry[]>([]);
const resultCount = computed(() => entries.value.length);

const selectedResult = computed(() => {
  if (!selectedDn.value) return null;
  return entries.value.find((e) => e.dn === selectedDn.value) ?? null;
});

// Popup
const popupOpen = ref(false);
const popupAttrName = ref("");
const popupValues = ref<string | string[]>("");

function isLongValue(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 1 || (value.length === 1 && String(value[0]).length > 120);
  return String(value).length > 120;
}

/** DN-valued attributes (member/memberOf/…) render each value as a link. */
function isDnAttribute(name: string): boolean {
  return isLdapDnAttribute(name);
}

function dnValues(value: unknown): string[] {
  const list = Array.isArray(value) ? value.map(String) : [String(value)];
  return list.filter((v) => looksLikeLdapDn(v));
}

function formatCellValue(value: unknown): string {
  if (Array.isArray(value)) {
    const joined = value.join(", ");
    return joined.length <= 120 ? joined : joined.slice(0, 117) + "...";
  }
  const str = String(value);
  return str.length <= 120 ? str : str.slice(0, 117) + "...";
}

function openValuePopup(name: string, value: unknown) {
  popupAttrName.value = name;
  popupValues.value = Array.isArray(value) ? value : String(value);
  popupOpen.value = true;
}

async function executeSearch() {
  if (!props.connectionId) return;
  loading.value = true;
  try {
    const baseDn = searchBaseDn.value.trim();
    // An empty base DN targets the Root DSE, which is only reachable at
    // base scope — mirror `ldapsearch -b "" -s base` instead of erroring.
    const effectiveScope = baseDn ? scope.value : "base";
    const attrList = attributes.value.trim()
      ? attributes.value
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean)
      : undefined;
    const result = await api.ldapSearch(props.connectionId, baseDn, filter.value || "(objectClass=*)", effectiveScope, attrList, sizeLimit.value || undefined);
    entries.value = result.entries.map((e: { dn: string; attributes: Record<string, string | string[]> }) => ({
      dn: e.dn,
      attributes: e.attributes,
    }));
    selectedDn.value = "";
  } catch (_e: unknown) {
    entries.value = [];
  } finally {
    loading.value = false;
  }
}

const toastCopied = ref(false);
let toastTimer: number | null = null;
function flashCopiedToast() {
  toastCopied.value = true;
  if (toastTimer !== null) clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    toastCopied.value = false;
  }, 1500);
}

const parsedAttributeList = computed(() =>
  attributes.value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0),
);

async function copyAsLdapSearch() {
  const cmd = buildLdapSearchCommand({
    baseDn: searchBaseDn.value,
    scope: parseScope(scope.value),
    filter: filter.value,
    attributes: parsedAttributeList.value,
    sizeLimit: sizeLimit.value,
    host: (config.value as any)?.host || undefined,
    port: (config.value as any)?.port || undefined,
    useTls: !!(config.value as any)?.ssl,
  });
  await copyToClipboard(cmd);
  flashCopiedToast();
}

async function copyAsPowershellGetAdObject() {
  const cmd = buildGetAdObjectCommand({
    baseDn: searchBaseDn.value,
    scope: parseScope(scope.value),
    filter: filter.value,
    attributes: parsedAttributeList.value,
    sizeLimit: sizeLimit.value,
    server: (config.value as any)?.host || undefined,
  });
  await copyToClipboard(cmd);
  flashCopiedToast();
}

async function copySelectedAsLdapSearch() {
  if (!selectedResult.value) return;
  const attrs = Object.keys(selectedResult.value.attributes);
  const cmd = buildLdapSearchByDnCommand(selectedResult.value.dn, (config.value as any)?.host || undefined, (config.value as any)?.port || undefined, !!(config.value as any)?.ssl);
  await copyToClipboard(attrs.length > 0 ? `${cmd} ${attrs.join(" ")}` : cmd);
  flashCopiedToast();
}

async function copySelectedAsPowershellGetAdObject() {
  if (!selectedResult.value) return;
  const cmd = buildGetAdObjectIdentityCommand(selectedResult.value.dn, (config.value as any)?.host || undefined);
  await copyToClipboard(cmd);
  flashCopiedToast();
}
</script>
