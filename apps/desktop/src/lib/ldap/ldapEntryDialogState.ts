import { reactive } from "vue";
import * as api from "@/lib/backend/api";

/**
 * Shared, framework-free state for the LDAP entry write dialogs mounted in
 * ConnectionTree. The sidebar context menu (SidebarTreeRuntimeHost) opens the
 * dialogs through the `open*` helpers; ConnectionTree renders the dialogs and
 * refreshes the tree after each write.
 */
export const ldapEntryDialogState = reactive({
  createOpen: false,
  editOpen: false,
  renameOpen: false,
  deleteOpen: false,
  connectionId: "",
  createParentDn: "",
  editEntry: null as { dn: string; attributes: Record<string, string | string[]> } | null,
  renameDn: "",
  deleteDn: "",
});

export function openLdapCreateEntryDialog(connectionId: string, parentDn: string) {
  ldapEntryDialogState.connectionId = connectionId;
  ldapEntryDialogState.createParentDn = parentDn;
  ldapEntryDialogState.createOpen = true;
}

/**
 * Fetch the entry's current attributes (the sidebar only knows the DN) and
 * open the edit dialog. Rejects with the backend error when the entry cannot
 * be read; the caller is responsible for surfacing the failure.
 */
export async function openLdapEditEntryDialog(connectionId: string, dn: string) {
  const result = await api.ldapSearch(connectionId, dn, "(objectClass=*)", "base");
  const entry = result.entries.length > 0 ? result.entries[0] : { dn, attributes: {} };
  ldapEntryDialogState.connectionId = connectionId;
  ldapEntryDialogState.editEntry = entry;
  ldapEntryDialogState.editOpen = true;
}

export function openLdapRenameEntryDialog(connectionId: string, dn: string) {
  ldapEntryDialogState.connectionId = connectionId;
  ldapEntryDialogState.renameDn = dn;
  ldapEntryDialogState.renameOpen = true;
}

export function openLdapDeleteEntryDialog(connectionId: string, dn: string) {
  ldapEntryDialogState.connectionId = connectionId;
  ldapEntryDialogState.deleteDn = dn;
  ldapEntryDialogState.deleteOpen = true;
}
