import { reactive } from "vue";

/**
 * Shared, framework-free state for the LDAP entry write dialogs mounted in
 * ConnectionTree. The sidebar context menu (SidebarTreeRuntimeHost) opens the
 * dialogs through the `open*` helpers; ConnectionTree renders the dialogs and
 * refreshes the tree after each write. Editing happens inline in the LDAP
 * browser tab (LdapEntryEditorTable), so there is no edit dialog here.
 */
export const ldapEntryDialogState = reactive({
  createOpen: false,
  renameOpen: false,
  deleteOpen: false,
  connectionId: "",
  createParentDn: "",
  renameDn: "",
  deleteDn: "",
});

export function openLdapCreateEntryDialog(connectionId: string, parentDn: string) {
  ldapEntryDialogState.connectionId = connectionId;
  ldapEntryDialogState.createParentDn = parentDn;
  ldapEntryDialogState.createOpen = true;
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
