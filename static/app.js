const state = {
  currentScreen: "dashboard",
  currentUser: null,
  dashboard: null,
  assets: [],
  people: [],
  assignments: [],
  admins: [],
  lookups: [],
  modal: null,
  activeLookupTargetField: null,
  activeLookupKind: null,
  lookupEditor: null,
  tableTools: {
    assets: { query: "", filter: "all", sort: "updated_desc" },
    people: { query: "", filter: "all", sort: "name_asc" },
    assignments: { query: "", filter: "all", sort: "assigned_desc" },
    admins: { query: "", filter: "all", sort: "name_asc" },
  },
};

const screens = {
  dashboard: document.getElementById("dashboardScreen"),
  assets: document.getElementById("assetsScreen"),
  people: document.getElementById("peopleScreen"),
  assignments: document.getElementById("assignmentsScreen"),
  admins: document.getElementById("adminsScreen"),
};

const labels = {
  dashboard: { title: "Dashboard", eyebrow: "Overview", action: { text: "New Asset", handler: () => openAssetForm() } },
  assets: { title: "Assets", eyebrow: "Hardware register", action: { text: "Add Asset", handler: () => openAssetForm() } },
  people: { title: "Team Members", eyebrow: "Assigned staff and device holders", action: { text: "Add Team Member", handler: () => openPersonForm() } },
  assignments: { title: "Assignments", eyebrow: "Check-in and check-out", action: { text: "Assign Asset", handler: () => openAssignForm() } },
  admins: { title: "Accounts", eyebrow: "Login access and permissions", action: { text: "Add Account", handler: () => openAdminForm() } },
};

const el = {
  loginView: document.getElementById("loginView"),
  appView: document.getElementById("appView"),
  loginForm: document.getElementById("loginForm"),
  loginError: document.getElementById("loginError"),
  logoutBtn: document.getElementById("logoutBtn"),
  changePasswordBtn: document.getElementById("changePasswordBtn"),
  importBtn: document.getElementById("importBtn"),
  exportCsvBtn: document.getElementById("exportCsvBtn"),
  exportPdfBtn: document.getElementById("exportPdfBtn"),
  refreshBtn: document.getElementById("refreshBtn"),
  primaryActionBtn: document.getElementById("primaryActionBtn"),
  importFileInput: document.getElementById("importFileInput"),
  messageBar: document.getElementById("messageBar"),
  screenTitle: document.getElementById("screenTitle"),
  screenEyebrow: document.getElementById("screenEyebrow"),
  currentAdminName: document.getElementById("currentAdminName"),
  formDialog: document.getElementById("formDialog"),
  entityForm: document.getElementById("entityForm"),
  dialogTitle: document.getElementById("dialogTitle"),
  dialogEyebrow: document.getElementById("dialogEyebrow"),
  dialogFields: document.getElementById("dialogFields"),
  closeDialogBtn: document.getElementById("closeDialogBtn"),
  cancelDialogBtn: document.getElementById("cancelDialogBtn"),
  lookupLists: document.getElementById("lookupLists"),
  pickerDialog: document.getElementById("pickerDialog"),
  pickerTitle: document.getElementById("pickerTitle"),
  pickerEyebrow: document.getElementById("pickerEyebrow"),
  pickerBody: document.getElementById("pickerBody"),
  closePickerBtn: document.getElementById("closePickerBtn"),
  pickerCloseActionBtn: document.getElementById("pickerCloseActionBtn"),
};

document.querySelectorAll(".nav-btn").forEach((button) => {
  button.addEventListener("click", () => setScreen(button.dataset.screen));
});

el.loginForm.addEventListener("submit", handleLogin);
el.logoutBtn.addEventListener("click", logout);
el.changePasswordBtn.addEventListener("click", openChangePasswordForm);
el.importBtn.addEventListener("click", triggerImport);
el.exportCsvBtn.addEventListener("click", exportCsv);
el.exportPdfBtn.addEventListener("click", exportPdf);
el.refreshBtn.addEventListener("click", () => loadAll());
if (el.importFileInput) {
  el.importFileInput.addEventListener("change", handleImportFile);
}
el.closeDialogBtn.addEventListener("click", closeEntityModal);
el.cancelDialogBtn.addEventListener("click", closeEntityModal);
el.closePickerBtn.addEventListener("click", closePickerModal);
el.pickerCloseActionBtn.addEventListener("click", closePickerModal);
el.entityForm.addEventListener("submit", submitModal);
el.formDialog.addEventListener("click", handleDialogBackdropClick);
el.pickerDialog.addEventListener("click", handleDialogBackdropClick);
document.addEventListener("click", handlePasswordToggle);
document.addEventListener("keydown", handleGlobalEscape);

boot();

async function boot() {
  try {
    const session = await api("/api/session");
    if (session.user) {
      state.currentUser = session.user;
      showApp();
      await loadAll();
    } else {
      showLogin();
    }
  } catch (error) {
    showLogin();
    flash("Could not restore the previous session. Please sign in again.", true);
  }
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    ...options,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

async function handleLogin(event) {
  event.preventDefault();
  const formData = new FormData(el.loginForm);
  showLoginError("");
  try {
    const result = await api("/api/login", { method: "POST", body: JSON.stringify(Object.fromEntries(formData.entries())) });
    state.currentUser = result.user;
    showApp();
    await loadAll();
    flash("Signed in successfully.");
  } catch (error) {
    showLogin();
    showLoginError(error.message || "Sign-in failed.");
    flash(error.message, true);
  }
}

async function logout() {
  await api("/api/logout", { method: "POST" });
  state.currentUser = null;
  showLogin();
}

function showLogin() {
  el.loginView.classList.remove("hidden");
  el.appView.classList.add("hidden");
}

function showApp() {
  showLoginError("");
  el.loginView.classList.add("hidden");
  el.appView.classList.remove("hidden");
  el.currentAdminName.textContent = state.currentUser?.full_name || "Admin";
  const adminNavButton = document.querySelector('[data-screen="admins"]');
  if (adminNavButton) {
    adminNavButton.classList.toggle("hidden", !canManageAccounts());
  }
  setScreen(state.currentScreen);
}

function canManageAccounts() {
  return ["Super Admin", "Admin"].includes(state.currentUser?.role);
}

function showLoginError(message) {
  if (!el.loginError) return;
  el.loginError.textContent = message || "";
  el.loginError.classList.toggle("hidden", !message);
}

function setScreen(name) {
  if (name === "admins" && !canManageAccounts()) {
    name = "dashboard";
  }
  state.currentScreen = name;
  Object.entries(screens).forEach(([key, node]) => node.classList.toggle("hidden", key !== name));
  document.querySelectorAll(".nav-btn").forEach((button) => button.classList.toggle("active", button.dataset.screen === name));
  const meta = labels[name];
  el.screenTitle.textContent = meta.title;
  el.screenEyebrow.textContent = meta.eyebrow;
  el.primaryActionBtn.textContent = meta.action.text;
  el.primaryActionBtn.onclick = meta.action.handler;
  const importable = ["assets", "people", "assignments", "admins"].includes(name) && (name !== "admins" || canManageAccounts());
  const exportable = ["assets", "people", "assignments", "admins"].includes(name) && (name !== "admins" || canManageAccounts());
  el.importBtn.classList.toggle("hidden", !importable);
  el.exportCsvBtn.classList.toggle("hidden", !exportable);
  el.exportPdfBtn.classList.toggle("hidden", !exportable);
  el.primaryActionBtn.classList.toggle("hidden", name === "admins" && !canManageAccounts());
}

async function loadAll() {
  try {
    const requests = [
      api("/api/lookups"),
      api("/api/dashboard"),
      api("/api/assets"),
      api("/api/people"),
      api("/api/assignments"),
      canManageAccounts() ? api("/api/admin-users") : Promise.resolve({ items: [] }),
    ];
    const [lookups, dashboard, assets, people, assignments, admins] = await Promise.all(requests);
    state.lookups = lookups.items;
    state.dashboard = dashboard;
    state.assets = assets.items;
    state.people = people.items;
    state.assignments = assignments.items;
    state.admins = admins.items;
    renderLookupLists();
    renderDashboard();
    renderAssets();
    renderPeople();
    renderAssignments();
    renderAdmins();
  } catch (error) {
    flash(error.message, true);
  }
}

function renderLookupLists() {
  const byKind = groupLookups();
  el.lookupLists.innerHTML = Object.keys(byKind).map((kind) =>
    `<datalist id="lookup-${kind}">${(byKind[kind] || []).map((item) => `<option value="${escapeAttribute(item.value)}"></option>`).join("")}</datalist>`
  ).join("");
}

function renderDashboard() {
  const stats = state.dashboard.stats;
  screens.dashboard.innerHTML = `
    <div class="metrics">
      ${metricCard("Total Assets", stats.assets_total)}
      ${metricCard("Assigned", stats.assets_assigned)}
      ${metricCard("Available", stats.assets_available)}
      ${metricCard("In Maintenance", stats.assets_maintenance)}
    </div>
    <div class="two-column">
      <div class="card">
        <div class="section-head"><div><h3>Latest asset changes</h3><p class="muted">Quick look at the devices changing most often.</p></div></div>
        <div class="table-wrap">${simpleTable(["Asset", "Status", "Holder"], state.dashboard.recent_assets.map((item) => [
          `${item.asset_tag}<br><span class="muted">${item.device_name}</span>`,
          statusPill(item.status),
          item.holder_name || "Unassigned",
        ]))}</div>
      </div>
      <div class="card">
        <div class="section-head"><div><h3>Recent assignment history</h3><p class="muted">Who received devices and what came back.</p></div></div>
        <div class="activity-list">
          ${state.dashboard.recent_activity.map((item) => `
            <div class="activity-item">
              <strong>${item.asset_tag}</strong>
              <div>${item.full_name}</div>
              <div class="muted">${item.returned_at ? `Returned on ${formatDate(item.returned_at)}` : `Assigned on ${formatDate(item.assigned_at)}`}</div>
            </div>
          `).join("") || `<div class="muted">No activity yet.</div>`}
        </div>
      </div>
    </div>
  `;
}

function renderAssets() {
  const tools = state.tableTools.assets;
  const items = sortAssets(filterAssets(state.assets, tools), tools.sort);
  screens.assets.innerHTML = `
    ${renderDataToolbar("assets", "Search asset tag, device, category, brand, model, holder", [
      { value: "all", label: "All Statuses" },
      ...uniqueOptions(state.assets.map((item) => item.status)),
    ], [
      { value: "updated_desc", label: "Newest First" },
      { value: "updated_asc", label: "Oldest First" },
      { value: "tag_asc", label: "Asset Tag A-Z" },
      { value: "device_asc", label: "Device A-Z" },
      { value: "status_asc", label: "Status A-Z" },
    ])}
    <div class="table-wrap">${simpleTable(["Asset Tag", "Device", "Category", "Status", "Holder", "Actions"], items.map((asset) => [
    asset.asset_tag,
    `${asset.device_name}<br><span class="muted">${asset.brand || ""} ${asset.model || ""}</span>`,
    asset.category,
    statusPill(asset.status),
    asset.holder_name || "Unassigned",
    actionButtons([
      { label: "Edit", action: `openAssetForm(${asset.id})` },
      asset.status === "Assigned" ? { label: "Return", action: `openReturnForm(${asset.id})` } : { label: "Assign", action: `openAssignForm(${asset.id})` },
      { label: "Delete", action: `deleteAsset(${asset.id})`, danger: true },
    ]),
  ]))}</div>
  `;
}

function renderPeople() {
  const tools = state.tableTools.people;
  const items = sortPeople(filterPeople(state.people, tools), tools.sort);
  screens.people.innerHTML = `
    ${renderDataToolbar("people", "Search name, department, email, phone, location", [
      { value: "all", label: "All Departments" },
      ...uniqueOptions(state.people.map((item) => item.department)),
    ], [
      { value: "name_asc", label: "Name A-Z" },
      { value: "name_desc", label: "Name Z-A" },
      { value: "department_asc", label: "Department A-Z" },
      { value: "assigned_desc", label: "Most Assigned" },
      { value: "assigned_asc", label: "Least Assigned" },
    ])}
    <div class="table-wrap">${simpleTable(["Name", "Department", "Contact", "Assigned", "Actions"], items.map((person) => [
    `${person.full_name}<br><span class="muted">${person.location || "No location"}</span>`,
    person.department,
    `${person.email || "-"}<br><span class="muted">${person.phone || ""}</span>`,
    `${person.assigned_assets} asset(s)`,
    actionButtons([
      { label: "Edit", action: `openPersonForm(${person.id})` },
      { label: "Delete", action: `deletePerson(${person.id})`, danger: true },
    ]),
  ]))}</div>
  `;
}

function renderAssignments() {
  const tools = state.tableTools.assignments;
  const items = sortAssignments(filterAssignments(state.assignments, tools), tools.sort);
  screens.assignments.innerHTML = `
    ${renderDataToolbar("assignments", "Search asset, device, assigned user, or admin", [
      { value: "all", label: "All Statuses" },
      { value: "open", label: "Open Only" },
      { value: "returned", label: "Returned Only" },
    ], [
      { value: "assigned_desc", label: "Newest First" },
      { value: "assigned_asc", label: "Oldest First" },
      { value: "asset_asc", label: "Asset A-Z" },
      { value: "person_asc", label: "Assigned To A-Z" },
    ])}
    <div class="card">
      <div class="section-head">
        <div><h3>Assignment controls</h3><p class="muted">Use these records to know who has which device and when it was returned.</p></div>
      </div>
      <div class="table-wrap">${simpleTable(["Asset", "Assigned To", "Assigned By", "Assigned At", "Status"], items.map((item) => [
        `${item.asset_tag}<br><span class="muted">${item.device_name}</span>`,
        item.person_name,
        item.admin_name,
        formatDate(item.assigned_at),
        item.returned_at ? `Returned<br><span class="muted">${formatDate(item.returned_at)}</span>` : `<button class="ghost-btn" onclick="openReturnForm(${item.asset_id})">Return Asset</button>`,
      ]))}</div>
    </div>
  `;
}

function renderAdmins() {
  const tools = state.tableTools.admins;
  const items = sortAdmins(filterAdmins(state.admins, tools), tools.sort);
  screens.admins.innerHTML = `
    ${renderDataToolbar("admins", "Search name, username, or role", [
      { value: "all", label: "All Roles" },
      ...uniqueOptions(state.admins.map((item) => item.role)),
    ], [
      { value: "name_asc", label: "Name A-Z" },
      { value: "name_desc", label: "Name Z-A" },
      { value: "username_asc", label: "Username A-Z" },
      { value: "role_asc", label: "Role A-Z" },
      { value: "active_first", label: "Active First" },
    ])}
    <div class="table-wrap">${simpleTable(["Name", "Username", "Role", "Status", "Actions"], items.map((admin) => [
    admin.full_name,
    admin.username,
    admin.role,
    admin.is_active ? `<span class="pill available">Active</span>` : `<span class="pill maintenance">Inactive</span>`,
    actionButtons([
      { label: "Edit", action: `openAdminForm(${admin.id})` },
      { label: "Delete", action: `deleteAdmin(${admin.id})`, danger: true },
    ]),
  ]))}</div>
  `;
}

function metricCard(label, value) { return `<div class="metric-card"><div class="eyebrow">${label}</div><strong>${value}</strong></div>`; }

function simpleTable(headers, rows) {
  return `<table><thead><tr>${headers.map((header) => `<th>${header}</th>`).join("")}</tr></thead><tbody>${rows.map((columns) => `<tr>${columns.map((column) => `<td>${column}</td>`).join("")}</tr>`).join("") || `<tr><td colspan="${headers.length}" class="muted">No records found.</td></tr>`}</tbody></table>`;
}

function statusPill(status) { return `<span class="pill ${status.toLowerCase()}">${status}</span>`; }

function actionButtons(actions) {
  return `<div class="table-actions">${actions.map((item) => `<button class="${item.danger ? "danger-btn" : "ghost-btn"}" onclick="${item.action}">${item.label}</button>`).join("")}</div>`;
}

function renderDataToolbar(screen, placeholder, filterOptions, sortOptions) {
  const tools = state.tableTools[screen];
  return `
    <div class="data-toolbar card">
      <div class="toolbar-field toolbar-search">
        <span>Search</span>
        <div class="search-input-wrap">
          <input type="text" data-table-query="${screen}" value="${escapeAttribute(tools.query)}" placeholder="${escapeAttribute(placeholder)}" oninput="updateTableQuery('${screen}', this.value, this.selectionStart, this.selectionEnd)">
          ${tools.query ? `<button type="button" class="search-clear-btn" onclick="clearTableQuery('${screen}')" aria-label="Clear search" title="Clear search">x</button>` : ""}
        </div>
      </div>
      <div class="toolbar-field">
        <span>Filter</span>
        <select onchange="updateTableFilter('${screen}', this.value)">
          ${filterOptions.map((option) => `<option value="${escapeAttribute(option.value)}" ${option.value === tools.filter ? "selected" : ""}>${escapeHtml(option.label)}</option>`).join("")}
        </select>
      </div>
      <div class="toolbar-field">
        <span>Sort</span>
        <select onchange="updateTableSort('${screen}', this.value)">
          ${sortOptions.map((option) => `<option value="${escapeAttribute(option.value)}" ${option.value === tools.sort ? "selected" : ""}>${escapeHtml(option.label)}</option>`).join("")}
        </select>
      </div>
    </div>
  `;
}

function uniqueOptions(values) {
  return Array.from(new Set(values.filter(Boolean))).sort((a, b) => String(a).localeCompare(String(b))).map((value) => ({ value, label: value }));
}

function textIncludes(haystack, needle) {
  return String(haystack || "").toLowerCase().includes(String(needle || "").trim().toLowerCase());
}

function filterAssets(items, tools) {
  return items.filter((item) => {
    const matchesQuery = !tools.query || [
      item.asset_tag, item.device_name, item.category, item.brand, item.model, item.holder_name, item.location,
    ].some((value) => textIncludes(value, tools.query));
    const matchesFilter = tools.filter === "all" || item.status === tools.filter;
    return matchesQuery && matchesFilter;
  });
}

function sortAssets(items, sort) {
  return [...items].sort((a, b) => {
    if (sort === "updated_asc") return String(a.updated_at || "").localeCompare(String(b.updated_at || ""));
    if (sort === "tag_asc") return String(a.asset_tag || "").localeCompare(String(b.asset_tag || ""));
    if (sort === "device_asc") return String(a.device_name || "").localeCompare(String(b.device_name || ""));
    if (sort === "status_asc") return String(a.status || "").localeCompare(String(b.status || ""));
    return String(b.updated_at || "").localeCompare(String(a.updated_at || ""));
  });
}

function filterPeople(items, tools) {
  return items.filter((item) => {
    const matchesQuery = !tools.query || [
      item.full_name, item.department, item.email, item.phone, item.location,
    ].some((value) => textIncludes(value, tools.query));
    const matchesFilter = tools.filter === "all" || item.department === tools.filter;
    return matchesQuery && matchesFilter;
  });
}

function sortPeople(items, sort) {
  return [...items].sort((a, b) => {
    if (sort === "name_desc") return String(b.full_name || "").localeCompare(String(a.full_name || ""));
    if (sort === "department_asc") return String(a.department || "").localeCompare(String(b.department || ""));
    if (sort === "assigned_desc") return Number(b.assigned_assets || 0) - Number(a.assigned_assets || 0);
    if (sort === "assigned_asc") return Number(a.assigned_assets || 0) - Number(b.assigned_assets || 0);
    return String(a.full_name || "").localeCompare(String(b.full_name || ""));
  });
}

function filterAssignments(items, tools) {
  return items.filter((item) => {
    const matchesQuery = !tools.query || [
      item.asset_tag, item.device_name, item.person_name, item.admin_name,
    ].some((value) => textIncludes(value, tools.query));
    const status = item.returned_at ? "returned" : "open";
    const matchesFilter = tools.filter === "all" || status === tools.filter;
    return matchesQuery && matchesFilter;
  });
}

function sortAssignments(items, sort) {
  return [...items].sort((a, b) => {
    if (sort === "assigned_asc") return String(a.assigned_at || "").localeCompare(String(b.assigned_at || ""));
    if (sort === "asset_asc") return String(a.asset_tag || "").localeCompare(String(b.asset_tag || ""));
    if (sort === "person_asc") return String(a.person_name || "").localeCompare(String(b.person_name || ""));
    return String(b.assigned_at || "").localeCompare(String(a.assigned_at || ""));
  });
}

function filterAdmins(items, tools) {
  return items.filter((item) => {
    const matchesQuery = !tools.query || [
      item.full_name, item.username, item.role,
    ].some((value) => textIncludes(value, tools.query));
    const matchesFilter = tools.filter === "all" || item.role === tools.filter;
    return matchesQuery && matchesFilter;
  });
}

function sortAdmins(items, sort) {
  return [...items].sort((a, b) => {
    if (sort === "name_desc") return String(b.full_name || "").localeCompare(String(a.full_name || ""));
    if (sort === "username_asc") return String(a.username || "").localeCompare(String(b.username || ""));
    if (sort === "role_asc") return String(a.role || "").localeCompare(String(b.role || ""));
    if (sort === "active_first") return Number(b.is_active) - Number(a.is_active) || String(a.full_name || "").localeCompare(String(b.full_name || ""));
    return String(a.full_name || "").localeCompare(String(b.full_name || ""));
  });
}

function rerenderCurrentScreen() {
  if (state.currentScreen === "assets") return renderAssets();
  if (state.currentScreen === "people") return renderPeople();
  if (state.currentScreen === "assignments") return renderAssignments();
  if (state.currentScreen === "admins") return renderAdmins();
}

function restoreTableQueryFocus(screen, selectionStart = null, selectionEnd = null) {
  const input = document.querySelector(`[data-table-query="${screen}"]`);
  if (!input) return;
  input.focus();
  if (selectionStart !== null && selectionEnd !== null) {
    input.setSelectionRange(selectionStart, selectionEnd);
  }
}

function updateTableQuery(screen, value, selectionStart = null, selectionEnd = null) {
  state.tableTools[screen].query = value;
  rerenderCurrentScreen();
  restoreTableQueryFocus(screen, selectionStart, selectionEnd);
}

function clearTableQuery(screen) {
  state.tableTools[screen].query = "";
  rerenderCurrentScreen();
  restoreTableQueryFocus(screen, 0, 0);
}

function updateTableFilter(screen, value) {
  state.tableTools[screen].filter = value;
  rerenderCurrentScreen();
}

function updateTableSort(screen, value) {
  state.tableTools[screen].sort = value;
  rerenderCurrentScreen();
}

function groupLookups() {
  return state.lookups.reduce((acc, item) => {
    if (!acc[item.kind]) acc[item.kind] = [];
    acc[item.kind].push(item);
    return acc;
  }, {});
}

function labelForLookupKind(kind) {
  const labels = {
    category: "Categories",
    device_name: "Device Names",
    brand: "Brands",
    model: "Models",
    location: "Asset Locations",
    status: "Statuses",
    condition: "Conditions",
    department: "Departments",
    person_location: "User Locations",
    role: "Admin Roles",
  };
  return labels[kind] || kind;
}

function addLabelForLookupKind(kind) {
  const labels = {
    category: "Category",
    device_name: "Device Name",
    brand: "Brand",
    model: "Model",
    location: "Location",
    status: "Status",
    condition: "Condition",
    department: "Department",
    person_location: "Location",
    role: "Role",
  };
  return labels[kind] || "Value";
}

function lookupField(name, label, value, kind, options = {}) {
  return {
    label,
    name,
    value,
    list: `lookup-${kind}`,
    manageAction: `openLookupManager('${kind}', '${name}')`,
    manageLabel: "&#9998;",
    manageTitle: `Manage ${labelForLookupKind(kind)}`,
    ...options,
  };
}

function roleOptions() {
  const saved = state.lookups
    .filter((item) => item.kind === "role")
    .map((item) => item.value)
    .filter(Boolean);
  const merged = Array.from(new Set(["Super Admin", "Admin", "User", ...saved]));
  return merged.map((value) => ({ value, label: value }));
}

function formatDate(value) {
  if (!value) return "-";
  return new Date(value.replace(" ", "T") + "Z").toLocaleString();
}

function exportEntityForScreen() {
  return ["assets", "people", "assignments", "admins"].includes(state.currentScreen)
    ? state.currentScreen
    : "assets";
}

async function exportCsv() {
  const entity = exportEntityForScreen();
  try {
    const response = await fetch(`/api/export?entity=${encodeURIComponent(entity)}`, {
      credentials: "same-origin",
    });
    if (!response.ok) {
      const data = await response.json();
      throw new Error(data.error || "Export failed");
    }
    const blob = await response.blob();
    const saved = await saveBlob(blob, `${entity}.csv`, "text/csv");
    flash(saved ? `Exported ${entity}.csv` : "Export cancelled.");
  } catch (error) {
    flash(error.message, true);
  }
}

async function exportPdf() {
  const entity = exportEntityForScreen();
  try {
    const response = await fetch(`/api/export-pdf?entity=${encodeURIComponent(entity)}`, {
      credentials: "same-origin",
    });
    if (!response.ok) {
      const data = await response.json();
      throw new Error(data.error || "PDF export failed");
    }
    const blob = await response.blob();
    const saved = await saveBlob(blob, `${entity}.pdf`, "application/pdf");
    flash(saved ? `Exported ${entity}.pdf` : "Export cancelled.");
  } catch (error) {
    flash(error.message, true);
  }
}

async function triggerImport() {
  try {
    if (window.pywebview?.api?.open_csv_file) {
      const file = await window.pywebview.api.open_csv_file();
      if (!file) return;
      await importCsvPayload(file.name, file.text);
      return;
    }
    if (window.showOpenFilePicker) {
      const [handle] = await window.showOpenFilePicker({
        multiple: false,
        types: [{
          description: "CSV files",
          accept: { "text/csv": [".csv"] },
        }],
      });
      if (!handle) return;
      const file = await handle.getFile();
      await importCsvFile(file);
      return;
    }
  } catch (error) {
    if (error?.name !== "AbortError") {
      flash("Falling back to browser file picker.", true);
    }
  }
  el.importFileInput.value = "";
  el.importFileInput.click();
}

async function handleImportFile(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  await importCsvFile(file);
}

async function importCsvFile(file) {
  const csvText = await file.text();
  await importCsvPayload(file.name, csvText);
}

async function importCsvPayload(fileName, csvText) {
  const entity = exportEntityForScreen();
  try {
    const result = await api(`/api/import?entity=${encodeURIComponent(entity)}`, {
      method: "POST",
      body: JSON.stringify({ csv_text: csvText }),
    });
    await loadAll();
    flash(`Imported ${result.imported} ${entity} record(s) from ${fileName}.`);
  } catch (error) {
    flash(error.message, true);
  }
}

async function saveBlob(blob, filename, mimeType) {
  if (window.pywebview?.api?.save_file) {
    const base64 = arrayBufferToBase64(await blob.arrayBuffer());
    const savedPath = await window.pywebview.api.save_file(filename, base64);
    return Boolean(savedPath);
  }
  if (window.showSaveFilePicker) {
    const handle = await window.showSaveFilePicker({
      suggestedName: filename,
      types: [{
        description: mimeType === "text/csv" ? "CSV file" : "File",
        accept: { [mimeType]: [filename.endsWith(".csv") ? ".csv" : ""] },
      }],
    });
    const writable = await handle.createWritable();
    await writable.write(blob);
    await writable.close();
    return true;
  }
  downloadBlob(blob, filename);
  return true;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function flash(message, isError = false) {
  el.messageBar.classList.remove("hidden");
  el.messageBar.textContent = message;
  el.messageBar.style.background = isError ? "#b91c1c" : "#0f766e";
  el.messageBar.style.color = "#ffffff";
  el.messageBar.style.borderColor = isError ? "#991b1b" : "#0b5f59";
  clearTimeout(flash._timer);
  flash._timer = setTimeout(() => el.messageBar.classList.add("hidden"), 3200);
}

function closeEntityModal() {
  state.modal = null;
  el.formDialog.classList.add("hidden");
}

function closePickerModal() {
  el.pickerDialog.classList.add("hidden");
}

function handleDialogBackdropClick(event) {
  if (event.target !== event.currentTarget) {
    return;
  }
  if (event.currentTarget === el.formDialog) {
    closeEntityModal();
  } else if (event.currentTarget === el.pickerDialog) {
    closePickerModal();
  }
}

function handleGlobalEscape(event) {
  if (event.key !== "Escape") return;
  if (!el.formDialog.classList.contains("hidden")) {
    closeEntityModal();
  } else if (!el.pickerDialog.classList.contains("hidden")) {
    closePickerModal();
  }
}

function openModal(config) {
  state.modal = config;
  el.dialogTitle.textContent = config.title;
  el.dialogEyebrow.textContent = config.eyebrow;
  el.dialogFields.innerHTML = config.fields.map(renderField).join("");
  el.formDialog.classList.remove("hidden");
}

function renderField(field) {
  const cls = field.full ? "full-span" : "";
  const value = field.value ?? "";
  if (field.type === "textarea") return `<label class="${cls}"><span>${field.label}</span><textarea name="${field.name}" ${field.required ? "required" : ""}>${escapeHtml(value)}</textarea></label>`;
  if (field.type === "select") {
    const selectHtml = `<label><span>${field.label}</span><select name="${field.name}" ${field.required ? "required" : ""}>${field.options.map((option) => `<option value="${escapeAttribute(option.value ?? option)}" ${String(option.value ?? option) === String(value) ? "selected" : ""}>${escapeHtml(option.label ?? option)}</option>`).join("")}</select></label>`;
    if (field.manageAction) {
      return `<div class="${cls} field-with-tools">${selectHtml}<button type="button" class="ghost-btn mini-tool-btn" onclick="${field.manageAction}" title="${escapeAttribute(field.manageTitle || "Manage values")}">${field.manageLabel || "&#9998;"}</button></div>`;
    }
    return `<label class="${cls}"><span>${field.label}</span><select name="${field.name}" ${field.required ? "required" : ""}>${field.options.map((option) => `<option value="${escapeAttribute(option.value ?? option)}" ${String(option.value ?? option) === String(value) ? "selected" : ""}>${escapeHtml(option.label ?? option)}</option>`).join("")}</select></label>`;
  }
  if (field.type === "password") {
    const passwordHtml = `<label class="${cls} password-field"><span>${field.label}</span><div class="password-input-wrap"><input type="password" name="${field.name}" value="${escapeAttribute(value)}" ${field.required ? "required" : ""}><button type="button" class="password-toggle" data-password-toggle aria-label="Show password" title="Show password"><span class="password-toggle-icon" aria-hidden="true"></span></button></div></label>`;
    if (field.manageAction) {
      return `<div class="${cls} field-with-tools">${passwordHtml}<button type="button" class="ghost-btn mini-tool-btn" onclick="${field.manageAction}" title="${escapeAttribute(field.manageTitle || "Manage values")}">${field.manageLabel || "&#9998;"}</button></div>`;
    }
    return passwordHtml;
  }
  const inputHtml = `<label><span>${field.label}</span><input type="${field.type || "text"}" name="${field.name}" value="${escapeAttribute(value)}" ${field.required ? "required" : ""} ${field.list ? `list="${field.list}"` : ""}></label>`;
  if (field.manageAction) {
    return `<div class="${cls} field-with-tools">${inputHtml}<button type="button" class="ghost-btn mini-tool-btn" onclick="${field.manageAction}" title="${escapeAttribute(field.manageTitle || "Manage values")}">${field.manageLabel || "&#9998;"}</button></div>`;
  }
  return `<label class="${cls}"><span>${field.label}</span><input type="${field.type || "text"}" name="${field.name}" value="${escapeAttribute(value)}" ${field.required ? "required" : ""} ${field.list ? `list="${field.list}"` : ""}></label>`;
}

function handlePasswordToggle(event) {
  const toggle = event.target.closest("[data-password-toggle]");
  if (!toggle) return;
  const wrap = toggle.closest(".password-input-wrap");
  const input = wrap?.querySelector("input");
  if (!input) return;
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  toggle.classList.toggle("is-visible", show);
  toggle.setAttribute("aria-label", show ? "Hide password" : "Show password");
  toggle.setAttribute("title", show ? "Hide password" : "Show password");
}

async function submitModal(event) {
  event.preventDefault();
  if (!state.modal) return;
  const payload = Object.fromEntries(new FormData(el.entityForm).entries());
  const modalConfig = state.modal;
  try {
    await modalConfig.submit(payload);
    closeEntityModal();
    await loadAll();
    flash(modalConfig.successMessage);
  } catch (error) {
    flash(error.message, true);
  }
}

function openAssetForm(id) {
  const asset = state.assets.find((item) => item.id === id) || {};
  openModal({
    title: id ? "Edit Asset" : "Add Asset",
    eyebrow: id ? "Update record" : "Create record",
    successMessage: id ? "Asset updated." : "Asset created.",
    fields: [
      { label: "Asset Tag", name: "asset_tag", value: asset.asset_tag, required: true },
      lookupField("device_name", "Device Name", asset.device_name, "device_name", { required: true }),
      lookupField("category", "Category", asset.category, "category", { required: true }),
      lookupField("brand", "Brand", asset.brand, "brand"),
      lookupField("model", "Model", asset.model, "model"),
      { label: "Serial Number", name: "serial_number", value: asset.serial_number },
      lookupField("status", "Status", asset.status || "Available", "status", { required: true }),
      lookupField("condition", "Condition", asset.condition || "Good", "condition", { required: true }),
      { label: "Purchase Date", name: "purchase_date", type: "date", value: asset.purchase_date || "" },
      { label: "Warranty End", name: "warranty_end", type: "date", value: asset.warranty_end || "" },
      lookupField("location", "Location", asset.location, "location", { full: true }),
      { label: "Notes", name: "notes", type: "textarea", value: asset.notes, full: true },
    ],
    submit: (payload) => api(id ? `/api/assets/${id}` : "/api/assets", { method: id ? "PUT" : "POST", body: JSON.stringify(payload) }),
  });
}

function openPersonForm(id) {
  const person = state.people.find((item) => item.id === id) || {};
  openModal({
    title: id ? "Edit Team Member" : "Add Team Member",
    eyebrow: id ? "Update profile" : "Create profile",
    successMessage: id ? "Team member updated." : "Team member created.",
    fields: [
      { label: "Full Name", name: "full_name", value: person.full_name, required: true },
      lookupField("department", "Department", person.department, "department", { required: true }),
      { label: "Email", name: "email", value: person.email },
      { label: "Phone", name: "phone", value: person.phone },
      lookupField("location", "Location", person.location, "person_location"),
      { label: "Notes", name: "notes", type: "textarea", value: person.notes, full: true },
    ],
    submit: (payload) => api(id ? `/api/people/${id}` : "/api/people", { method: id ? "PUT" : "POST", body: JSON.stringify(payload) }),
  });
}

function openAdminForm(id) {
  if (!canManageAccounts()) {
    flash("Admin access required.", true);
    return;
  }
  const admin = state.admins.find((item) => item.id === id) || {};
  openModal({
    title: id ? "Edit Account" : "Add Account",
    eyebrow: id ? "Update access" : "Create access",
    successMessage: id ? "Account updated." : "Account created.",
    fields: [
      { label: "Full Name", name: "full_name", value: admin.full_name, required: true },
      { label: "Username", name: "username", value: admin.username, required: true },
      { label: id ? "New Password" : "Password", name: "password", type: "password" },
      {
        label: "Role",
        name: "role",
        type: "select",
        value: admin.role || "Admin",
        options: roleOptions(),
        required: true,
        manageAction: "openLookupManager('role', 'role')",
        manageLabel: "&#9998;",
        manageTitle: "Manage Admin Roles",
      },
      { label: "Active", name: "is_active", type: "select", value: admin.is_active ? "true" : "false", options: [{ value: "true", label: "Active" }, { value: "false", label: "Inactive" }], required: true },
    ],
    submit: (payload) => api(id ? `/api/admin-users/${id}` : "/api/admin-users", { method: id ? "PUT" : "POST", body: JSON.stringify({ ...payload, is_active: payload.is_active === "true" }) }),
  });
}

function openChangePasswordForm() {
  openModal({
    title: "Change Password",
    eyebrow: "My account",
    successMessage: "Password updated.",
    fields: [
      { label: "Current Password", name: "current_password", type: "password", required: true },
      { label: "New Password", name: "new_password", type: "password", required: true },
      { label: "Confirm New Password", name: "confirm_password", type: "password", required: true },
    ],
    submit: async (payload) => {
      if (payload.new_password !== payload.confirm_password) {
        throw new Error("New password confirmation does not match.");
      }
      const result = await api("/api/account/password", {
        method: "POST",
        body: JSON.stringify({
          current_password: payload.current_password,
          new_password: payload.new_password,
        }),
      });
      state.currentUser = result.user;
      return result;
    },
  });
}

function openAssignForm(assetId = null) {
  const availableAssets = state.assets.filter((item) => item.status !== "Assigned");
  if (!availableAssets.length) {
    flash("No available assets to assign.", true);
    return;
  }
  if (!state.people.length) {
    flash("Create a user profile before assigning an asset.", true);
    return;
  }
  const peopleOptions = state.people.map((person) => ({ value: String(person.id), label: `${person.full_name} (${person.department})` }));
  const assetOptions = availableAssets.map((asset) => ({ value: String(asset.id), label: `${asset.asset_tag} - ${asset.device_name}` }));
  openModal({
    title: "Assign Asset",
    eyebrow: "Check-out",
    successMessage: "Asset assigned.",
    fields: [
      { label: "Asset", name: "asset_id", type: "select", value: String(assetId || assetOptions[0]?.value || ""), options: assetOptions, required: true, manageAction: "manageAssignmentAssets()", manageLabel: "&#9998;", manageTitle: "Manage Assets" },
      { label: "User", name: "person_id", type: "select", value: String(peopleOptions[0]?.value || ""), options: peopleOptions, required: true, manageAction: "manageAssignmentPeople()", manageLabel: "&#9998;", manageTitle: "Manage Users" },
      { label: "Notes", name: "notes", type: "textarea", full: true },
    ],
    submit: (payload) => api("/api/assignments/assign", { method: "POST", body: JSON.stringify(payload) }),
  });
}

function openReturnForm(assetId) {
  const asset = state.assets.find((item) => item.id === assetId);
  if (!asset) {
    flash("Asset not found.", true);
    return;
  }
  openModal({
    title: "Return Asset",
    eyebrow: "Check-in",
    successMessage: "Asset returned.",
    fields: [
      { label: "Asset", name: "asset_id", type: "select", value: String(assetId), options: [{ value: String(assetId), label: `${asset.asset_tag} - ${asset.device_name}` }], required: true },
      { label: "Return Notes", name: "return_notes", type: "textarea", full: true },
    ],
    submit: (payload) => api("/api/assignments/return", { method: "POST", body: JSON.stringify(payload) }),
  });
}

async function deleteAsset(id) {
  if (!confirm("Delete this asset?")) return;
  try { await api(`/api/assets/${id}`, { method: "DELETE" }); await loadAll(); flash("Asset deleted."); }
  catch (error) { flash(error.message, true); }
}

async function deletePerson(id) {
  if (!confirm("Delete this user profile?")) return;
  try { await api(`/api/people/${id}`, { method: "DELETE" }); await loadAll(); flash("Team member deleted."); }
  catch (error) { flash(error.message, true); }
}

async function deleteAdmin(id) {
  if (!confirm("Delete this account?")) return;
  try { await api(`/api/admin-users/${id}`, { method: "DELETE" }); await loadAll(); flash("Account deleted."); }
  catch (error) { flash(error.message, true); }
}

function openLookupManager(kind, fieldName = null) {
  state.activeLookupKind = kind;
  state.activeLookupTargetField = fieldName;
  const items = state.lookups.filter((item) => item.kind === kind);
  const usageHeader = kind === "role" ? "Used In Accounts" : "Used In Records";
  const editor = state.lookupEditor && state.lookupEditor.kind === kind ? state.lookupEditor : null;
  openPicker(
    `Manage ${labelForLookupKind(kind)}`,
    "Saved suggestions",
    `
      <div class="picker-inline-actions">
        <button type="button" class="primary-btn" onclick="openLookupInlineForm('${kind}')">${editor ? `Add Another ${addLabelForLookupKind(kind)}` : `Add ${addLabelForLookupKind(kind)}`}</button>
      </div>
      ${editor ? `
        <div class="card">
          <div class="section-head">
            <div>
              <h3>${editor.id ? `Edit ${addLabelForLookupKind(kind)}` : `Add ${addLabelForLookupKind(kind)}`}</h3>
              <p class="muted">This editor stays inside the saved suggestions box.</p>
            </div>
          </div>
          <div class="field-with-tools">
            <label class="full">
              <span>Value</span>
              <input id="lookupInlineValue" type="text" value="${escapeAttribute(editor.value || "")}" required>
            </label>
            <button type="button" class="primary-btn" onclick="saveLookupInline()">${editor.id ? "Save" : "Add"}</button>
            <button type="button" class="ghost-btn" onclick="cancelLookupInlineForm()">Cancel</button>
          </div>
        </div>
      ` : ""}
      <div class="table-wrap">
        ${simpleTable(
          ["Value", usageHeader, "Actions"],
          items.map((item) => [
            item.value,
            `${item.usage_count}`,
            actionButtons([
              ...(fieldName ? [{ label: "Select", action: `selectLookupValue(${item.id})` }] : []),
              { label: "Edit", action: `openLookupInlineForm('${kind}', ${item.id})` },
              { label: "Delete", action: `deleteLookupFromPicker(${item.id})`, danger: true },
            ]),
          ])
        )}
      </div>
    `
  );
}

function openLookupForm(kind, id = null) {
  const item = state.lookups.find((lookup) => lookup.id === id) || {};
  openModal({
    title: id ? `Edit ${addLabelForLookupKind(kind)}` : `Add ${addLabelForLookupKind(kind)}`,
    eyebrow: "Keyword library",
    successMessage: id ? "Keyword updated." : "Keyword saved.",
    fields: [
      { label: "Value", name: "value", value: item.value, required: true, full: true },
    ],
    submit: (payload) => api(id ? `/api/lookups/${id}` : "/api/lookups", {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(id ? payload : { kind, ...payload }),
    }),
  });
}

function editLookupFromPicker(id) {
  const item = state.lookups.find((lookup) => lookup.id === id);
  if (!item) return;
  openLookupInlineForm(item.kind, id);
}

async function deleteLookupFromPicker(id) {
  if (!confirm("Delete this saved keyword?")) return;
  try {
    await api(`/api/lookups/${id}`, { method: "DELETE" });
    await loadAll();
    state.lookupEditor = null;
    if (state.activeLookupKind) {
      openLookupManager(state.activeLookupKind, state.activeLookupTargetField);
    }
    flash("Keyword deleted.");
  } catch (error) {
    flash(error.message, true);
  }
}

function openPicker(title, eyebrow, body) {
  el.pickerTitle.textContent = title;
  el.pickerEyebrow.textContent = eyebrow;
  el.pickerBody.innerHTML = body;
  el.pickerDialog.classList.remove("hidden");
}

function manageAssignmentPeople() {
  openPicker(
    "Manage Team Members",
    "Dropdown CRUD",
    `
      <div class="picker-inline-actions">
        <button type="button" class="primary-btn" onclick="closePickerModal(); openPersonForm();">Add Team Member</button>
      </div>
      <div class="table-wrap">
        ${simpleTable(["Name", "Department", "Assigned", "Actions"], state.people.map((person) => [
          person.full_name,
          person.department,
          `${person.assigned_assets} asset(s)`,
          actionButtons([
            { label: "Edit", action: `editPersonFromPicker(${person.id})` },
            { label: "Delete", action: `deletePersonFromPicker(${person.id})`, danger: true },
          ]),
        ]))}
      </div>
    `
  );
}

function manageAssignmentAssets() {
  openPicker(
    "Manage Assets",
    "Dropdown CRUD",
    `
      <div class="picker-inline-actions">
        <button type="button" class="primary-btn" onclick="closePickerModal(); openAssetForm();">Add Asset</button>
      </div>
      <div class="table-wrap">
        ${simpleTable(["Asset Tag", "Device", "Status", "Actions"], state.assets.map((asset) => [
          asset.asset_tag,
          asset.device_name,
          statusPill(asset.status),
          actionButtons([
            { label: "Edit", action: `editAssetFromPicker(${asset.id})` },
            { label: "Delete", action: `deleteAssetFromPicker(${asset.id})`, danger: true },
          ]),
        ]))}
      </div>
    `
  );
}

function editPersonFromPicker(id) {
  closePickerModal();
  openPersonForm(id);
}

function editAssetFromPicker(id) {
  closePickerModal();
  openAssetForm(id);
}

async function deletePersonFromPicker(id) {
  closePickerModal();
  await deletePerson(id);
  openAssignForm();
}

async function deleteAssetFromPicker(id) {
  closePickerModal();
  await deleteAsset(id);
  openAssignForm();
}

function openLookupInlineForm(kind, id = null) {
  const item = state.lookups.find((lookup) => lookup.id === id) || {};
  state.lookupEditor = { kind, id, value: item.value || "" };
  openLookupManager(kind, state.activeLookupTargetField);
}

function cancelLookupInlineForm() {
  state.lookupEditor = null;
  if (state.activeLookupKind) {
    openLookupManager(state.activeLookupKind, state.activeLookupTargetField);
  }
}

async function saveLookupInline() {
  if (!state.lookupEditor) return;
  const input = document.getElementById("lookupInlineValue");
  const value = input?.value?.trim() || "";
  if (!value) {
    flash("Value is required.", true);
    return;
  }
  try {
    const { kind, id } = state.lookupEditor;
    await api(id ? `/api/lookups/${id}` : "/api/lookups", {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(id ? { value } : { kind, value }),
    });
    state.lookupEditor = null;
    await loadAll();
    openLookupManager(kind, state.activeLookupTargetField);
    flash(id ? "Keyword updated." : "Keyword saved.");
  } catch (error) {
    flash(error.message, true);
  }
}

function selectLookupValue(lookupId) {
  const fieldName = state.activeLookupTargetField;
  const selectedItem = state.lookups.find((lookup) => lookup.id === lookupId);
  if (!fieldName || !selectedItem) return;
  const field = el.entityForm?.elements?.namedItem(fieldName);
  if (!field) return;
  field.value = selectedItem.value;
  field.dispatchEvent(new Event("input", { bubbles: true }));
  field.dispatchEvent(new Event("change", { bubbles: true }));
  closePickerModal();
}

function escapeHtml(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll('"', "&quot;");
}

window.openAssetForm = openAssetForm;
window.openPersonForm = openPersonForm;
window.openAdminForm = openAdminForm;
window.openChangePasswordForm = openChangePasswordForm;
window.openAssignForm = openAssignForm;
window.openReturnForm = openReturnForm;
window.deleteAsset = deleteAsset;
window.deletePerson = deletePerson;
window.deleteAdmin = deleteAdmin;
window.openLookupManager = openLookupManager;
window.openLookupForm = openLookupForm;
window.editLookupFromPicker = editLookupFromPicker;
window.deleteLookupFromPicker = deleteLookupFromPicker;
window.closePickerModal = closePickerModal;
window.selectLookupValue = selectLookupValue;
window.openLookupInlineForm = openLookupInlineForm;
window.cancelLookupInlineForm = cancelLookupInlineForm;
window.saveLookupInline = saveLookupInline;
window.manageAssignmentPeople = manageAssignmentPeople;
window.manageAssignmentAssets = manageAssignmentAssets;
window.editPersonFromPicker = editPersonFromPicker;
window.editAssetFromPicker = editAssetFromPicker;
window.deletePersonFromPicker = deletePersonFromPicker;
window.deleteAssetFromPicker = deleteAssetFromPicker;
window.updateTableQuery = updateTableQuery;
window.updateTableFilter = updateTableFilter;
window.updateTableSort = updateTableSort;
window.clearTableQuery = clearTableQuery;
