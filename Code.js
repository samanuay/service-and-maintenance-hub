function isAdminOrHodUserV3(nameOrRole) {
  if (!nameOrRole) return true;
  var str = nameOrRole.toString().trim().toLowerCase();
  if (str === "" || str === "all" || str === "all engineers overview") return true;
  if (str.indexOf("admin") !== -1 || str.indexOf("hod") !== -1 || str.indexOf("head") !== -1 || str.indexOf("system") !== -1 || str.indexOf("supervisor") !== -1 || str.indexOf("manager") !== -1) {
    return true;
  }
  return false;
}

// ============================================================================
// SERVER-SIDE SESSION MANAGEMENT (Phase 1 of the security foundation)
// Sessions live in ScriptProperties, keyed "sess_<token>". Never trust a
// client-supplied role/username string for anything privileged again -
// always call requireSession(token, allowedRoles) and use the role it
// returns, which is read fresh from server-held state.
// ============================================================================

var SESSION_TTL_MS_V3 = 12 * 60 * 60 * 1000; // 12 hours sliding expiry

function _sessionKeyV3(token) {
  return "sess_" + token;
}

function createSessionV3(username, fullName, role) {
  var token = Utilities.getUuid();
  var now = Date.now();
  var session = {
    username: username,
    fullName: fullName,
    role: role,
    issuedAt: now,
    expiresAt: now + SESSION_TTL_MS_V3
  };
  PropertiesService.getScriptProperties().setProperty(_sessionKeyV3(token), JSON.stringify(session));
  _purgeExpiredSessionsV3();
  return token;
}

function _purgeExpiredSessionsV3() {
  try {
    var props = PropertiesService.getScriptProperties();
    var all = props.getProperties();
    var now = Date.now();
    Object.keys(all).forEach(function(key) {
      if (key.indexOf("sess_") !== 0) return;
      try {
        var sess = JSON.parse(all[key]);
        if (!sess.expiresAt || sess.expiresAt < now) props.deleteProperty(key);
      } catch (e) {
        props.deleteProperty(key);
      }
    });
  } catch (e) {}
}

/**
 * Validates a session token and returns the server-held session record.
 * allowedRoles: null/undefined = any authenticated user is fine.
 *               array of role names = caller's role must be one of them
 *               (case-insensitive; "Admin" is always implicitly allowed
 *               wherever "HOD" is allowed).
 * Returns { ok: true, session: {...} } or { ok: false, message, sessionExpired: true }.
 */
function requireSession(token, allowedRoles) {
  if (!token) {
    return { ok: false, message: "Not signed in. Please sign in again.", sessionExpired: true };
  }
  var props = PropertiesService.getScriptProperties();
  var raw = props.getProperty(_sessionKeyV3(token));
  if (!raw) {
    return { ok: false, message: "Session expired. Please sign in again.", sessionExpired: true };
  }
  var session;
  try {
    session = JSON.parse(raw);
  } catch (e) {
    props.deleteProperty(_sessionKeyV3(token));
    return { ok: false, message: "Session invalid. Please sign in again.", sessionExpired: true };
  }
  if (!session.expiresAt || session.expiresAt < Date.now()) {
    props.deleteProperty(_sessionKeyV3(token));
    return { ok: false, message: "Session expired. Please sign in again.", sessionExpired: true };
  }

  if (allowedRoles && allowedRoles.length) {
    var roleLower = (session.role || "").toString().trim().toLowerCase();
    var allowed = allowedRoles.some(function(r) { return r.toString().trim().toLowerCase() === roleLower; });
    if (!allowed && roleLower === "admin") allowed = true; // Admin can do anything HOD/Engineer-scoped can
    if (!allowed) {
      return { ok: false, message: "You don't have permission to do that.", sessionExpired: false };
    }
  }

  // Sliding expiry: extend on activity
  session.expiresAt = Date.now() + SESSION_TTL_MS_V3;
  props.setProperty(_sessionKeyV3(token), JSON.stringify(session));

  return { ok: true, session: session };
}

function validateSessionV3(token) {
  var check = requireSession(token, null);
  if (!check.ok) return { success: false, message: check.message };
  return { success: true, user: { username: check.session.username, fullName: check.session.fullName, role: check.session.role, token: token, allowedPages: getAllowedPagesForRoleV3(check.session.role) } };
}

function logoutSessionV3(token) {
  try {
    if (token) PropertiesService.getScriptProperties().deleteProperty(_sessionKeyV3(token));
  } catch (e) {}
  return { success: true };
}

function findHeaderRowAndIndexes(data) {
  var headerRowIdx = 0;
  var colSim = 0;
  var colEng = 1;
  var colLoc = 2;
  var colStatus = -1;
  var colRemarks = -1;
  var colDate = -1;

  if (!data || data.length === 0) {
    return { headerRowIdx: 0, colSim: 0, colEng: 1, colLoc: 2, colStatus: -1, colRemarks: -1, colDate: -1 };
  }

  for (var r = 0; r < Math.min(data.length, 5); r++) {
    var row = data[r];
    if (!row) continue;
    for (var c = 0; c < row.length; c++) {
      var cellVal = row[c] ? row[c].toString().trim().toLowerCase().replace(/[^a-z0-9]/g, "") : "";
      if (cellVal.indexOf("sim") !== -1 || cellVal.indexOf("iccid") !== -1 || cellVal.indexOf("card") !== -1) {
        headerRowIdx = r;
        break;
      }
    }
  }

  var headersRow = data[headerRowIdx] || [];
  for (var col = 0; col < headersRow.length; col++) {
    var h = headersRow[col] ? headersRow[col].toString().trim().toLowerCase().replace(/[^a-z0-9]/g, "") : "";
    if (h.indexOf("sim") !== -1 || h.indexOf("iccid") !== -1 || h.indexOf("card") !== -1) {
      colSim = col;
    } else if (h.indexOf("engineer") !== -1 || h.indexOf("assigned") !== -1 || h.indexOf("person") !== -1 || h.indexOf("user") !== -1) {
      colEng = col;
    } else if (h.indexOf("location") !== -1 || h.indexOf("station") !== -1 || h.indexOf("site") !== -1) {
      colLoc = col;
    } else if (h.indexOf("status") !== -1) {
      colStatus = col;
    } else if (h.indexOf("remark") !== -1 || h.indexOf("note") !== -1) {
      colRemarks = col;
    } else if (h.indexOf("date") !== -1 || h.indexOf("time") !== -1 || h.indexOf("update") !== -1) {
      colDate = col;
    }
  }

  return {
    headerRowIdx: headerRowIdx,
    colSim: colSim,
    colEng: colEng,
    colLoc: colLoc,
    colStatus: colStatus,
    colRemarks: colRemarks,
    colDate: colDate
  };
}

function getSimColumnIndexes(headersRow) {
  var colSim = 0;
  var colEng = 1;
  var colLoc = 2;
  var colStatus = -1;
  var colRemarks = -1;
  var colDate = -1;

  if (headersRow && headersRow.length > 0) {
    for (var col = 0; col < headersRow.length; col++) {
      var h = headersRow[col] ? headersRow[col].toString().trim().toLowerCase().replace(/[^a-z0-9]/g, "") : "";
      if (h.indexOf("sim") !== -1 || h.indexOf("iccid") !== -1 || h.indexOf("card") !== -1) {
        colSim = col;
      } else if (h.indexOf("engineer") !== -1 || h.indexOf("assigned") !== -1 || h.indexOf("person") !== -1) {
        colEng = col;
      } else if (h.indexOf("location") !== -1 || h.indexOf("station") !== -1 || h.indexOf("site") !== -1) {
        colLoc = col;
      } else if (h.indexOf("status") !== -1) {
        colStatus = col;
      } else if (h.indexOf("remark") !== -1 || h.indexOf("note") !== -1) {
        colRemarks = col;
      } else if (h.indexOf("date") !== -1 || h.indexOf("time") !== -1 || h.indexOf("update") !== -1) {
        colDate = col;
      }
    }
  }

  return {
    colSim: colSim,
    colEng: colEng,
    colLoc: colLoc,
    colStatus: colStatus,
    colRemarks: colRemarks,
    colDate: colDate
  };
}

function getInventoryColumnIndexes(headers) {
  var stationCol = 1;
  var cpIdCol = 2;
  var capacityCol = 4;
  var engineerCol = 7;

  if (headers && headers.length > 0) {
    for (var col = 0; col < headers.length; col++) {
      var h = headers[col] ? headers[col].toString().trim().toLowerCase().replace(/[^a-z0-9]/g, "") : "";
      if (h.indexOf("station") !== -1 || h.indexOf("site") !== -1 || h.indexOf("location") !== -1) {
        stationCol = col;
      } else if (h.indexOf("cp") !== -1 || h.indexOf("chargerid") !== -1 || h.indexOf("cpid") !== -1 || (h.indexOf("charger") !== -1 && h.indexOf("name") === -1)) {
        cpIdCol = col;
      } else if (h.indexOf("engineer") !== -1 || h.indexOf("assigned") !== -1 || h.indexOf("service") !== -1 || h.indexOf("person") !== -1) {
        engineerCol = col;
      } else if (h.indexOf("capacity") !== -1 || h.indexOf("kw") !== -1 || h.indexOf("power") !== -1) {
        capacityCol = col;
      }
    }
  }
  return { stationCol: stationCol, cpIdCol: cpIdCol, capacityCol: capacityCol, engineerCol: engineerCol };
}

var GOEC_LOGO_BASE64 = "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RERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERFRwJOwAKBwLFiyIx6dOFa8TpV5vt5Ptx6+srNKOjk5d2gnst0tN/9BrzQDwRUSzfT0iIktV4wBqATQsXtk7dVR9SWtFiWc/g14D0CkiPkeK8sXcuepttx0SJSWI9/R0R+eerQpobTdmly1rBkQkFXY4RES0XnS+KCjnVDUBYJsgCMa5rrttV9KUZ9L+XjHHKfOD7OXbritwBP5AOkilMzDjRyQeBuAYoFcDrHBdDNgkv78fL5eVISki7Vm7OBEVrTVrekbU1ZV9JhZzvgVgi//5V/YDbj6APyeTuKe0FMsBTjJSdKnqWAA7JTPBuN4Bs2vMlcn269X3w58bdxwgHnPQlwx6RtTEHwXwzADwUimwgpP3G6+pSZ3vfAcjy8qwLYCYfZ4zQEcf8EoN0C0idmGEiIjoratZqnqCqj6hqkkNT6Cq/arakfFNs6r+SVW/7/v+oUMrbkREm5QMJdPB5ara8z6fPxnfN7f09+s4DjFFUdPcuV4mo/up6k1D35WRZ1T7faOzVXUfVeWi0UZQ1YqUr59K+8HfVXWtqnbb592ovqqql6rqJ1XVy90rjoiI8k6zqquqf1XVFRpNgTH6uqrepqqfnjt3Lr/I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";
/**
 * ============================================================================
 * GO EC MANAGEMENT PORTAL - BACKEND V2 (Code_V3.gs)
 * ============================================================================
 * Clean, robust backend logic for Google Apps Script Web App.
 * Handles authentication, user management, password changes, analytics reading,
 * form submissions, engineer pending PM schedules, HOD metrics, and live KPI stats.
 * Includes aesthetic sheet formatting with dark headers, text wrapping, and borders.
 * ============================================================================
 */

var CONFIG_V3;
const CONFIG_V2 = {

  // Dynamically resolved: Script Property 'SPREADSHEET_ID' or active container spreadsheet
  SPREADSHEET_ID: (function() {
    try {
      return PropertiesService.getScriptProperties().getProperty('SPREADSHEET_ID') || '';
    } catch(e) { return ''; }
  })(),
  NOTIFICATION_EMAILS: (function() {
    try {
      return PropertiesService.getScriptProperties().getProperty('NOTIFICATION_EMAILS') || '';
    } catch(e) { return ''; }
  })(),
  SHEET_COMMISSIONING: 'Commissioning Log',
  SHEET_PM_CIVIL: 'PM_ElectricalCivil_Log',
  SHEET_PM_CHARGER: 'PM_Charger_Log',
    SHEET_DAILY_WORK: 'Daily_Work_Report',
    SHEET_HOD_OVERRIDE: 'HOD_Override_Log',
  SHEET_TADA: 'TADA_Log',
  SHEET_USERS: 'Users',
  SHEET_INVENTORY: 'Charger Inventory',
  SHEET_SIM: 'Sim Inventory',
  SHEET_WEEKLY_PENDING: 'Weekly_Pending_Issues_Log',
  SHEET_ROLES: 'Roles',
  SHEET_STATIONS: 'Stations'
};

// All logical pages/tabs the SPA nav can show. Keep in sync with Home_V4.html's
// _v4BtnMap / _templateMap - AllowedPages in the Roles sheet is a CSV of these ids
// (or the literal "ALL"), never a template filename (some tabIds share one file).
var ALL_PORTAL_PAGES_V3 = [
  'dashboard', 'commissioning', 'pm_civil', 'pm_charger', 'daily_work', 'weekly_pending',
  'tada', 'sim_inventory', 'pm_report', 'hod_comm', 'hod_weekly', 'hod_tada',
  'hod_work_monitor', 'users', 'roles', 'stations', 'audit_log'
];

// Pages added after a role was already seeded into a live Roles sheet - see
// ensureNewPagesGrantedToSystemRolesV3() for the additive, non-destructive
// migration that backfills these onto existing HOD/Engineer rows.
var NEWLY_ADDED_PAGES_BY_ROLE_V3 = {
  'HOD': ['stations']
};

var DEFAULT_ROLE_PAGES_V3 = {
  'Engineer': ['dashboard', 'commissioning', 'pm_civil', 'pm_charger', 'daily_work', 'weekly_pending', 'tada', 'sim_inventory'],
  'HOD': ['dashboard', 'commissioning', 'pm_civil', 'pm_charger', 'daily_work', 'weekly_pending', 'tada', 'sim_inventory', 'pm_report', 'hod_comm', 'hod_weekly', 'hod_tada', 'hod_work_monitor', 'stations'],
  'Admin': ['ALL']
};

// ============================================================================
// DYNAMIC ROLES & PER-PAGE PERMISSIONS
// Roles sheet columns: RoleName | AllowedPages (CSV of tabIds, or "ALL") | IsSystemRole
// ============================================================================

function getOrCreateRolesSheetV3() {
  var ss = getSpreadsheetV3();
  var sheet = ss.getSheetByName(CONFIG_V2.SHEET_ROLES);
  if (!sheet) {
    sheet = ss.insertSheet(CONFIG_V2.SHEET_ROLES);
    sheet.appendRow(['RoleName', 'AllowedPages', 'IsSystemRole']);
    Object.keys(DEFAULT_ROLE_PAGES_V3).forEach(function(roleName) {
      sheet.appendRow([roleName, DEFAULT_ROLE_PAGES_V3[roleName].join(','), true]);
    });
  } else if (sheet.getLastRow() < 2) {
    Object.keys(DEFAULT_ROLE_PAGES_V3).forEach(function(roleName) {
      sheet.appendRow([roleName, DEFAULT_ROLE_PAGES_V3[roleName].join(','), true]);
    });
  } else {
    ensureNewPagesGrantedToSystemRolesV3(sheet);
  }
  return sheet;
}

// A page added in a later phase (e.g. "stations") needs to reach a system
// role's row in an ALREADY-SEEDED Roles sheet too. This only ADDS pages
// that were never seen before for that role - it never removes a page an
// admin deliberately unchecked, so it's safe to run on every access.
function ensureNewPagesGrantedToSystemRolesV3(sheet) {
  try {
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      var roleName = data[i][0] ? data[i][0].toString().trim() : "";
      var newPages = NEWLY_ADDED_PAGES_BY_ROLE_V3[roleName];
      if (!newPages || !newPages.length) continue;

      var pagesRaw = data[i][1] ? data[i][1].toString().trim() : "";
      var pages = pagesRaw.split(',').map(function(p) { return p.trim(); }).filter(Boolean);
      if (pages.indexOf('ALL') !== -1) continue;

      var missing = newPages.filter(function(p) { return pages.indexOf(p) === -1; });
      if (missing.length) {
        sheet.getRange(i + 1, 2).setValue(pages.concat(missing).join(','));
      }
    }
  } catch (e) {}
}

function getAllRolesRawV3() {
  var sheet = getOrCreateRolesSheetV3();
  var data = sheet.getDataRange().getValues();
  var roles = [];
  for (var i = 1; i < data.length; i++) {
    var name = data[i][0] ? data[i][0].toString().trim() : "";
    if (!name) continue;
    var pagesRaw = data[i][1] ? data[i][1].toString().trim() : "";
    var pages = pagesRaw.split(',').map(function(p) { return p.trim(); }).filter(Boolean);
    roles.push({
      rowIndex: i + 1,
      roleName: name,
      allowedPages: pages,
      isSystemRole: (data[i][2] === true || data[i][2] === 'true' || data[i][2] === 'TRUE')
    });
  }
  return roles;
}

function getAllowedPagesForRoleV3(roleName) {
  var roles = getAllRolesRawV3();
  var rLower = (roleName || "").toString().trim().toLowerCase();
  for (var i = 0; i < roles.length; i++) {
    if (roles[i].roleName.toLowerCase() === rLower) return roles[i].allowedPages;
  }
  // Unknown role (e.g. a stale role deleted after a user was assigned it) - safest default is dashboard-only.
  return ['dashboard'];
}

function roleHasPageAccessV3(roleName, tabId) {
  if (!tabId || tabId === 'dashboard') return true;
  var pages = getAllowedPagesForRoleV3(roleName);
  return pages.indexOf('ALL') !== -1 || pages.indexOf(tabId) !== -1;
}

function getRolesListV3(token) {
  var access = requireSession(token, ['Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };
  try {
    var roles = getAllRolesRawV3().map(function(r) {
      return { roleName: r.roleName, allowedPages: r.allowedPages, isSystemRole: r.isSystemRole };
    });
    return { success: true, roles: roles, allPages: ALL_PORTAL_PAGES_V3 };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

// Used to populate the role dropdown when creating a user - any authenticated
// user managing users needs this, but it only exposes names, not permissions.
function getRoleNamesForUserFormV3(token) {
  var access = requireSession(token, ['Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };
  try {
    var names = getAllRolesRawV3().map(function(r) { return r.roleName; });
    return { success: true, roleNames: names };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

function saveRoleV3(roleName, allowedPages, originalName, token) {
  var access = requireSession(token, ['Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var name = (roleName || "").toString().trim();
    if (!name) return { success: false, message: "Role name cannot be empty." };

    var pagesArr = Array.isArray(allowedPages) ? allowedPages : (allowedPages || "").toString().split(',');
    pagesArr = pagesArr.map(function(p) { return p.toString().trim(); }).filter(Boolean);
    if (!pagesArr.length) return { success: false, message: "Select at least one page for this role." };

    var sheet = getOrCreateRolesSheetV3();
    var data = sheet.getDataRange().getValues();
    var nameLower = name.toLowerCase();
    // Editing an existing role always matches by the name it had when the
    // edit modal was opened (originalName) - not the possibly-just-changed
    // new name - so renaming a role updates that row in place instead of
    // leaving the old row behind and appending a second, duplicate role.
    var matchKey = (originalName || name).toString().trim().toLowerCase();

    for (var i = 1; i < data.length; i++) {
      var rowName = data[i][0] ? data[i][0].toString().trim() : "";
      if (rowName.toLowerCase() === matchKey) {
        var isSystem = (data[i][2] === true || data[i][2] === 'true' || data[i][2] === 'TRUE');
        if (isSystem && rowName === 'Admin') {
          return { success: false, message: "The Admin role always has full access and can't be edited." };
        }
        if (rowName.toLowerCase() !== nameLower) {
          if (isSystem) return { success: false, message: "Built-in roles can't be renamed." };
          for (var j = 1; j < data.length; j++) {
            if (j !== i && data[j][0] && data[j][0].toString().trim().toLowerCase() === nameLower) {
              return { success: false, message: "A role named '" + name + "' already exists." };
            }
          }
          sheet.getRange(i + 1, 1).setValue(name);
        }
        sheet.getRange(i + 1, 2).setValue(pagesArr.join(','));
        return { success: true, message: "Role '" + name + "' updated." };
      }
    }

    // New custom role
    sheet.appendRow([name, pagesArr.join(','), false]);
    return { success: true, message: "Role '" + name + "' created." };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

function deleteRoleV3(roleName, token) {
  var access = requireSession(token, ['Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var name = (roleName || "").toString().trim();
    var sheet = getOrCreateRolesSheetV3();
    var data = sheet.getDataRange().getValues();
    var nameLower = name.toLowerCase();

    for (var i = 1; i < data.length; i++) {
      var rowName = data[i][0] ? data[i][0].toString().trim() : "";
      if (rowName.toLowerCase() === nameLower) {
        var isSystem = (data[i][2] === true || data[i][2] === 'true' || data[i][2] === 'TRUE');
        if (isSystem) {
          return { success: false, message: "'" + rowName + "' is a built-in role and can't be deleted." };
        }

        // Refuse to delete a role that's still assigned to at least one user.
        var usersSheet = getSpreadsheetV3().getSheetByName(CONFIG_V2.SHEET_USERS || "Users");
        if (usersSheet) {
          var usersData = usersSheet.getDataRange().getValues();
          for (var u = 1; u < usersData.length; u++) {
            var uRole = usersData[u][3] ? usersData[u][3].toString().trim().toLowerCase() : "";
            if (uRole === nameLower) {
              return { success: false, message: "Can't delete '" + rowName + "' - it's still assigned to at least one user. Reassign them first." };
            }
          }
        }

        sheet.deleteRow(i + 1);
        return { success: true, message: "Role '" + rowName + "' deleted." };
      }
    }
    return { success: false, message: "Role not found." };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

// ============================================================================
// STATIONS MASTER DATA
// Stations sheet columns: StationName | InvestorName | InvestorEmails (CSV) | AssignedEngineer
// Charger details stay in Charger Inventory (joined by StationName); this sheet
// is the source of truth for investor contacts and the "official" assigned
// engineer, dual-written into Charger Inventory's Engineer column (index 7)
// so the many existing readers of that column keep working unchanged.
// ============================================================================

function getOrCreateStationsSheetV3() {
  var ss = getSpreadsheetV3();
  var sheet = ss.getSheetByName(CONFIG_V2.SHEET_STATIONS);
  if (!sheet) {
    sheet = ss.insertSheet(CONFIG_V2.SHEET_STATIONS);
    sheet.appendRow(['StationName', 'InvestorName', 'InvestorEmails', 'AssignedEngineer']);
  }
  return sheet;
}

function _stationKeyV3(name) {
  return (name || "").toString().trim().toLowerCase();
}

// Ensures every distinct station already in Charger Inventory has a row here,
// so stations commissioned before this feature existed still show up. Only
// ADDS missing stations - never touches an existing Stations row.
function seedStationsFromInventoryV3(stationsSheet) {
  try {
    var ss = getSpreadsheetV3();
    var invSheet = ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory");
    if (!invSheet || invSheet.getLastRow() < 2) return;

    var existing = stationsSheet.getDataRange().getValues();
    var knownKeys = {};
    for (var i = 1; i < existing.length; i++) {
      var n = existing[i][0] ? existing[i][0].toString().trim() : "";
      if (n) knownKeys[_stationKeyV3(n)] = true;
    }

    var invData = invSheet.getDataRange().getValues();
    var toAdd = {};
    for (var r = 1; r < invData.length; r++) {
      var stName = invData[r][1] ? invData[r][1].toString().trim() : "";
      if (!stName) continue;
      var key = _stationKeyV3(stName);
      if (knownKeys[key] || toAdd[key]) continue;
      var eng = invData[r][7] ? invData[r][7].toString().trim() : "";
      toAdd[key] = { name: stName, engineer: eng };
    }

    Object.keys(toAdd).forEach(function(key) {
      stationsSheet.appendRow([toAdd[key].name, '', '', toAdd[key].engineer]);
    });
  } catch (e) {}
}

// Called from addCommissionedChargerToInventoryV2 on every new commissioning
// submission. Only creates a row if this station has never been seen before -
// never overwrites an existing station's investor info or AssignedEngineer,
// so a later manual reassignment survives future commissioning visits.
function upsertStationOnCommissioningV3(stationName, engineerName) {
  try {
    if (!stationName) return;
    var sheet = getOrCreateStationsSheetV3();
    var data = sheet.getDataRange().getValues();
    var key = _stationKeyV3(stationName);

    for (var i = 1; i < data.length; i++) {
      var rowName = data[i][0] ? data[i][0].toString().trim() : "";
      if (_stationKeyV3(rowName) === key) return; // already registered, leave as-is
    }

    sheet.appendRow([stationName.toString().trim(), '', '', (engineerName || '').toString().trim()]);
  } catch (e) {}
}

// Stations has its own page permission ('stations') in the dynamic roles
// system, so gating it on a hardcoded ['HOD','Admin'] role-name check (like
// the code below used to) silently locks out any custom role an Admin grants
// that page to - check the actual page permission instead, the same way
// getSubTemplateV4 already decides whether to serve this page at all.
function requireStationsAccessV3(token) {
  var access = requireSession(token, null);
  if (!access.ok) return access;
  if (!roleHasPageAccessV3(access.session.role, 'stations')) {
    return { ok: false, message: "You don't have permission to do that.", sessionExpired: false };
  }
  return access;
}

function getAllStationsV3(token) {
  var access = requireStationsAccessV3(token);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var stationsSheet = getOrCreateStationsSheetV3();
    seedStationsFromInventoryV3(stationsSheet);

    var stationsData = stationsSheet.getDataRange().getValues();
    var stationsByKey = {};
    var order = [];
    for (var i = 1; i < stationsData.length; i++) {
      var name = stationsData[i][0] ? stationsData[i][0].toString().trim() : "";
      if (!name) continue;
      var key = _stationKeyV3(name);
      stationsByKey[key] = {
        stationName: name,
        investorName: stationsData[i][1] ? stationsData[i][1].toString().trim() : "",
        investorEmails: stationsData[i][2] ? stationsData[i][2].toString().trim() : "",
        assignedEngineer: stationsData[i][3] ? stationsData[i][3].toString().trim() : "",
        chargerCount: 0
      };
      order.push(key);
    }

    var ss = getSpreadsheetV3();
    var invSheet = ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory");
    if (invSheet && invSheet.getLastRow() > 1) {
      var invData = invSheet.getDataRange().getValues();
      for (var r = 1; r < invData.length; r++) {
        var stName = invData[r][1] ? invData[r][1].toString().trim() : "";
        if (!stName) continue;
        var k = _stationKeyV3(stName);
        var hasCp = invData[r][2] && invData[r][2].toString().trim();
        if (stationsByKey[k] && hasCp) stationsByKey[k].chargerCount++;
      }
    }

    var stations = order.map(function(k) { return stationsByKey[k]; });

    // HOD only sees stations whose assigned engineer is one of theirs.
    var scope = getHodEngineerScopeV3(token);
    if (scope.ok && scope.scoped) {
      stations = stations.filter(function(s) { return engineerInHodScopeV3(scope, s.assignedEngineer); });
    }

    stations.sort(function(a, b) { return a.stationName.localeCompare(b.stationName); });

    return { success: true, stations: stations };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

// Station-name dropdown for an Engineer's own submission forms (Weekly
// Pending Issues) - returns only the stations assigned to the calling
// engineer, so they can't mistype/mistarget a station. Any authenticated
// role can call this; Admin/HOD get the full station list (matches how
// they're treated as unscoped everywhere else), an Engineer gets just
// their own assigned stations by exact name match on AssignedEngineer.
function getEngineerAssignedStationsV3(token) {
  var access = requireSession(token, null);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var stationsSheet = getOrCreateStationsSheetV3();
    seedStationsFromInventoryV3(stationsSheet);

    var stationsData = stationsSheet.getDataRange().getValues();
    var role = (access.session.role || "").toString().trim().toLowerCase();
    var engName = (access.session.fullName || access.session.username || "").toString().trim().toLowerCase();

    var names = [];
    var seen = {};
    for (var i = 1; i < stationsData.length; i++) {
      var name = stationsData[i][0] ? stationsData[i][0].toString().trim() : "";
      if (!name) continue;
      var assignedEngineer = stationsData[i][3] ? stationsData[i][3].toString().trim().toLowerCase() : "";

      var visible = (role === 'admin' || role === 'hod') ? true : (assignedEngineer === engName);
      if (!visible) continue;

      var key = _stationKeyV3(name);
      if (seen[key]) continue;
      seen[key] = true;
      names.push(name);
    }

    names.sort(function(a, b) { return a.localeCompare(b); });
    return { success: true, stations: names };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

function getStationDetailV3(stationName, token) {
  var access = requireStationsAccessV3(token);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var key = _stationKeyV3(stationName);
    var stationsSheet = getOrCreateStationsSheetV3();
    var stationsData = stationsSheet.getDataRange().getValues();
    var station = { stationName: stationName, investorName: "", investorEmails: "", assignedEngineer: "" };
    for (var i = 1; i < stationsData.length; i++) {
      var name = stationsData[i][0] ? stationsData[i][0].toString().trim() : "";
      if (_stationKeyV3(name) === key) {
        station = {
          stationName: name,
          investorName: stationsData[i][1] ? stationsData[i][1].toString().trim() : "",
          investorEmails: stationsData[i][2] ? stationsData[i][2].toString().trim() : "",
          assignedEngineer: stationsData[i][3] ? stationsData[i][3].toString().trim() : ""
        };
        break;
      }
    }

    var chargers = [];
    var ss = getSpreadsheetV3();
    var invSheet = ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory");
    if (invSheet && invSheet.getLastRow() > 1) {
      var invData = invSheet.getDataRange().getValues();
      for (var r = 1; r < invData.length; r++) {
        var stName = invData[r][1] ? invData[r][1].toString().trim() : "";
        if (_stationKeyV3(stName) !== key) continue;
        var cpId = invData[r][2] ? invData[r][2].toString().trim() : "";
        var serialNo = invData[r][3] ? invData[r][3].toString().trim() : "";
        var oem = invData[r][4] ? invData[r][4].toString().trim() : "";
        var power = invData[r][6] ? invData[r][6].toString().trim() : "";
        if (cpId || serialNo) chargers.push({ rowIndex: r + 1, cpId: cpId, serialNo: serialNo, oem: oem, power: power });
      }
    }

    return { success: true, station: station, chargers: chargers };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

// Edits one charger row's CP ID, Serial No, OEM, and Power directly from the
// Stations detail view. rowIndex comes from getStationDetailV3 (1-indexed
// sheet row); re-verified against stationName here before writing, so a
// stale rowIndex (row moved/deleted since the page loaded) fails safely
// instead of silently editing the wrong charger.
function updateStationChargerV3(stationName, rowIndex, cpId, serialNo, oem, power, token) {
  var access = requireStationsAccessV3(token);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
  } catch (e) {
    return { success: false, message: "System is busy, please try again in a moment." };
  }

  try {
    var ss = getSpreadsheetV3();
    var invSheet = ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory");
    if (!invSheet) return { success: false, message: "Charger Inventory sheet not found." };

    var r = parseInt(rowIndex, 10);
    if (!r || r < 2 || r > invSheet.getLastRow()) return { success: false, message: "Charger row not found - the list may be out of date, please refresh." };

    var rowStation = invSheet.getRange(r, 2).getValue();
    if (_stationKeyV3(rowStation) !== _stationKeyV3(stationName)) {
      return { success: false, message: "That charger no longer belongs to this station - please refresh and try again." };
    }

    invSheet.getRange(r, 3).setValue((cpId || '').toString().trim());   // CP ID
    invSheet.getRange(r, 4).setValue((serialNo || '').toString().trim()); // Serial No
    invSheet.getRange(r, 5).setValue((oem || '').toString().trim());      // OEM
    invSheet.getRange(r, 7).setValue((power || '').toString().trim());   // Power

    return { success: true, message: "Charger details updated." };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

// Renames a station everywhere it's the "key": the Stations sheet row and
// every matching Charger Inventory row. Does NOT rewrite historical
// Commissioning/PM/TA-DA log rows - those stay as originally submitted, so
// past reports keep the station name that was true at the time.
function updateStationNameV3(oldName, newName, token) {
  var access = requireStationsAccessV3(token);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
  } catch (e) {
    return { success: false, message: "System is busy, please try again in a moment." };
  }

  try {
    var cleanNew = (newName || "").toString().trim();
    if (!cleanNew) return { success: false, message: "New station name cannot be empty." };
    var oldKey = _stationKeyV3(oldName);
    var newKey = _stationKeyV3(cleanNew);

    var stationsSheet = getOrCreateStationsSheetV3();
    var stationsData = stationsSheet.getDataRange().getValues();

    if (newKey !== oldKey) {
      for (var i = 1; i < stationsData.length; i++) {
        var rn = stationsData[i][0] ? stationsData[i][0].toString().trim() : "";
        if (_stationKeyV3(rn) === newKey) {
          return { success: false, message: "A station named '" + cleanNew + "' already exists." };
        }
      }
    }

    var foundRow = -1;
    for (var j = 1; j < stationsData.length; j++) {
      var name = stationsData[j][0] ? stationsData[j][0].toString().trim() : "";
      if (_stationKeyV3(name) === oldKey) { foundRow = j + 1; break; }
    }
    if (foundRow > 0) {
      stationsSheet.getRange(foundRow, 1).setValue(cleanNew);
    } else {
      stationsSheet.appendRow([cleanNew, '', '', '']);
    }

    var ss = getSpreadsheetV3();
    var invSheet = ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory");
    var syncedRows = 0;
    if (invSheet && invSheet.getLastRow() > 1) {
      var invData = invSheet.getDataRange().getValues();
      for (var r = 1; r < invData.length; r++) {
        var stName = invData[r][1] ? invData[r][1].toString().trim() : "";
        if (_stationKeyV3(stName) === oldKey) {
          invSheet.getRange(r + 1, 2).setValue(cleanNew);
          syncedRows++;
        }
      }
    }

    return { success: true, message: "Station renamed to '" + cleanNew + "' (" + syncedRows + " charger row(s) synced). Historical PM/commissioning reports keep the original name.", newName: cleanNew };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

// Used right after a PM verification to pre-fill the report email - any
// signed-in user is fine here since reaching this point already required
// PM Report page access (HOD/Admin only), and this is read-only.
function getStationInvestorContactV3(stationName, token) {
  var access = requireSession(token, null);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var key = _stationKeyV3(stationName);
    var sheet = getOrCreateStationsSheetV3();
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      var rowName = data[i][0] ? data[i][0].toString().trim() : "";
      if (_stationKeyV3(rowName) === key) {
        return {
          success: true,
          investorName: data[i][1] ? data[i][1].toString().trim() : "",
          investorEmails: data[i][2] ? data[i][2].toString().trim() : ""
        };
      }
    }
    return { success: true, investorName: "", investorEmails: "" };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

function updateStationInvestorInfoV3(stationName, investorName, investorEmails, token) {
  var access = requireStationsAccessV3(token);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    if (!stationName) return { success: false, message: "Station name is required." };
    var sheet = getOrCreateStationsSheetV3();
    var data = sheet.getDataRange().getValues();
    var key = _stationKeyV3(stationName);

    for (var i = 1; i < data.length; i++) {
      var rowName = data[i][0] ? data[i][0].toString().trim() : "";
      if (_stationKeyV3(rowName) === key) {
        sheet.getRange(i + 1, 2).setValue((investorName || '').toString().trim());
        sheet.getRange(i + 1, 3).setValue((investorEmails || '').toString().trim());
        return { success: true, message: "Investor details updated for " + rowName + "." };
      }
    }

    sheet.appendRow([stationName.toString().trim(), (investorName || '').toString().trim(), (investorEmails || '').toString().trim(), '']);
    return { success: true, message: "Investor details saved for " + stationName + "." };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

// Dual-write: updates the Stations sheet (source of truth going forward) AND
// syncs every matching Charger Inventory row's Engineer column, since many
// existing functions (PM assignment filtering, dashboards) still read the
// engineer from Charger Inventory directly.
function updateStationEngineerV3(stationName, engineerName, token) {
  var access = requireStationsAccessV3(token);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    if (!stationName) return { success: false, message: "Station name is required." };
    var engClean = (engineerName || '').toString().trim();
    var key = _stationKeyV3(stationName);

    var stationsSheet = getOrCreateStationsSheetV3();
    var stationsData = stationsSheet.getDataRange().getValues();
    var foundStationRow = -1;
    for (var i = 1; i < stationsData.length; i++) {
      var rowName = stationsData[i][0] ? stationsData[i][0].toString().trim() : "";
      if (_stationKeyV3(rowName) === key) { foundStationRow = i + 1; break; }
    }
    if (foundStationRow > 0) {
      stationsSheet.getRange(foundStationRow, 4).setValue(engClean);
    } else {
      stationsSheet.appendRow([stationName.toString().trim(), '', '', engClean]);
    }

    var ss = getSpreadsheetV3();
    var invSheet = ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory");
    var syncedRows = 0;
    if (invSheet && invSheet.getLastRow() > 1) {
      var invData = invSheet.getDataRange().getValues();
      for (var r = 1; r < invData.length; r++) {
        var stName = invData[r][1] ? invData[r][1].toString().trim() : "";
        if (_stationKeyV3(stName) === key) {
          invSheet.getRange(r + 1, 8).setValue(engClean); // col 8 = Engineer (index 7)
          syncedRows++;
        }
      }
    }

    return { success: true, message: "Engineer for '" + stationName + "' set to " + (engClean || "(unassigned)") + " (" + syncedRows + " charger row(s) synced)." };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

// ============================================================================
// UNIVERSAL ADMIN EDIT/DELETE + AUDIT LOG
// Lets Admin fix or remove any submission from inside the portal instead of
// editing the Google Sheet directly. Every submission type is identified by
// a stable RecordID column (stamped at submit time - see ensureTrailingHeadersV3
// / stampRecordIdV3 in submitFormV2) so edit/delete always re-search by that
// ID rather than trusting a row number, and everything is wrapped in
// LockService to stay safe if two admins act on the same record at once.
// ============================================================================

var SUBMISSION_SHEETS_V3 = {
  commissioning: { sheetName: 'Commissioning Log', idColumn: 'RecordID', baseHeaderCount: 38, backfillable: true },
  // PM Civil's real header row is 24 columns wide (ending in "Payload JSON") -
  // RecordID is stamped one column after that, at index 24. This was
  // previously set to 23, which collided with the "Payload JSON" column and
  // could corrupt that header when the admin edit/delete backfill ran.
  pm_civil: { sheetName: 'PM_ElectricalCivil_Log', idColumn: 'RecordID', baseHeaderCount: 24, backfillable: true },
  pm_charger: { sheetName: 'PM_Charger_Log', idColumn: 'RecordID', baseHeaderCount: 29, backfillable: true },
  daily_work: { sheetName: 'Daily_Work_Report', idColumn: 'RecordID', baseHeaderCount: 14, backfillable: true },
  tada: { sheetName: 'TADA_Log', idColumn: 'RecordID', baseHeaderCount: 14, backfillable: true },
  // Weekly Pending already has a natural "Issue ID" key from submit time - never blank, so it's never backfilled.
  weekly_pending: { sheetName: 'Weekly_Pending_Issues_Log', idColumn: 'Issue ID', backfillable: false }
};

// Self-healing: makes sure a submission sheet's RecordID header exists AND
// every existing row has a value in it, so edit/delete work immediately on
// data submitted before this feature shipped - not just new submissions.
// Safe to call every time: only touches the header cell and blank ID cells,
// never an existing ID or any submission content.
function ensureSubmissionIdsBackfilledV3(sheet, cfg) {
  if (!cfg.backfillable) return;
  try {
    ensureTrailingHeadersV3(sheet, cfg.baseHeaderCount, [cfg.idColumn]);
    var idColIdx1Based = cfg.baseHeaderCount + 1;
    var lastRow = sheet.getLastRow();
    if (lastRow < 2) return;

    var timestampCol = sheet.getRange(2, 1, lastRow - 1, 1).getValues();
    var idRange = sheet.getRange(2, idColIdx1Based, lastRow - 1, 1);
    var idValues = idRange.getValues();
    var changed = false;
    for (var i = 0; i < idValues.length; i++) {
      var hasContent = timestampCol[i][0] !== '' && timestampCol[i][0] !== null;
      var isBlankId = !idValues[i][0] || idValues[i][0].toString().trim() === '';
      if (hasContent && isBlankId) {
        idValues[i][0] = Utilities.getUuid();
        changed = true;
      }
    }
    if (changed) idRange.setValues(idValues);
  } catch (e) {}
}

// Fields no one edits by hand - internal bookkeeping, not submission content.
var SUBMISSION_EDIT_BLOCKLIST_V3 = ['Timestamp', 'Payload JSON', 'RecordID', 'SubmissionID'];

function getOrCreateAuditLogSheetV3() {
  var ss = getSpreadsheetV3();
  var sheet = ss.getSheetByName('Audit_Log');
  if (!sheet) {
    sheet = ss.insertSheet('Audit_Log');
    sheet.appendRow(['Timestamp', 'ActorUsername', 'ActorFullName', 'Action', 'SheetKey', 'RecordID', 'FieldChanged', 'OldValue', 'NewValue']);
  }
  return sheet;
}

function logAuditEntryV3(actorSession, action, sheetKey, recordId, fieldChanged, oldValue, newValue) {
  try {
    getOrCreateAuditLogSheetV3().appendRow([
      new Date(), actorSession.username, actorSession.fullName, action, sheetKey, recordId, fieldChanged, oldValue, newValue
    ]);
  } catch (e) {}
}

function _findSubmissionRowV3(sheet, idColIdx, recordId) {
  var data = sheet.getDataRange().getValues();
  var target = (recordId || "").toString().trim();
  for (var i = 1; i < data.length; i++) {
    var val = data[i][idColIdx] ? data[i][idColIdx].toString().trim() : "";
    if (val && val === target) return { rowIndex: i + 1, rowValues: data[i], headers: data[0] };
  }
  return null;
}

function getSubmissionRecordV3(sheetKey, recordId, token) {
  var access = requireSession(token, ['Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var cfg = SUBMISSION_SHEETS_V3[sheetKey];
    if (!cfg) return { success: false, message: "Unknown submission type." };
    var sheet = getSpreadsheetV3().getSheetByName(cfg.sheetName);
    if (!sheet) return { success: false, message: "Sheet not found." };

    ensureSubmissionIdsBackfilledV3(sheet, cfg);
    var headers = sheet.getDataRange().getValues()[0].map(function(h) { return h ? h.toString().trim() : ""; });
    var idColIdx = headers.indexOf(cfg.idColumn);
    if (idColIdx === -1) return { success: false, message: "This sheet has no " + cfg.idColumn + " column yet." };

    var found = _findSubmissionRowV3(sheet, idColIdx, recordId);
    if (!found) return { success: false, message: "Record not found - it may have been deleted, or this list is out of date. Try refreshing the page." };

    var fields = [];
    headers.forEach(function(h, idx) {
      if (h && SUBMISSION_EDIT_BLOCKLIST_V3.indexOf(h) === -1) {
        var v = found.rowValues[idx];
        fields.push({ field: h, value: (v !== undefined && v !== null) ? v.toString() : "" });
      }
    });

    return { success: true, fields: fields };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

function adminEditSubmissionV3(sheetKey, recordId, changes, token) {
  var access = requireSession(token, ['Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
  } catch (e) {
    return { success: false, message: "System is busy handling another edit - please try again in a moment." };
  }

  try {
    var cfg = SUBMISSION_SHEETS_V3[sheetKey];
    if (!cfg) return { success: false, message: "Unknown submission type." };
    var sheet = getSpreadsheetV3().getSheetByName(cfg.sheetName);
    if (!sheet) return { success: false, message: "Sheet not found." };

    ensureSubmissionIdsBackfilledV3(sheet, cfg);
    var headers = sheet.getDataRange().getValues()[0].map(function(h) { return h ? h.toString().trim() : ""; });
    var idColIdx = headers.indexOf(cfg.idColumn);
    if (idColIdx === -1) return { success: false, message: "This record type can't be edited yet." };

    var found = _findSubmissionRowV3(sheet, idColIdx, recordId);
    if (!found) return { success: false, message: "Record not found - it may have already been changed or deleted. Try refreshing the page." };

    var changedCount = 0;
    Object.keys(changes || {}).forEach(function(fieldName) {
      if (SUBMISSION_EDIT_BLOCKLIST_V3.indexOf(fieldName) !== -1) return;
      var colIdx = headers.indexOf(fieldName);
      if (colIdx === -1) return;

      var oldVal = found.rowValues[colIdx];
      oldVal = (oldVal !== undefined && oldVal !== null) ? oldVal.toString() : "";
      var newVal = (changes[fieldName] !== undefined && changes[fieldName] !== null) ? changes[fieldName].toString() : "";
      if (oldVal === newVal) return;

      sheet.getRange(found.rowIndex, colIdx + 1).setValue(newVal);
      logAuditEntryV3(access.session, 'Edit', sheetKey, recordId, fieldName, oldVal, newVal);
      changedCount++;
    });

    return { success: true, message: changedCount ? ("Updated " + changedCount + " field(s).") : "No changes to save." };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function adminDeleteSubmissionV3(sheetKey, recordId, token) {
  var access = requireSession(token, ['Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
  } catch (e) {
    return { success: false, message: "System is busy handling another change - please try again in a moment." };
  }

  try {
    var cfg = SUBMISSION_SHEETS_V3[sheetKey];
    if (!cfg) return { success: false, message: "Unknown submission type." };
    var sheet = getSpreadsheetV3().getSheetByName(cfg.sheetName);
    if (!sheet) return { success: false, message: "Sheet not found." };

    ensureSubmissionIdsBackfilledV3(sheet, cfg);
    var headers = sheet.getDataRange().getValues()[0].map(function(h) { return h ? h.toString().trim() : ""; });
    var idColIdx = headers.indexOf(cfg.idColumn);
    if (idColIdx === -1) return { success: false, message: "This record type can't be deleted yet." };

    var found = _findSubmissionRowV3(sheet, idColIdx, recordId);
    if (!found) return { success: false, message: "Record not found - it may have already been deleted. Try refreshing the page." };

    var snapshot = {};
    headers.forEach(function(h, idx) {
      if (!h) return;
      var v = found.rowValues[idx];
      snapshot[h] = (v !== undefined && v !== null) ? v.toString() : "";
    });

    sheet.deleteRow(found.rowIndex);
    logAuditEntryV3(access.session, 'Delete', sheetKey, recordId, '(entire record)', JSON.stringify(snapshot), '');

    return { success: true, message: "Record deleted." };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function getAuditLogV3(token) {
  var access = requireSession(token, ['Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var sheet = getOrCreateAuditLogSheetV3();
    var data = sheet.getDataRange().getValues();
    var entries = [];
    for (var i = data.length - 1; i >= 1 && entries.length < 500; i--) {
      entries.push({
        timestamp: data[i][0] ? new Date(data[i][0]).toLocaleString() : "",
        actorUsername: data[i][1] || "",
        actorFullName: data[i][2] || "",
        action: data[i][3] || "",
        sheetKey: data[i][4] || "",
        recordId: data[i][5] || "",
        fieldChanged: data[i][6] || "",
        oldValue: data[i][7] || "",
        newValue: data[i][8] || ""
      });
    }
    return { success: true, entries: entries };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}


/**
 * Gets active spreadsheet or opens by ID gracefully.
 */
/**
 * Normalizes station names for robust fuzzy matching (lowercase alphanumeric only)
 */
function cleanPMKeyV2(str) {
  if (!str) return "";
  return str.toString().toLowerCase().replace(/[^a-z0-9]/g, "");
}

function getSpreadsheetV3() {
  try {
    var active = SpreadsheetApp.getActiveSpreadsheet();
    if (active) return active;
  } catch (e) {}

  var propId = '';
  try {
    propId = PropertiesService.getScriptProperties().getProperty('SPREADSHEET_ID');
  } catch (eProps) {}

  var targetId = propId || CONFIG_V2.SPREADSHEET_ID;
  if (targetId && targetId.trim() !== '') {
    try {
      return SpreadsheetApp.openById(targetId.trim());
    } catch (eOpen) {
      Logger.log("Error opening spreadsheet by ID: " + eOpen.toString());
    }
  }

  throw new Error("No database spreadsheet linked. Please run setupPortal() once from the Apps Script editor to create and initialize the database.");
}

/**
 * Calculates top KPI metrics (Total Stations, Total Chargers, PMs Completed This Month, PMs Pending This Month).
 */
function getDashboardKpiMetricsV2(engineerName, monthStr, token) {
  try {
    var ss = getSpreadsheetV3();
    var engInput = engineerName ? engineerName.toString().trim().toLowerCase() : "";

    // Who's asking, from the real session - not a name-content guess. Determines
    // whether we show one engineer's own stations, an HOD's assigned subset,
    // or everything (Admin).
    var hodScope = getHodEngineerScopeV3(token);
    if (!hodScope.ok) return { success: false, message: hodScope.message, sessionExpired: hodScope.sessionExpired, totalStations: 0, totalChargers: 0, completedThisMonth: 0, pendingThisMonth: 0 };
    var callerRole = (hodScope.session.role || "").toString().trim().toLowerCase();
    function kpiStationVisible(engVal) {
      if (callerRole === 'engineer') {
        var eLow = (engVal || "").toString().trim().toLowerCase();
        return !!eLow && (eLow === engInput || (engInput && engInput.indexOf(eLow) !== -1) || eLow.indexOf(engInput) !== -1);
      }
      if (callerRole === 'hod' && hodScope.scoped) {
        return engineerInHodScopeV3(hodScope, engVal);
      }
      return true; // Admin, or unscoped HOD - unrestricted
    }

    var totalStationsSet = {};
    var totalChargersSet = {};
    
    // 1. Read Charger Inventory for Stations & Chargers (CP IDs)
    var inventorySheet = ss ? (ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory") || ss.getSheetByName("Sheet1")) : null;
    if (inventorySheet) {
      var invData = inventorySheet.getDataRange().getValues();
      var cols = getInventoryColumnIndexes(invData[0]);
      for (var i = 1; i < invData.length; i++) {
        var station = invData[i][cols.stationCol] ? invData[i][cols.stationCol].toString().trim() : "";
        var cpId = invData[i][cols.cpIdCol] ? invData[i][cols.cpIdCol].toString().trim() : "";
        var eng = invData[i][cols.engineerCol] ? invData[i][cols.engineerCol].toString().trim() : "";

        if (!station) continue;

        if (!kpiStationVisible(eng)) continue;

        totalStationsSet[station.toLowerCase()] = true;
        if (cpId) totalChargersSet[cpId.toLowerCase()] = true;
      }
    }

    var numStations = Object.keys(totalStationsSet).length;
    var numChargers = Object.keys(totalChargersSet).length;

    // 2. Read Completed PMs This Month across PM Civil & PM Charger Logs -
    // counts DISTINCT STATIONS completed, not raw submission rows (a station
    // can get more than one PM row in a month, e.g. a re-visit or both a
    // civil and a charger PM), so this must dedupe per station or the count
    // overstates how many stations were actually serviced.
    var targetDate = (monthStr && /^\d{4}-\d{2}$/.test(monthStr)) ? new Date(monthStr + '-01T00:00:00') : new Date();
    var currentYear = targetDate.getFullYear();
    var currentMonth = targetDate.getMonth();

    var completedStationSet = {};
    var pmTabs = [CONFIG_V2.SHEET_PM_CIVIL, CONFIG_V2.SHEET_PM_CHARGER];
    pmTabs.forEach(function(tName) {
      var sh = ss ? ss.getSheetByName(tName) : null;
      if (sh) {
        var d = sh.getDataRange().getValues();
        for (var r = 1; r < d.length; r++) {
          var timeVal = d[r][0];
          var engVal = d[r][1] ? d[r][1].toString().trim() : "";
          var stVal = d[r][2] ? d[r][2].toString().trim() : "";

          if (!kpiStationVisible(engVal)) continue;

          if (timeVal && stVal) {
            var dt = new Date(timeVal);
            if (!isNaN(dt.getTime()) && dt.getFullYear() === currentYear && dt.getMonth() === currentMonth) {
              completedStationSet[stVal.toLowerCase()] = true;
            }
          }
        }
      }
    });

    var completedThisMonth = Object.keys(completedStationSet).length;

    // 3. Pending PMs
    var pendingPMs = Math.max(0, numStations - completedThisMonth);

    return {
      success: true,
      totalStations: numStations,
      totalChargers: numChargers,
      completedThisMonth: completedThisMonth,
      pendingThisMonth: pendingPMs
    };
  } catch (e) {
    return {
      success: false,
      totalStations: 0,
      totalChargers: 0,
      completedThisMonth: 0,
      pendingThisMonth: 0
    };
  }
}

/**
 * 1. Resumable Upload Session URL (Drive API v3).
 * Enables direct client streaming for 100MB+ videos with progress tracking.
 */
function createResumableUploadUrlV2(fileName, mimeType, fileSize) {
  try {
    var folderName = "GOEC_TADA_Attachments";
    var folders = DriveApp.getFoldersByName(folderName);
    var folder = folders.hasNext() ? folders.next() : DriveApp.createFolder(folderName);
    folder.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    var folderId = folder.getId();

    var finalMime = mimeType || 'video/mp4';
    if (!mimeType || mimeType.trim() === '') {
      var ext = fileName ? fileName.split('.').pop().toLowerCase() : '';
      if (['mp4', 'mov', 'avi', 'mkv', '3gp', 'webm'].indexOf(ext) !== -1) {
        finalMime = 'video/mp4';
      } else if (['jpg', 'jpeg', 'png', 'webp', 'heic'].indexOf(ext) !== -1) {
        finalMime = 'image/jpeg';
      } else {
        finalMime = 'application/octet-stream';
      }
    }

    var metadata = {
      name: fileName || ('media_' + Date.now()),
      mimeType: finalMime,
      parents: [folderId]
    };

    var token = ScriptApp.getOAuthToken();
    var response = UrlFetchApp.fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable', {
      method: 'post',
      contentType: 'application/json; charset=UTF-8',
      headers: {
        'Authorization': 'Bearer ' + token,
        'X-Upload-Content-Type': finalMime
      },
      payload: JSON.stringify(metadata),
      muteHttpExceptions: true
    });

    var headers = response.getAllHeaders();
    var uploadUrl = headers['location'] || headers['Location'];

    if (uploadUrl) {
      return { success: true, uploadUrl: uploadUrl };
    } else {
      return { success: false, message: "UrlFetch response: " + response.getContentText() };
    }
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

/**
 * 2. Sets public view sharing on uploaded Google Drive file and returns viewable link.
 */
function setFilePublicV2(fileId) {
  try {
    if (!fileId) return { success: false, message: "No file ID provided" };
    var file = DriveApp.getFileById(fileId);
    file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    return {
      success: true,
      url: file.getUrl(),
      fileId: fileId
    };
  } catch (e) {
    return {
      success: true,
      url: "https://drive.google.com/open?id=" + fileId,
      fileId: fileId
    };
  }
}

/**
 * 3. Direct Base64 Media Upload to Google Drive (Zero extra permissions required).
 * Handles images & videos <= 35MB instantly.
 */
function uploadMediaToDriveV2(base64Data, fileName, mimeType) {
  try {
    var folderName = "GOEC_TADA_Attachments";
    var folder;
    try {
      var folders = DriveApp.getFoldersByName(folderName);
      folder = folders.hasNext() ? folders.next() : DriveApp.createFolder(folderName);
    } catch(errFolder) {
      folder = DriveApp.getRootFolder();
    }

    try {
      folder.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    } catch(errShare1) {}

    var finalMime = mimeType || 'image/jpeg';
    if (!mimeType || mimeType.trim() === '') {
      var ext = fileName ? fileName.split('.').pop().toLowerCase() : '';
      if (['mp4', 'mov', 'avi', 'mkv', '3gp', 'webm'].indexOf(ext) !== -1) {
        finalMime = 'video/mp4';
      } else if (['jpg', 'jpeg', 'png', 'webp', 'heic', 'pdf'].indexOf(ext) !== -1) {
        finalMime = ext === 'pdf' ? 'application/pdf' : 'image/jpeg';
      } else {
        finalMime = 'application/octet-stream';
      }
    }

    var decoded = Utilities.base64Decode(base64Data);
    var blob = Utilities.newBlob(decoded, finalMime, fileName || ('media_' + Date.now()));
    var file = folder.createFile(blob);

    try {
      file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    } catch(errShare2) {}

    var fileUrl = file.getUrl();
    return {
      success: true,
      url: fileUrl,
      fileName: fileName
    };
  } catch (e) {
    Logger.log("uploadMediaToDriveV2 Error: " + e.toString());
    return { success: false, message: e.toString() };
  }
}

function uploadMediaToDriveV3(base64Data, fileName, mimeType) {
  return uploadMediaToDriveV2(base64Data, fileName, mimeType);
}

function uploadMediaToDrive(base64Data, fileName, mimeType) {
  return uploadMediaToDriveV2(base64Data, fileName, mimeType);
}

function saveBase64ToDriveV3(base64Data, fileName, mimeType) {
  return uploadMediaToDriveV2(base64Data, fileName, mimeType);
}

function uploadFileV3(base64Data, fileName, mimeType) {
  return uploadMediaToDriveV2(base64Data, fileName, mimeType);
}


/**
 * Create a direct single-file Google Drive upload session URL for Client-to-Drive direct upload (Method 3).
 */
function createResumableDriveSessionV3(fileName, mimeType) {
  try {
    var folderName = "GOEC_TADA_Attachments";
    var folder;
    try {
      var folders = DriveApp.getFoldersByName(folderName);
      folder = folders.hasNext() ? folders.next() : DriveApp.createFolder(folderName);
    } catch(errFolder) {
      folder = DriveApp.getRootFolder();
    }

    try {
      folder.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    } catch(eShare) {}

    var token = ScriptApp.getOAuthToken();
    var finalMime = mimeType || 'video/mp4';
    var metadata = {
      name: fileName || ("video_" + Date.now() + ".mp4"),
      mimeType: finalMime,
      parents: [folder.getId()]
    };

    var response = UrlFetchApp.fetch("https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable", {
      method: "post",
      contentType: "application/json; charset=UTF-8",
      headers: {
        Authorization: "Bearer " + token,
        "X-Upload-Content-Type": finalMime
      },
      payload: JSON.stringify(metadata),
      muteHttpExceptions: true
    });

    var headers = response.getHeaders();
    var locationUrl = headers["Location"] || headers["location"] || headers["LOCATION"];

    if (!locationUrl) {
      return { success: false, message: "Could not obtain Drive session URL: " + response.getContentText() };
    }

    return {
      success: true,
      uploadUrl: locationUrl,
      fileMime: finalMime
    };
  } catch (e) {
    Logger.log("createResumableDriveSessionV3 Error: " + e.toString());
    return { success: false, message: e.toString() };
  }
}

function makeDriveFilePublicV3(fileId) {
  try {
    if (!fileId) return { success: false, message: "Missing fileId" };
    var file = DriveApp.getFileById(fileId);
    file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    return { success: true, url: file.getUrl() };
  } catch (e) {
    Logger.log("makeDriveFilePublicV3 Error: " + e.toString());
    return { success: false, message: e.toString() };
  }
}




/**
 * Automatically formats log sheets with dark headers, text wrapping, clean grid borders, and vertical centering.
 */
function formatLogSheetAestheticV2(sheet) {
  try {
    if (!sheet) return;
    var lastRow = sheet.getLastRow();
    var lastCol = sheet.getLastColumn();
    if (lastRow === 0 || lastCol === 0) return;

    // 1. Freeze Header Row
    sheet.setFrozenRows(1);

    // 2. Format Header Row (Row 1)
    var headerRange = sheet.getRange(1, 1, 1, lastCol);
    headerRange.setBackground("#1e293b"); // Sleek dark slate
    headerRange.setFontColor("#ffffff"); // White text
    headerRange.setFontWeight("bold");
    headerRange.setFontSize(11);
    headerRange.setVerticalAlignment("middle");
    headerRange.setWrap(true);
    headerRange.setHeight(36);

    // 3. Format Data Rows & Set Text Wrapping
    var fullRange = sheet.getRange(1, 1, lastRow, lastCol);
    fullRange.setWrap(true); // TEXT WRAPPING TURNED ON FOR ALL CELLS!
    fullRange.setVerticalAlignment("middle");
    
    // Set subtle grid borders
    fullRange.setBorder(true, true, true, true, true, true, "#cbd5e1", SpreadsheetApp.BorderStyle.SOLID);

    // Set row height for data rows so wrapped text looks spacious
    for (var r = 2; r <= lastRow; r++) {
      if (sheet.getRowHeight(r) < 28) {
        sheet.setRowHeight(r, 28);
      }
    }
  } catch (e) {
    Logger.log("formatLogSheetAestheticV2 error: " + e.toString());
  }
}

/**
 * Utility to format all log sheets currently in the spreadsheet.
 */
function formatAllLogSheetsV2() {
  var ss = getSpreadsheetV3();
  if (!ss) return;
  var sheetNames = [CONFIG_V2.SHEET_COMMISSIONING, CONFIG_V2.SHEET_PM_CIVIL, CONFIG_V2.SHEET_PM_CHARGER, CONFIG_V2.SHEET_TADA];
  sheetNames.forEach(function(sName) {
    var sh = ss.getSheetByName(sName);
    if (sh) formatLogSheetAestheticV2(sh);
  });
}

/**
 * Clean Date Formatter - Returns ONLY date (YYYY-MM-DD).
 */
function formatDateOnlyV2(val) {
  if (!val) return "Pending Schedule";
  try {
    var d = new Date(val);
    if (isNaN(d.getTime())) return val.toString();
    var year = d.getFullYear();
    var month = ("0" + (d.getMonth() + 1)).slice(-2);
    var day = ("0" + d.getDate()).slice(-2);
    return year + "-" + month + "-" + day;
  } catch (e) {
    return val.toString();
  }
}

/**
 * Safely creates an HTML template handling any filename extension variations (.html or no extension).
 */
function createTemplateSafelyV2(filename) {
  var cleanName = filename.toString().replace(/\.html$/i, "");
  try {
    return HtmlService.createTemplateFromFile(cleanName);
  } catch (e1) {
    try {
      return HtmlService.createTemplateFromFile(cleanName + '.html');
    } catch (e2) {
      try {
        return HtmlService.createTemplateFromFile(filename);
      } catch (e3) {
        throw new Error("Template file not found: " + filename);
      }
    }
  }
}

/**
 * Helper for safely including HTML templates inside other HTML templates.
 */
function includeV2(filename) {
  var cleanName = filename.toString().replace(/\.html$/i, "");
  try {
    return HtmlService.createTemplateFromFile(cleanName).getRawContent();
  } catch (err0) {
    try {
      return HtmlService.createHtmlOutputFromFile(cleanName).getContent();
    } catch (err1) {
      try {
        return HtmlService.createHtmlOutputFromFile(cleanName + '.html').getContent();
      } catch (err2) {
        try {
          return HtmlService.createHtmlOutputFromFile(filename).getContent();
        } catch (err3) {
          Logger.log("includeV2 failed for " + filename + ": " + err3.toString());
          return "<!-- Error including " + filename + ": " + err3.toString() + " -->";
        }
      }
    }
  }
}

/**
 * Returns raw HTML content of a sub-template file for client-side lazy loading.
 * Called from the client via google.script.run.getSubTemplateV2(filename).
 * Uses getRawContent() to bypass the Caja HTML sanitizer entirely since
 * the content is returned as a string, not as HtmlOutput.
 */
function getSubTemplateV2(filename) {
  var cleanName = filename.toString().replace(/\.html$/i, "");
  try {
    return HtmlService.createTemplateFromFile(cleanName).getRawContent();
  } catch (e1) {
    try {
      return HtmlService.createHtmlOutputFromFile(cleanName).getContent();
    } catch (e2) {
      try {
        return HtmlService.createTemplateFromFile(cleanName + '.html').getRawContent();
      } catch (e3) {
        throw new Error("Template not found: " + filename);
      }
    }
  }
}


/**
 * Simple SHA-256 password hashing helper.
 */
function hashPasswordV2(str) {
  if (!str) return "";
  var rawHash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, str, Utilities.Charset.UTF_8);
  var txtHash = "";
  for (var j = 0; j < rawHash.length; j++) {
    var pad = (rawHash[j] < 0 ? rawHash[j] + 256 : rawHash[j]).toString(16);
    txtHash += (pad.length == 1 ? "0" + pad : pad);
  }
  return txtHash;
}

function getCPDetailsForStationV2(stationName) {
  try {
    var ss = getSpreadsheetV3();
    var sheet = ss ? (ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory") || ss.getSheetByName("Sheet1")) : null;
    if (!sheet) return { success: false, cpList: [] };

    var data = sheet.getDataRange().getValues();
    var headers = data[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });

    var colStation = headers.indexOf("station name");
    if (colStation === -1) colStation = 1;

    var colCp = headers.indexOf("cp id");
    if (colCp === -1) colCp = headers.indexOf("cpid");
    if (colCp === -1) colCp = 2;

    var colSerial = headers.indexOf("serial no");
    if (colSerial === -1) colSerial = headers.indexOf("serial number");
    if (colSerial === -1) colSerial = headers.indexOf("charger serial no.");
    if (colSerial === -1) colSerial = 3;

    var colOem = headers.indexOf("oem name");
    if (colOem === -1) colOem = headers.indexOf("oem");
    if (colOem === -1) colOem = 4;

    var colPower = headers.indexOf("power(kw)");
    if (colPower === -1) colPower = headers.indexOf("power");
    if (colPower === -1) colPower = headers.indexOf("capacity");
    if (colPower === -1) colPower = 6;

    var stInput = stationName ? stationName.toString().trim().toLowerCase() : "";
    var cpList = [];

    for (var i = 1; i < data.length; i++) {
      var stVal = data[i][colStation] ? data[i][colStation].toString().trim().toLowerCase() : "";
      if (stInput && stVal === stInput) {
        var cpId = data[i][colCp] ? data[i][colCp].toString().trim() : "";
        var serial = data[i][colSerial] ? data[i][colSerial].toString().trim() : "";
        var oem = data[i][colOem] ? data[i][colOem].toString().trim() : "";
        var power = data[i][colPower] ? data[i][colPower].toString().trim() : "";

        if (cpId) {
          cpList.push({
            rowIndex: i + 1,
            cpId: cpId,
            serialNo: serial,
            oem: oem,
            power: power
          });
        }
      }
    }

    return { success: true, cpList: cpList };
  } catch (e) {
    return { success: false, message: e.toString(), cpList: [] };
  }
}

/**
 * Updates Charger Inventory sheet when engineer modifies Serial No, OEM, or Capacity!
 */
/**
 * Updates Charger Inventory sheet when engineer modifies Serial No, OEM, or Capacity during a PM!
 */
function updateChargerInventoryV2(cpId, serialNo, oem, capacity, locationName) {
  try {
    var ss = getSpreadsheetV3();
    var sheet = ss ? (ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory") || ss.getSheetByName("Sheet1")) : null;
    if (!sheet) return;

    var data = sheet.getDataRange().getValues();
    if (data.length < 2) return;

    var headers = data[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });

    var colCp = headers.indexOf("cp id");
    if (colCp === -1) colCp = headers.indexOf("charge point id");
    if (colCp === -1) colCp = headers.indexOf("cpid");
    if (colCp === -1) colCp = 2;

    var colSerial = headers.indexOf("serial no.");
    if (colSerial === -1) colSerial = headers.indexOf("serial no");
    if (colSerial === -1) colSerial = headers.indexOf("serial number");
    if (colSerial === -1) colSerial = headers.indexOf("charger serial no.");
    if (colSerial === -1) colSerial = 3;

    var colOem = headers.indexOf("oem name");
    if (colOem === -1) colOem = headers.indexOf("oem");
    if (colOem === -1) colOem = 4;

    var colPower = headers.indexOf("power (kw)");
    if (colPower === -1) colPower = headers.indexOf("power(kw)");
    if (colPower === -1) colPower = headers.indexOf("power");
    if (colPower === -1) colPower = headers.indexOf("capacity");
    if (colPower === -1) colPower = 6;

    var colLoc = headers.indexOf("location name");
    if (colLoc === -1) colLoc = headers.indexOf("location");
    if (colLoc === -1) colLoc = 1;

    var qCpKey = cpId ? cleanPMKeyV2(cpId) : "";
    var qLocKey = locationName ? cleanPMKeyV2(locationName) : "";

    var matchRowIndex = -1;

    // 1. Try matching by CP ID first
    if (qCpKey) {
      for (var i = 1; i < data.length; i++) {
        var rowCp = data[i][colCp] ? cleanPMKeyV2(data[i][colCp]) : "";
        if (rowCp && (rowCp === qCpKey || isPMStationMatchV2(rowCp, qCpKey))) {
          matchRowIndex = i + 1;
          break;
        }
      }
    }

    // 2. Fallback: try matching by Location Name if CP ID was not matched
    if (matchRowIndex === -1 && qLocKey) {
      for (var j = 1; j < data.length; j++) {
        var rowLoc = data[j][colLoc] ? cleanPMKeyV2(data[j][colLoc]) : "";
        if (rowLoc && (rowLoc === qLocKey || isPMStationMatchV2(rowLoc, qLocKey))) {
          matchRowIndex = j + 1;
          break;
        }
      }
    }

    if (matchRowIndex > 0) {
      if (serialNo) sheet.getRange(matchRowIndex, colSerial + 1).setValue(serialNo);
      if (oem) sheet.getRange(matchRowIndex, colOem + 1).setValue(oem);
      if (capacity) sheet.getRange(matchRowIndex, colPower + 1).setValue(capacity);
      Logger.log("Successfully updated Charger Inventory at row " + matchRowIndex + ": CP ID = " + cpId + ", Serial No = " + serialNo);
    } else {
      Logger.log("updateChargerInventoryV2: No matching charger found in inventory for CP ID '" + cpId + "' / Location '" + locationName + "'");
    }
  } catch (e) {
    Logger.log("updateChargerInventoryV2 error: " + e.toString());
  }
}

function getHODSummaryV2(monthStr, token) {
  try {
    var ss = getSpreadsheetV3();
    var users = getUsersListV2();

    var fieldEngineers = users.filter(function(u) {
      return u.role === "Engineer" && u.username.toLowerCase() !== "admin" && u.username.toLowerCase() !== "hod";
    });

    // HOD only sees their assigned engineers in this table.
    var hodScope = getHodEngineerScopeV3(token);
    if (!hodScope.ok) return null;
    if (hodScope.scoped) {
      fieldEngineers = fieldEngineers.filter(function(u) {
        return engineerInHodScopeV3(hodScope, u.fullName || u.username);
      });
    }

    var canonicalNameMap = {}; // engKey -> Display Name
    var engKeyLookup = {};     // lowercase token -> engKey

    fieldEngineers.forEach(function(e) {
      var name = (e.fullName || e.username || "").trim();
      if (name) {
        var key = name.toLowerCase();
        if (!canonicalNameMap[key]) {
          canonicalNameMap[key] = name;
          var firstToken = key.split(" ")[0];
          if (firstToken && firstToken.length >= 3 && !engKeyLookup[firstToken]) {
            engKeyLookup[firstToken] = key;
          }
        }
      }
    });

    function resolveEngKey(rawName) {
      if (!rawName) return "";
      var rLower = rawName.toString().trim().toLowerCase();
      if (!rLower) return "";
      if (canonicalNameMap[rLower]) return rLower;
      
      var firstToken = rLower.split(" ")[0];
      if (firstToken && engKeyLookup[firstToken]) {
        return engKeyLookup[firstToken];
      }
      canonicalNameMap[rLower] = rawName.trim();
      return rLower;
    }

    var now = new Date();
    // "Delayed" always compares against today, regardless of which month is
    // being viewed - but "completed this month" tracks whichever month the
    // HOD picked (or the current one, if none was picked).
    var todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    var targetDate = (monthStr && /^\d{4}-\d{2}$/.test(monthStr)) ? new Date(monthStr + '-01T00:00:00') : now;
    var currentYear = targetDate.getFullYear();
    var currentMonth = targetDate.getMonth();

    // 1. Read Charger Inventory to get Scope & Delayed Stations per Engineer
    var engStations = {}; // engKey -> set of unique station names
    var engDelayed = {};  // engKey -> set of delayed unique station names
    var stationDisplayNameMapV3 = {}; // lowercase station key -> original-cased display name

    var inventorySheet = ss ? (ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory") || ss.getSheetByName("Sheet1")) : null;
    if (inventorySheet) {
      var invData = inventorySheet.getDataRange().getValues();
      if (invData.length > 1) {
        var iHeaders = invData[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });

        var colSt = iHeaders.indexOf("location name");
        if (colSt === -1) colSt = iHeaders.indexOf("evcs location name");
        if (colSt === -1) colSt = iHeaders.indexOf("station name");
        if (colSt === -1) colSt = iHeaders.indexOf("station");
        if (colSt === -1) colSt = 1;

        var colEng = iHeaders.indexOf("engineer");
        if (colEng === -1) colEng = iHeaders.indexOf("assigned engineer");
        if (colEng === -1) colEng = 7;

        var colDue = iHeaders.indexOf("pm due date");
        if (colDue === -1) colDue = 8;
        if (colDue >= invData[0].length) colDue = invData[0].length - 1;

        for (var j = 1; j < invData.length; j++) {
          var stName = invData[j][colSt] ? invData[j][colSt].toString().trim() : "";
          var assignedEng = invData[j][colEng] ? invData[j][colEng].toString().trim() : "";
          var dueDateStr = (colDue >= 0 && colDue < invData[j].length) ? invData[j][colDue] : "";

          if (stName && assignedEng) {
            var eKey = resolveEngKey(assignedEng);
            var stKeyLower = stName.toLowerCase();
            if (!stationDisplayNameMapV3[stKeyLower]) stationDisplayNameMapV3[stKeyLower] = stName;
            if (!engStations[eKey]) engStations[eKey] = {};
            engStations[eKey][stKeyLower] = true;

            var isDelayed = false;
            if (dueDateStr) {
              var due = new Date(dueDateStr);
              if (!isNaN(due.getTime()) && due.setHours(0,0,0,0) < todayStart) {
                isDelayed = true;
              }
            }

            if (isDelayed) {
              if (!engDelayed[eKey]) engDelayed[eKey] = {};
              engDelayed[eKey][stName.toLowerCase()] = true;
            }
          }
        }
      }
    }

    // 2. Read PM Civil & Electrical Log for Completed & Verified PMs
    var engCompletedThisMonth = {};  // engKey -> count of DISTINCT stations completed this month
    var completedStationMapV3 = {};  // engKey -> { stationLower: true } - dedupes rows into stations
    var engVerifiedCount = {};      // engKey -> count of verified PMs
    var verifiedStationMap = {};    // engKey -> { stationLower: true }
    var concerns = [];

    var civilSheet = ss ? (ss.getSheetByName(CONFIG_V2.SHEET_PM_CIVIL) || ss.getSheetByName("PM_ElectricalCivil_Log")) : null;
    if (civilSheet) {
      var civilData = civilSheet.getDataRange().getValues();
      if (civilData.length > 1) {
        var cHeaders = civilData[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
        var colVerif = cHeaders.indexOf("verification status");
        if (colVerif === -1) colVerif = cHeaders.indexOf("verified");
        if (colVerif === -1) colVerif = 25; // Default column Z (26th col)

        for (var i = 1; i < civilData.length; i++) {
          var row = civilData[i];
          var timeVal = row[0];
          var engName = row[1] ? row[1].toString().trim() : "";
          var stLoc = row[2] ? row[2].toString().trim() : "";
          var remarks = row[23] ? row[23].toString().trim() : "";

          if (engName) {
            var eKey = resolveEngKey(engName);
            if (timeVal && stLoc) {
              var dt = new Date(timeVal);
              if (!isNaN(dt.getTime()) && dt.getFullYear() === currentYear && dt.getMonth() === currentMonth) {
                var compKey = stLoc.toLowerCase();
                if (!stationDisplayNameMapV3[compKey]) stationDisplayNameMapV3[compKey] = stLoc;
                if (!completedStationMapV3[eKey]) completedStationMapV3[eKey] = {};
                if (!completedStationMapV3[eKey][compKey]) {
                  completedStationMapV3[eKey][compKey] = true;
                  engCompletedThisMonth[eKey] = (engCompletedThisMonth[eKey] || 0) + 1;
                }
              }
            }

            // "Verified" only counts if the PM row it applies to was submitted
            // in the selected month - otherwise a station verified last month
            // (or any earlier month) would keep showing as verified forever,
            // regardless of which month the HOD is currently viewing.
            var isRowInSelectedMonth = false;
            if (timeVal) {
              var vDt = new Date(timeVal);
              isRowInSelectedMonth = !isNaN(vDt.getTime()) && vDt.getFullYear() === currentYear && vDt.getMonth() === currentMonth;
            }
            var verifVal = (colVerif < row.length && row[colVerif]) ? row[colVerif].toString().trim().toUpperCase() : "";
            if (isRowInSelectedMonth && (verifVal === "VERIFIED" || row[22] === "VERIFIED" || row[23] === "VERIFIED" || row[24] === "VERIFIED" || row[25] === "VERIFIED")) {
              if (!verifiedStationMap[eKey]) verifiedStationMap[eKey] = {};
              var stKey = stLoc ? stLoc.toLowerCase().trim() : ("pm_" + i);
              if (!verifiedStationMap[eKey][stKey]) {
                verifiedStationMap[eKey][stKey] = true;
                engVerifiedCount[eKey] = (engVerifiedCount[eKey] || 0) + 1;
              }
            }
          }

          if (remarks && remarks.length > 5) {
            concerns.push({
              station: stLoc || "EV Station",
              engineer: engName || "Service Engineer",
              issues: remarks,
              form: "PM Electrical & Civil"
            });
          }
        }
      }
    }

    // Also check Charger Sheet for Verified Status
    var chgSheet = ss ? (ss.getSheetByName(CONFIG_V2.SHEET_PM_CHARGER) || ss.getSheetByName("PM_Charger_Log")) : null;
    if (chgSheet) {
      var chgData = chgSheet.getDataRange().getValues();
      if (chgData.length > 1) {
        var chgHeaders = chgData[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
        var colVerifChg = chgHeaders.indexOf("verification status");
        if (colVerifChg === -1) colVerifChg = chgHeaders.indexOf("verified");
        if (colVerifChg === -1) colVerifChg = 26;

        for (var c = 1; c < chgData.length; c++) {
          var chgRow = chgData[c];
          var chgEng = chgRow[1] ? chgRow[1].toString().trim() : "";
          var chgSt = chgRow[2] ? chgRow[2].toString().trim() : "";
          if (chgEng) {
            var eKeyChg = resolveEngKey(chgEng);
            var chgIsRowInSelectedMonth = false;
            if (chgRow[0]) {
              var chgDt = new Date(chgRow[0]);
              chgIsRowInSelectedMonth = !isNaN(chgDt.getTime()) && chgDt.getFullYear() === currentYear && chgDt.getMonth() === currentMonth;
            }
            var vVal = (colVerifChg < chgRow.length && chgRow[colVerifChg]) ? chgRow[colVerifChg].toString().trim().toUpperCase() : "";
            if (chgIsRowInSelectedMonth && (vVal === "VERIFIED" || chgRow[25] === "VERIFIED" || chgRow[26] === "VERIFIED" || chgRow[30] === "VERIFIED")) {
              if (!verifiedStationMap[eKeyChg]) verifiedStationMap[eKeyChg] = {};
              var stKeyChg = chgSt ? chgSt.toLowerCase().trim() : ("chg_" + c);
              if (!verifiedStationMap[eKeyChg][stKeyChg]) {
                verifiedStationMap[eKeyChg][stKeyChg] = true;
                engVerifiedCount[eKeyChg] = (engVerifiedCount[eKeyChg] || 0) + 1;
              }
            }
          }
        }
      }
    }

    // 3. Build Engineer Performance Stats List
    function stationKeysToNamesV3(keySet) {
      return Object.keys(keySet || {}).map(function(k) { return stationDisplayNameMapV3[k] || k; }).sort();
    }

    var engineerKeys = Object.keys(canonicalNameMap);
    var engineerStats = engineerKeys.map(function(key) {
      var engName = canonicalNameMap[key];

      var scopeStationsSet = engStations[key] || {};
      var completedStationsSet = completedStationMapV3[key] || {};
      var delayedStationsSet = engDelayed[key] || {};
      var verifiedStationsSet = verifiedStationMap[key] || {};

      var pendingStationsSet = {};
      Object.keys(scopeStationsSet).forEach(function(k) {
        if (!completedStationsSet[k]) pendingStationsSet[k] = true;
      });

      var scope = Object.keys(scopeStationsSet).length;
      var completed = Object.keys(completedStationsSet).length;
      var verified = engVerifiedCount[key] || 0;
      var verifiedPercent = completed > 0 ? Math.min(100, Math.round((verified / completed) * 100)) : (scope > 0 && verified > 0 ? Math.min(100, Math.round((verified / scope) * 100)) : 0);
      var delayed = Object.keys(delayedStationsSet).length;
      var pending = Object.keys(pendingStationsSet).length;

      return {
        name: engName,
        scope: scope,
        completed: completed,
        verified: verified,
        verifiedPercent: verifiedPercent,
        delayed: delayed,
        pending: pending,
        scopeStations: stationKeysToNamesV3(scopeStationsSet),
        completedStations: stationKeysToNamesV3(completedStationsSet),
        delayedStations: stationKeysToNamesV3(delayedStationsSet),
        pendingStations: stationKeysToNamesV3(pendingStationsSet),
        verifiedStations: stationKeysToNamesV3(verifiedStationsSet)
      };
    });

    // Sort engineers in Alphabetical Order A-Z
    engineerStats.sort(function(a, b) {
      return (a.name || "").localeCompare(b.name || "");
    });

    return {
      engineerStats: engineerStats,
      concerns: concerns.length > 0 ? concerns.slice(0, 5) : [
        { station: "All Stations Operational", engineer: "System", issues: "No critical points of concern reported in logs.", form: "System Status" }
      ]
    };
  } catch (e) {
    return null;
  }
}


/**
 * Smart Analytics Logs Fetchers V2
 */
function loadCommissioningLogsV2(token) {
  try {
    var scope = getHodEngineerScopeV3(token);
    if (!scope.ok) return { success: false, message: scope.message, sessionExpired: scope.sessionExpired, logs: [] };
    var ss = getSpreadsheetV3();
    var sheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_COMMISSIONING) : null;
    if (!sheet) return { success: true, logs: [] };

    ensureSubmissionIdsBackfilledV3(sheet, SUBMISSION_SHEETS_V3.commissioning);
    var data = sheet.getDataRange().getValues();
    if (data.length <= 1) return { success: true, logs: [] };

    var logs = [];
    for (var i = 1; i < data.length; i++) {
      var row = data[i];
      if (!row || row.length === 0 || !row[0]) continue;

      // Payload JSON is always at fixed index 37 (Commissioning Log's declared
      // header length is 38) - don't use "last column", since RecordID/
      // SubmissionID now live in trailing columns after it.
      var rawPayloadStr = row.length > 37 ? row[37] : row[row.length - 1];
      if (typeof rawPayloadStr !== 'string' || rawPayloadStr.indexOf('{') === -1) {
        rawPayloadStr = row[1];
      }

      var payload = {};
      if (typeof rawPayloadStr === 'string' && rawPayloadStr.trim().indexOf('{') === 0) {
        try {
          payload = JSON.parse(rawPayloadStr);
        } catch(e) {}
      }

      logs.push({
        id: 'COMM_' + i,
        recordId: row.length > 38 ? (row[38] ? row[38].toString() : '') : '',
        timestamp: row[0] ? row[0].toString() : new Date().toLocaleString(),
        engineer: payload.engineer || payload.engineerName || (row[1] ? row[1].toString() : 'Unknown'),
        stationName: payload.locationName || payload.stationName || (row[2] ? row[2].toString() : 'EV Station'),
        visitDate: payload.visitDate || (row[3] ? row[3].toString() : ''),
        oem: payload.oem || (row[4] ? row[4].toString() : 'N/A'),
        capacity: payload.capacity || (row[5] ? row[5].toString() : 'N/A'),
        serialNo: payload.serialNo || (row[6] ? row[6].toString() : ''),
        brandingStickerStatus: payload.brandingStickerStatus || (row[7] ? row[7].toString() : ''),
        instructionBoardStatus: payload.instructionBoardStatus || (row[8] ? row[8].toString() : ''),
        canopyBackdropStatus: payload.canopyBackdropStatus || (row[9] ? row[9].toString() : ''),
        externalLightBoardStatus: payload.externalLightBoardStatus || (row[10] ? row[10].toString() : ''),
        syntaxBoxSmps: payload.syntaxBoxSmps || (row[11] ? row[11].toString() : ''),
        canopySquareLightStatus: payload.canopySquareLightStatus || (row[12] ? row[12].toString() : ''),
        canopyBrandingLightStatus: payload.canopyBrandingLightStatus || (row[13] ? row[13].toString() : ''),
        sdCardStatus: payload.sdCardStatus || (row[14] ? row[14].toString() : ''),
        cctvStatus: payload.cctvStatus || (row[15] ? row[15].toString() : ''),
        fireExtinguisherStatus: payload.fireExtinguisherStatus || (row[16] ? row[16].toString() : ''),
        modemStatus: payload.modemStatus || (row[17] ? row[17].toString() : ''),
        bollardStatus: payload.bollardStatus || (row[18] ? row[18].toString() : ''),
        transformerCapacity: payload.transformerCapacity || (row[19] ? row[19].toString() : ''),
        cableSizeTransformerToLt: payload.cableSizeTransformerToLt || (row[20] ? row[20].toString() : ''),
        cableSizeLtToCharger: payload.cableSizeLtToCharger || (row[21] ? row[21].toString() : ''),
        timerContactorStatus: payload.timerContactorStatus || (row[22] ? row[22].toString() : ''),
        canopyHoleDamage: payload.canopyHoleDamage || (row[23] ? row[23].toString() : ''),
        ltPanelCoatingCondition: payload.ltPanelCoatingCondition || (row[24] ? row[24].toString() : ''),
        mfmSpdElrWorking: payload.mfmSpdElrWorking || (row[25] ? row[25].toString() : ''),
        spdRating: payload.spdRating || (row[26] ? row[26].toString() : ''),
        lightningConcealedConduit: payload.lightningConcealedConduit || (row[27] ? row[27].toString() : ''),
        civilStructureCondition: payload.civilStructureCondition || (row[28] ? row[28].toString() : ''),
        parkingPaintingStatus: payload.parkingPaintingStatus || (row[29] ? row[29].toString() : ''),
        interlockStatus: payload.interlockStatus || (row[30] ? row[30].toString() : ''),
        simNumber: payload.simNumber || (row[31] ? row[31].toString() : ''),
        remarks: payload.remarks || (row[32] ? row[32].toString() : ''),
        fullStationImage: payload.fullStationImage || (row[33] ? row[33].toString() : ''),
        panelPhoto: payload.panelPhoto || (row[34] ? row[34].toString() : ''),
        placementOfPanel: payload.placementOfPanel || (row[35] ? row[35].toString() : ''),
        mcbMapping: payload.mcbMapping || (row[36] ? row[36].toString() : ''),
        chargers: payload.chargers || [],
        sims: payload.sims || []
      });
    }
    if (scope.ok && scope.scoped) {
      logs = logs.filter(function(l) { return engineerInHodScopeV3(scope, l.engineer); });
    }
    return { success: true, logs: logs };
  } catch (e) {
    return { success: false, message: e.toString(), logs: [] };
  }
}

function loadTADALogsV2() {
  try {
    var ss = getSpreadsheetV3();
    var sheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_TADA) : null;
    if (!sheet) return { success: true, logs: [] };

    var data = sheet.getDataRange().getValues();
    if (data.length <= 1) return { success: true, logs: [] };

    var headers = data[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
    var colTime = headers.indexOf("timestamp");
    var colEng = headers.indexOf("engineer");
    var colDate = headers.indexOf("travel date");
    var colPurpose = headers.indexOf("purpose of visit");
    if (colPurpose === -1) colPurpose = headers.indexOf("purpose");
    var colAmount = headers.indexOf("total amount (\u20b9)");
    if (colAmount === -1) colAmount = headers.indexOf("amount");

    var logs = [];
    for (var i = 1; i < data.length; i++) {
      var row = data[i];
      if (!row || row.length === 0 || !row[0]) continue;

      var raw = row[1];
      var isJson = false;
      var payload = {};

      if (typeof raw === 'string' && raw.trim().indexOf('{') === 0) {
        try {
          payload = JSON.parse(raw);
          isJson = true;
        } catch(e) {}
      }

      if (isJson) {
        logs.push({
          claimId: 'CLM-' + (1000 + i),
          timestamp: row[0] ? row[0].toString() : new Date().toLocaleString(),
          engineer: payload.engineer || 'Unknown',
          travelDate: payload.travelDate || '',
          purpose: payload.purpose || '',
          amount: payload.amount || 0,
          remarks: payload.remarks || ''
        });
      } else {
        var timeVal = colTime !== -1 ? row[colTime] : row[0];
        var engVal = colEng !== -1 ? row[colEng] : row[1];
        var dateVal = colDate !== -1 ? row[colDate] : row[2];
        var purpVal = colPurpose !== -1 ? row[colPurpose] : row[3];
        var amtVal = colAmount !== -1 ? row[colAmount] : row[4];

        logs.push({
          claimId: 'CLM-' + (1000 + i),
          timestamp: timeVal ? timeVal.toString() : new Date().toLocaleString(),
          engineer: engVal ? engVal.toString() : 'Unknown',
          travelDate: dateVal ? dateVal.toString() : '',
          purpose: purpVal ? purpVal.toString() : '',
          amount: amtVal ? Number(amtVal) || 0 : 0,
          remarks: 'Tabular Log'
        });
      }
    }
    return { success: true, logs: logs };
  } catch (e) {
    return { success: false, message: e.toString(), logs: [] };
  }
}

/**
 * Fetches unique list data for dropdown options from Charger Inventory (Columns E & G).
 */
function getSheet1DataV3(requestedKeys) {
  try {
    var ss = getSpreadsheetV3();
    var res = { engineers: [], oems: [], powers: [], simInventory: [] };
    
    if (!ss) return res;

    // READ CHARGER INVENTORY
    var inventorySheet = ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory") || ss.getSheetByName("Sheet1") || ss.getSheets()[0];
    if (inventorySheet) {
      var data = inventorySheet.getDataRange().getValues();
      var engSet = {}, oemSet = {}, pwrSet = {};

      for (var i = 1; i < data.length; i++) {
        var row = data[i];
        var eng = row[7] || row[1];
        var oem = row[4];
        var pwr = row[6];

        if (eng && eng.toString().trim()) engSet[eng.toString().trim()] = true;
        if (oem && oem.toString().trim()) oemSet[oem.toString().trim()] = true;
        if (pwr && pwr.toString().trim()) pwrSet[pwr.toString().trim()] = true;
      }

      res.engineers = Object.keys(engSet).sort();
      res.oems = Object.keys(oemSet).sort();
      res.powers = Object.keys(pwrSet).sort();
    }

    if (res.oems.length === 0) res.oems = ["Exicom", "Kempower", "Servotech", "Delta", "ABB", "Tritium"];
    if (res.powers.length === 0) res.powers = ["30kW", "60kW", "120kW", "180kW", "240kW", "360kW"];

    if (res.oems.indexOf("Other") === -1) res.oems.push("Other");
    if (res.powers.indexOf("Other") === -1) res.powers.push("Other");

    return res;
  } catch (err) {
    return {
      engineers: ["Anand", "Deepak", "Jishnu", "Nithin", "Rahul", "Vikas"],
      oems: ["Exicom", "Kempower", "Delta", "Other"],
      powers: ["30kW", "60kW", "120kW", "Other"],
      simInventory: ["Other"]
    };
  }
}

/**
 * Public endpoint to fetch OEM and Capacity options dynamically for Commissioning form.
 */
function getOemsAndCapacitiesV2() {
  return getSheet1DataV3(["oems", "powers"]);
}


/**
 * Fetches SIM Cards assigned specifically to an engineer that have NO location assigned yet.
 */
function getAvailableSimsForEngineerV2(engineerName) {
  try {
    var ss = getSpreadsheetV3();
    var simSheet = ss ? (ss.getSheetByName(CONFIG_V3.SHEET_SIM) || ss.getSheetByName("Sim Inventory")) : null;
    if (!simSheet) return ["Other"];

    var simData = simSheet.getDataRange().getValues();
    if (simData.length <= 1) return ["Other"];

    var info = findHeaderRowAndIndexes(simData);
    var colSim = info.colSim;
    var colEng = info.colEng;
    var colLoc = info.colLoc;

    var engInput = engineerName ? engineerName.toString().trim().toLowerCase() : "";
    var availableSims = [];

    for (var s = info.headerRowIdx + 1; s < simData.length; s++) {
      var row = simData[s];
      if (!row) continue;

      var simNum = row[colSim] ? row[colSim].toString().trim() : "";
      if (!simNum) continue;

      var sLow = simNum.toLowerCase().replace(/[^a-z0-9]/g, "");
      if (sLow === "sim" || sLow === "simnum" || sLow === "simnumber" || sLow === "simcard") continue;

      var engVal = row[colEng] ? row[colEng].toString().trim().toLowerCase() : "";
      var locVal = row[colLoc] ? row[colLoc].toString().trim() : "";

      var isSupervisor = isAdminOrHodUserV3(engInput);
      if (!isSupervisor) {
        // Engineer user: only show SIM cards assigned directly to them
        if (engVal && (engVal === engInput || engInput.indexOf(engVal) !== -1 || engVal.indexOf(engInput) !== -1)) {
          availableSims.push(simNum);
        }
      } else {
        // Supervisor/Admin user: show all unassigned or matching in stock SIMs
        if (!locVal || locVal.length === 0 || locVal === "In Stock / Warehouse") {
          if (!engInput || !engVal || engVal === "unassigned" || engVal === engInput || engInput.indexOf(engVal) !== -1 || engVal.indexOf(engInput) !== -1) {
            availableSims.push(simNum);
          }
        }
      }
    }

    if (availableSims.indexOf("Other") === -1) {
      availableSims.push("Other");
    }

    return availableSims;
  } catch (e) {
    return ["Other"];
  }
}

/**
 * Automatically calculates next month same day for PM Due Date.
 */
function calculateNextMonthSameDayV2(dateStr) {
  try {
    var dt = dateStr ? new Date(dateStr) : new Date();
    if (isNaN(dt.getTime())) dt = new Date();

    var origDay = dt.getDate();
    dt.setMonth(dt.getMonth() + 1);

    // Month rollover correction (e.g. Jan 31 -> Feb 28/29)
    if (dt.getDate() !== origDay) {
      dt.setDate(0);
    }

    var day = ("0" + dt.getDate()).slice(-2);
    var month = ("0" + (dt.getMonth() + 1)).slice(-2);
    var year = dt.getFullYear();

    return day + "/" + month + "/" + year; // Format: DD/MM/YYYY
  } catch (e) {
    return "";
  }
}

/**
 * Adds or updates newly commissioned charger into Charger Inventory sheet!
 * Automatically populates Location Name, Serial No, OEM, Power, Engineer, and PM Due Date (1 month after commission date).
 */
function addCommissionedChargerToInventoryV2(payload) {
  try {
    var ss = getSpreadsheetV3();
    var invSheet = ss ? (ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory") || ss.getSheetByName("Sheet1")) : null;
    if (!invSheet) return;

    var invData = invSheet.getDataRange().getValues();
    var headers = invData.length > 0 ? invData[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; }) : [];

    var colLocName = headers.indexOf("location name");
    if (colLocName === -1) colLocName = 1;

    var colCpId = headers.indexOf("charge point id");
    if (colCpId === -1) colCpId = headers.indexOf("cp id");
    if (colCpId === -1) colCpId = 2;

    var colSerial = headers.indexOf("serial number");
    if (colSerial === -1) colSerial = headers.indexOf("serial no");
    if (colSerial === -1) colSerial = 3;

    var colOem = headers.indexOf("oem name");
    if (colOem === -1) colOem = headers.indexOf("oem");
    if (colOem === -1) colOem = 4;

    var colType = headers.indexOf("connector stan");
    if (colType === -1) colType = headers.indexOf("connector type");
    if (colType === -1) colType = 5;

    var colPower = headers.indexOf("power (kw)");
    if (colPower === -1) colPower = headers.indexOf("power(kw)");
    if (colPower === -1) colPower = headers.indexOf("power");
    if (colPower === -1) colPower = 6;

    var colEng = headers.indexOf("engineer");
    if (colEng === -1) colEng = 7;

    var colPmDate = headers.indexOf("pm due date");
    if (colPmDate === -1) colPmDate = 8;

    var locInput = payload.locationName || payload.stationName || "";
    var engInput = payload.engineer || payload.engineerName || "";
    var visitDate = payload.visitDate || payload.timestamp || new Date().toISOString();
    var nextPmDueDate = calculateNextMonthSameDayV2(visitDate);

    var rawList = [];
    if (payload.chargers && Array.isArray(payload.chargers) && payload.chargers.length > 0) {
      rawList = payload.chargers;
    } else {
      rawList = [{
        cpId: payload.cpId || "",
        serialNo: payload.serialNo || "",
        oem: payload.oem || "",
        capacity: payload.capacity || ""
      }];
    }

    var expandedChargers = [];
    rawList.forEach(function(item) {
      var cpStr = (item.cpId || "").toString();
      var serialStr = (item.serialNo || "").toString();
      var oemStr = (item.oem || "").toString();
      var capStr = (item.capacity || "").toString();

      if (cpStr.indexOf(',') !== -1 || serialStr.indexOf(',') !== -1 || oemStr.indexOf(',') !== -1 || capStr.indexOf(',') !== -1) {
        var cpArr = cpStr.split(',').map(function(s) { return s.trim(); });
        var serialArr = serialStr.split(',').map(function(s) { return s.trim(); });
        var oemArr = oemStr.split(',').map(function(s) { return s.trim(); });
        var capArr = capStr.split(',').map(function(s) { return s.trim(); });

        var count = Math.max(cpArr.length, serialArr.length, oemArr.length, capArr.length, 1);
        for (var k = 0; k < count; k++) {
          expandedChargers.push({
            cpId: cpArr[k] !== undefined ? cpArr[k] : (cpArr[0] || ""),
            serialNo: serialArr[k] !== undefined ? serialArr[k] : (serialArr[0] || ""),
            oem: oemArr[k] !== undefined ? oemArr[k] : (oemArr[0] || ""),
            capacity: capArr[k] !== undefined ? capArr[k] : (capArr[0] || "")
          });
        }
      } else {
        expandedChargers.push({
          cpId: cpStr.trim(),
          serialNo: serialStr.trim(),
          oem: oemStr.trim(),
          capacity: capStr.trim()
        });
      }
    });

    var maxCpNumber = 0;
    for (var i = 1; i < invData.length; i++) {
      var rCp = invData[i][colCpId] ? invData[i][colCpId].toString().trim() : "";
      if (rCp) {
        var numMatch = rCp.match(/\d+/);
        if (numMatch) {
          var numVal = parseInt(numMatch[0], 10);
          if (numVal > maxCpNumber) maxCpNumber = numVal;
        }
      }
    }

    expandedChargers.forEach(function(chgItem) {
      var serialInput = chgItem.serialNo ? chgItem.serialNo.toString().trim() : "";
      var cpInput = chgItem.cpId ? chgItem.cpId.toString().trim() : "";
      var oemInput = chgItem.oem ? chgItem.oem.toString().trim() : "";
      var powerInput = chgItem.capacity ? chgItem.capacity.toString().trim() : "";

      var connectorType = "";
      if (powerInput) {
        var pUpper = powerInput.toString().toUpperCase();
        if (pUpper.indexOf("DC") !== -1) connectorType = "DC";
        else if (pUpper.indexOf("AC") !== -1) connectorType = "AC";
      }

      var existingRowIndex = -1;

      for (var i = 1; i < invData.length; i++) {
        var rCp = invData[i][colCpId] ? invData[i][colCpId].toString().trim() : "";
        var rSerial = invData[i][colSerial] ? invData[i][colSerial].toString().trim() : "";

        if ((serialInput && rSerial.toLowerCase() === serialInput.toLowerCase()) || (cpInput && rCp.toLowerCase() === cpInput.toLowerCase())) {
          existingRowIndex = i + 1;
          break;
        }
      }

      if (existingRowIndex > 0) {
        if (locInput) invSheet.getRange(existingRowIndex, colLocName + 1).setValue(locInput);
        if (serialInput) invSheet.getRange(existingRowIndex, colSerial + 1).setValue(serialInput);
        if (oemInput) invSheet.getRange(existingRowIndex, colOem + 1).setValue(oemInput);
        if (connectorType) invSheet.getRange(existingRowIndex, colType + 1).setValue(connectorType);
        if (powerInput) invSheet.getRange(existingRowIndex, colPower + 1).setValue(powerInput);
        if (engInput) invSheet.getRange(existingRowIndex, colEng + 1).setValue(engInput);
        if (nextPmDueDate) invSheet.getRange(existingRowIndex, colPmDate + 1).setValue(nextPmDueDate);
      } else {
        var newCpId = cpInput || "";
        var newRow = [];
        var maxCols = Math.max(9, headers.length);
        for (var c = 0; c < maxCols; c++) {
          newRow.push("");
        }

        newRow[colLocName] = locInput;
        newRow[colCpId] = newCpId;
        newRow[colSerial] = serialInput;
        newRow[colOem] = oemInput;
        newRow[colType] = connectorType;
        newRow[colPower] = powerInput;
        newRow[colEng] = engInput;
        newRow[colPmDate] = nextPmDueDate;

        invSheet.appendRow(newRow);

        var mockRow = [];
        for (var mc = 0; mc < maxCols; mc++) mockRow.push("");
        mockRow[colLocName] = locInput;
        mockRow[colCpId] = newCpId;
        mockRow[colSerial] = serialInput;
        invData.push(mockRow);
      }
    });

    // Register this station in the Stations master list if it's new (leaves
    // investor info blank for the admin to fill in via the Stations page).
    // Never overwrites an existing station's AssignedEngineer - that could
    // silently undo a manual reassignment made after commissioning.
    if (locInput) upsertStationOnCommissioningV3(locInput, engInput);
  } catch (eInventory) {
    Logger.log("addCommissionedChargerToInventoryV2 error: " + eInventory.toString());
  }
}

/**
 * Generic Submission Handler V2 - Writes complete structured tabular rows per entry for all 3 forms!
 */
// Adds/repairs trailing header labels (e.g. "RecordID") starting right after
// a sheet's original column count, WITHOUT touching any existing data row or
// the original header cells. Idempotent - safe to call on every submission.
function ensureTrailingHeadersV3(sheet, baseHeaderCount, extraLabels) {
  try {
    var range = sheet.getRange(1, baseHeaderCount + 1, 1, extraLabels.length);
    var current = range.getValues()[0];
    var needsWrite = false;
    for (var i = 0; i < extraLabels.length; i++) {
      if ((current[i] || "").toString().trim() !== extraLabels[i]) { needsWrite = true; break; }
    }
    if (needsWrite) range.setValues([extraLabels]);
  } catch (e) {}
}

// Stamps a fresh UUID into the trailing "RecordID" cell of the row just
// appended (at column baseHeaderCount+1), and returns it. Call right after
// sheet.appendRow(...) so getLastRow() still points at that new row.
function stampRecordIdV3(sheet, baseHeaderCount) {
  var recordId = Utilities.getUuid();
  sheet.getRange(sheet.getLastRow(), baseHeaderCount + 1).setValue(recordId);
  return recordId;
}

function submitFormV2(formType, payload, token) {
  var access = requireSession(token, null);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  // Every submission is attributed to whoever is actually logged in, not
  // whatever name the client happened to send - otherwise anyone could file
  // a commissioning/PM/daily-work/TADA record under a colleague's name.
  // Admin/HOD keep the client-supplied name since a supervisor legitimately
  // may be filing on behalf of a specific engineer.
  var callerRole = (access.session.role || "").toString().trim().toLowerCase();
  if (callerRole !== 'admin' && callerRole !== 'hod') {
    var ownName = access.session.fullName || access.session.username;
    payload = payload || {};
    payload.engineer = ownName;
    payload.engineerName = ownName;
  }

  try {
    var ss = getSpreadsheetV3();
    var fType = (formType || "").toString().toLowerCase().trim();
    var targetSheetName = CONFIG_V2.SHEET_COMMISSIONING;

    if (fType === 'pm_civil') targetSheetName = CONFIG_V2.SHEET_PM_CIVIL;
    else if (fType === 'pm_charger') targetSheetName = CONFIG_V2.SHEET_PM_CHARGER;
    else if (fType === 'tada' || fType === 'tada_log') targetSheetName = CONFIG_V2.SHEET_TADA;
    else if (fType === 'daily_work' || fType === 'dailywork') targetSheetName = CONFIG_V2.SHEET_DAILY_WORK || 'Daily_Work_Report';

    var sheet = ss.getSheetByName(targetSheetName);
    if (!sheet) {
      sheet = ss.insertSheet(targetSheetName);
    }

    if (formType === 'commissioning') {
      var commissioningHeaders = [
        "Timestamp", "ENGINEER", "Location Name", "Visit date", "Charger OEM", "charger Capacity",
        "Charger Serial no.", "Branding Sticker Status", "Instruction Board Status", "Canopy Backdrop Status",
        "External Light Board Status", "Syntax Box SMPS", "Canopy Square Light Status", "Canopy Branding Light Status",
        "SD Card Status", "CCTV Status", "Fire Extinguisher Status", "Modem Status", "Bollard Status",
        "Transformer Capacity", "Transformer to LT Cable Size", "LT to Charger Cable Size", "Timer & Contactor Status",
        "Canopy Hole Damage", "LT Panel Coating Condition", "MFM SPD ELR Working", "SPD Rating",
        "Lightning Concealed Conduit", "Civil Structure Condition", "Parking Slot Painting Status",
        "Interlock Work Status", "SIM No.", "Remarks", "Full Station Image (App)", "Panel Photo (Tech Support)",
        "Placement of Panel", "MCB to Charger Mapping", "Payload JSON"
      ];
      if (sheet.getLastRow() === 0) {
        sheet.appendRow(commissioningHeaders);
      }
      ensureTrailingHeadersV3(sheet, commissioningHeaders.length, ["RecordID", "SubmissionID"]);

      var placementCombined = (payload.placementOfPanel || "") + (payload.placementOfPanelMedia ? (" | Media: " + payload.placementOfPanelMedia) : "");

      var chargersList = (payload.chargers && Array.isArray(payload.chargers) && payload.chargers.length > 0)
        ? payload.chargers
        : [{
            oem: payload.oem || "",
            capacity: payload.capacity || "",
            serialNo: payload.serialNo || "",
            cpId: payload.cpId || ""
          }];

      var commissioningSubmissionId = Utilities.getUuid();

      chargersList.forEach(function(chg) {
        var serialDisplay = (chg.serialNo || payload.serialNo || "");
        if (chg.cpId && serialDisplay.indexOf(chg.cpId) === -1) {
          serialDisplay = chg.cpId + (serialDisplay ? (" - " + serialDisplay) : "");
        }

        var rowData = [
          new Date(),
          payload.engineer || payload.engineerName || "",
          payload.locationName || payload.stationName || "",
          payload.visitDate || "",
          chg.oem || payload.oem || "",
          chg.capacity || payload.capacity || "",
          serialDisplay,
          payload.brandingStickerStatus || "",
          payload.instructionBoardStatus || "",
          payload.canopyBackdropStatus || "",
          payload.externalLightBoardStatus || "",
          payload.syntaxBoxSmps || "",
          payload.canopySquareLightStatus || "",
          payload.canopyBrandingLightStatus || "",
          payload.sdCardStatus || "",
          payload.cctvStatus || "",
          payload.fireExtinguisherStatus || "",
          payload.modemStatus || "",
          payload.bollardStatus || "",
          payload.transformerCapacity || "",
          payload.cableSizeTransformerToLt || "",
          payload.cableSizeLtToCharger || "",
          payload.timerContactorStatus || "",
          payload.canopyHoleDamage || "",
          payload.ltPanelCoatingCondition || "",
          payload.mfmSpdElrWorking || "",
          payload.spdRating || "",
          payload.lightningConcealedConduit || "",
          payload.civilStructureCondition || "",
          payload.parkingPaintingStatus || "",
          payload.interlockStatus || "",
          payload.simNumber || "",
          payload.remarks || "",
          payload.fullStationImage || "",
          payload.panelPhoto || "",
          placementCombined,
          payload.mcbMapping || "",
          JSON.stringify(payload)
        ];

        sheet.appendRow(rowData);
        var newCommRow = sheet.getLastRow();
        sheet.getRange(newCommRow, commissioningHeaders.length + 1).setValue(Utilities.getUuid());
        sheet.getRange(newCommRow, commissioningHeaders.length + 2).setValue(commissioningSubmissionId);
      });


      // AUTOMATICALLY ADD / UPDATE CHARGER IN INVENTORY WITH NEXT MONTH PM DUE DATE
      addCommissionedChargerToInventoryV2(payload);

      var simListToUpdate = [];
      if (payload.sims && Array.isArray(payload.sims) && payload.sims.length > 0) {
        simListToUpdate = payload.sims;
      } else if (payload.simNumber) {
        simListToUpdate = payload.simNumber.toString().split(',').map(function(s) { return s.trim(); });
      }

      if (simListToUpdate.length > 0 && (payload.locationName || payload.stationName)) {
        try {
          var simSheet = ss.getSheetByName(CONFIG_V2.SHEET_SIM) || ss.getSheetByName("Sim Inventory");
          if (simSheet) {
            var simData = simSheet.getDataRange().getValues();
            var simHeaders = simData[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
            
            var colSim = simHeaders.indexOf("sim number");
            if (colSim === -1) colSim = 0;

            var colLoc = simHeaders.indexOf("location");
            if (colLoc === -1) colLoc = simData[0].length > 2 ? 2 : (simData[0].length > 1 ? 1 : 2);

            var stName = payload.locationName || payload.stationName;

            simListToUpdate.forEach(function(simNum) {
              if (!simNum || simNum === 'Other') return;
              for (var k = 1; k < simData.length; k++) {
                var sNum = simData[k][colSim] ? simData[k][colSim].toString().trim() : "";
                if (sNum.toLowerCase() === simNum.toString().trim().toLowerCase()) {
                  simSheet.getRange(k + 1, colLoc + 1).setValue(stName);
                  break;
                }
              }
            });
          }
        } catch (eSimUpdate) {
          Logger.log("SIM Inventory update error: " + eSimUpdate.toString());
        }
      }

      // AUTOMATICALLY TRIGGER EMAIL WITH PDF ATTACHMENT TO HOD & MANAGEMENT DIRECTORS
      try {
        sendCommissioningEmailWithPdfV2(payload);
      } catch (eEmailTrigger) {
        Logger.log("Automatic commissioning email trigger error: " + eEmailTrigger.toString());
      }



    } else if (formType === 'pm_civil') {
      var pmCivilHeaders = [
        "Timestamp", "ENGINEER", "EVCS Location Name", "PM Date", "Transformer Type (Public/Private)",
        "Before PM Media", "Panel Maintenance", "Panel Voltages (L-L & L-N)", "Earth Pit Voltage (V)",
        "SPD Status", "ELR Tripping Status", "MFM Meter Status", "Unauthorized Load Check",
        "Canopy Structural Integrity", "Modem & CCTV Status", "Canopy Lighting", "External Branding Board",
        "Instruction & Do's/Don'ts Signage", "Fire Extinguisher Status", "Fire Extinguisher Photo",
        "Civil Bay & Bollards", "After PM Media", "Remarks", "Payload JSON"
      ];
      if (sheet.getLastRow() === 0) {
        sheet.appendRow(pmCivilHeaders);
      }
      ensureTrailingHeadersV3(sheet, pmCivilHeaders.length, ["RecordID"]);

      sheet.appendRow([
        new Date(),
        payload.engineer || payload.engineerName || "",
        payload.locationName || "",
        payload.pmDate || "",
        payload.transformerInstalled || "",
        payload.beforePmMedia || "",
        payload.panelMaintenance || "",
        payload.panelVoltage || "",
        payload.earthPitVoltage || "",
        payload.spdStatus || "",
        payload.elrStatus || "",
        payload.mfmMeterStatus || "",
        payload.unauthorizedLoad || "",
        payload.canopyLeakageStatus || "",
        payload.cctvModemStatus || "",
        payload.canopyLightingStatus || "",
        payload.brandingBoardStatus || "",
        payload.instructionSignageStatus || "",
        payload.fireExtinguisherStatus || "",
        payload.fireExtinguisherPhoto || "",
        payload.civilBayBollardsStatus || "",
        payload.afterPmMedia || "",
        payload.remarks || "",
        JSON.stringify(payload)
      ]);
      stampRecordIdV3(sheet, pmCivilHeaders.length);

      updateStationPMDueDateV2(payload.locationName || payload.evcsLocationName, payload.pmDate);
    } else if (formType === 'pm_charger') {
      var pmChargerHeaders = [
        "Timestamp", "ENGINEER", "EVCS Location Name", "PM Date", "CP ID", "Charger Serial No.",
        "Capacity & Type", "Before PM Media", "Alarms Status", "Cleaning Status", "Filter Replacement",
        "Cables Tightness", "Guns & Sockets", "Rodent Proofing", "Display & Touch Status", "Doors & Locks",
        "Power Module Status", "Input Voltages (V)", "Neutral-Earth Voltage (V)", "Emergency Stop Test",
        "Internet Status", "MCB/RCCB/SMPS Status", "Vehicle Charging Test", "RFID Status", "After PM Media",
        "Remarks", "Payload JSON"
      ];
      if (sheet.getLastRow() === 0) {
        sheet.appendRow(pmChargerHeaders);
      }
      // PM_Charger_Log already has undocumented trailing columns beyond its
      // declared headers (verification status/by/date, written by the PM
      // verify flow at fixed offsets 27/28/29) - place RecordID past those,
      // not right after the declared headers, to avoid colliding with them.
      var PM_CHARGER_SAFE_TRAILING_BASE_V3 = 29;
      ensureTrailingHeadersV3(sheet, PM_CHARGER_SAFE_TRAILING_BASE_V3, ["RecordID"]);

      sheet.appendRow([
        new Date(),
        payload.engineer || payload.engineerName || "",
        payload.locationName || "",
        payload.pmDate || "",
        payload.cpId || "",
        payload.serialNo || "",
        payload.capacityAndType || "",
        payload.beforePmMedia || "",
        payload.alarmsStatus || "",
        payload.cleaningStatus || "",
        payload.filterReplacement || "",
        payload.cablesTightness || "",
        payload.gunsAndSockets || "",
        payload.rodentProofing || "",
        payload.displayTouchStatus || "",
        payload.doorsHingesStatus || "",
        payload.powerModuleStatus || "",
        payload.inputVoltages || payload.inputVoltage || ((payload.inputVoltagesLL || payload.inputVoltagesLN) ? ('L-L: ' + (payload.inputVoltagesLL || '-') + ' | L-N: ' + (payload.inputVoltagesLN || '-')) : '') || "",
        payload.neutralEarthVoltage || "",
        payload.emergencyStopTest || "",
        payload.internetStatus || "",
        payload.mcbRccbSmpsStatus || "",
        payload.vehicleChargingTest || "",
        payload.rfidStatus || "",
        payload.afterPmMedia || "",
        payload.remarks || "",
        JSON.stringify(payload)
      ]);
      stampRecordIdV3(sheet, PM_CHARGER_SAFE_TRAILING_BASE_V3);

      if (payload.cpId && (payload.serialNo || payload.capacityAndType)) {
        updateChargerInventoryV2(payload.cpId, payload.serialNo, null, payload.capacityAndType, payload.locationName || payload.evcsLocationName);
      }

          updateStationPMDueDateV2(payload.locationName || payload.evcsLocationName, payload.pmDate);
    } else if (fType === 'daily_work' || fType === 'dailywork') {
      targetSheetName = CONFIG_V2.SHEET_DAILY_WORK || 'Daily_Work_Report';
      sheet = ss.getSheetByName(targetSheetName);
      if (!sheet) sheet = ss.insertSheet(targetSheetName);

      var dailyWorkHeaders = [
        "Timestamp", "ENGINEER", "ROLE", "REPORT TYPE", "WORK DATE",
        "LOCATION / STATION", "CP ID / CATEGORY", "ISSUE / DESCRIPTION",
        "CORRECTIVE ACTION", "SPARE PARTS USED", "WORK STATUS", "REMARKS",
        "ATTACHMENT URL", "Payload JSON"
      ];
      if (sheet.getLastRow() === 0) {
        sheet.appendRow(dailyWorkHeaders);
      }
      // "CP ID / CATEGORY" used to get overwritten with the Work Hours
      // string (Work Hours never had its own column), so this cell never
      // actually showed the charger's CP ID or the Others-tab category -
      // give Work Hours its own trailing column instead of hijacking this one.
      ensureTrailingHeadersV3(sheet, dailyWorkHeaders.length, ["RecordID", "Work Hours"]);

      var cpIdOrCategory = payload.cpId || payload.category || "";
      var rowData = [
        new Date(),
        payload.engineer || payload.engineerName || "",
        payload.role || "",
        payload.reportType || "CM",
        payload.workDate || "",
        payload.locationName || "",
        cpIdOrCategory,
        payload.issueReported || payload.description || "",
        payload.correctiveAction || "",
        payload.sparePartsUsed || "",
        payload.workStatus || "",
        payload.remarks || "",
        payload.attachmentUrl || "",
        JSON.stringify(payload)
      ];

      sheet.appendRow(rowData);
      stampRecordIdV3(sheet, dailyWorkHeaders.length);
      if (payload.workHours) {
        var workHoursDisplay = payload.workHours.toString().toLowerCase().indexOf("hr") !== -1 ? payload.workHours : (payload.workHours + " hrs");
        sheet.getRange(sheet.getLastRow(), dailyWorkHeaders.length + 2).setValue(workHoursDisplay);
      }
      return { success: true, message: "Daily work report logged successfully." };

    } else if (fType === 'tada' || fType === 'tada_log') {
      var tadaHeaders = [
        "Timestamp", "ENGINEER", "ROLE", "Claim Date",
        "Travel Total (\u20b9)", "Food Total (\u20b9)", "Accommodation Total (\u20b9)", "Consumables Total (\u20b9)", "Grand Total (\u20b9)",
        "Travel Details", "Food Details", "Accommodation Details", "Consumables Details",
        "Payload JSON"
      ];

      if (sheet.getLastRow() === 0 || sheet.getLastColumn() < 5) {
        sheet.clearContents();
        sheet.getRange(1, 1, 1, tadaHeaders.length).setValues([tadaHeaders]);
      }
      ensureTrailingHeadersV3(sheet, tadaHeaders.length, ["RecordID"]);

      var travelSummary = [];
      if (payload.travelLogs && payload.travelLogs.length) {
        payload.travelLogs.forEach(function(t) {
          travelSummary.push((t.method || 'Travel') + (t.km ? ' (' + t.km + ' km)' : '') + (t.location ? ' ' + t.location : '') + (t.purpose ? ' - ' + t.purpose : '') + (t.attachmentUrl ? ' [Attach: ' + t.attachmentUrl + ']' : ''));
        });
      }

      var foodSummary = [];
      if (payload.foodLogs && payload.foodLogs.length) {
        payload.foodLogs.forEach(function(f) {
          foodSummary.push((f.meal || 'Food') + (f.location ? ' (' + f.location + ')' : '') + (f.description ? ' - ' + f.description : '') + (f.attachmentUrl ? ' [Attach: ' + f.attachmentUrl + ']' : ''));
        });
      }

      var staySummary = [];
      if (payload.stayLogs && payload.stayLogs.length) {
        payload.stayLogs.forEach(function(s) {
          staySummary.push((s.hotelName || 'Hotel') + (s.location ? ' (' + s.location + ')' : '') + (s.description ? ' - ' + s.description : '') + (s.attachmentUrl ? ' [Attach: ' + s.attachmentUrl + ']' : ''));
        });
      }

      var consSummary = [];
      if (payload.consumableLogs && payload.consumableLogs.length) {
        payload.consumableLogs.forEach(function(c) {
          consSummary.push((c.description || 'Item') + ' (\u20b9' + (c.amount || 0) + ')' + (c.attachmentUrl ? ' [Attach: ' + c.attachmentUrl + ']' : ''));
        });
      }

      sheet.appendRow([
        new Date(),
        payload.engineer || payload.engineerName || "",
        payload.role || "",
        payload.claimDate || new Date().toISOString().split('T')[0],
        Number(payload.travelTotal) || 0,
        Number(payload.foodTotal) || 0,
        Number(payload.stayTotal) || 0,
        Number(payload.consTotal) || 0,
        Number(payload.grandTotal) || 0,
        travelSummary.join('; ') || "-",
        foodSummary.join('; ') || "-",
        staySummary.join('; ') || "-",
        consSummary.join('; ') || "-",
        JSON.stringify(payload)
      ]);
      stampRecordIdV3(sheet, tadaHeaders.length);
      updateStationPMDueDateV2(payload.locationName || payload.evcsLocationName, payload.pmDate);
    } else if (fType === 'tada' || fType === 'tada_log') {
      var tadaHeaders = [
        "Timestamp", "ENGINEER", "ROLE", "Claim Date",
        "Travel Total (\u20b9)", "Food Total (\u20b9)", "Accommodation Total (\u20b9)", "Consumables Total (\u20b9)", "Grand Total (\u20b9)",
        "Travel Details", "Food Details", "Accommodation Details", "Consumables Details",
        "Payload JSON"
      ];

      if (sheet.getLastRow() === 0 || sheet.getLastColumn() < 5) {
        sheet.clearContents();
        sheet.getRange(1, 1, 1, tadaHeaders.length).setValues([tadaHeaders]);
      }

      var travelSummary = [];
      if (payload.travelLogs && payload.travelLogs.length) {
        payload.travelLogs.forEach(function(t) {
          travelSummary.push((t.method || 'Travel') + (t.km ? ' (' + t.km + ' km)' : '') + (t.location ? ' ' + t.location : '') + (t.purpose ? ' - ' + t.purpose : '') + (t.attachmentUrl ? ' [Attach: ' + t.attachmentUrl + ']' : ''));
        });
      }

      var foodSummary = [];
      if (payload.foodLogs && payload.foodLogs.length) {
        payload.foodLogs.forEach(function(f) {
          foodSummary.push((f.meal || 'Food') + (f.location ? ' (' + f.location + ')' : '') + (f.description ? ' - ' + f.description : '') + (f.attachmentUrl ? ' [Attach: ' + f.attachmentUrl + ']' : ''));
        });
      }

      var staySummary = [];
      if (payload.stayLogs && payload.stayLogs.length) {
        payload.stayLogs.forEach(function(s) {
          staySummary.push((s.hotelName || 'Hotel') + (s.location ? ' (' + s.location + ')' : '') + (s.description ? ' - ' + s.description : '') + (s.attachmentUrl ? ' [Attach: ' + s.attachmentUrl + ']' : ''));
        });
      }

      var consSummary = [];
      if (payload.consumableLogs && payload.consumableLogs.length) {
        payload.consumableLogs.forEach(function(c) {
          consSummary.push((c.description || 'Item') + ' (\u20b9' + (c.amount || 0) + ')' + (c.attachmentUrl ? ' [Attach: ' + c.attachmentUrl + ']' : ''));
        });
      }

      sheet.appendRow([
        new Date(),
        payload.engineer || payload.engineerName || "",
        payload.role || "",
        payload.claimDate || new Date().toISOString().split('T')[0],
        Number(payload.travelTotal) || 0,
        Number(payload.foodTotal) || 0,
        Number(payload.stayTotal) || 0,
        Number(payload.consTotal) || 0,
        Number(payload.grandTotal) || 0,
        travelSummary.join('; ') || "-",
        foodSummary.join('; ') || "-",
        staySummary.join('; ') || "-",
        consSummary.join('; ') || "-",
        JSON.stringify(payload)
      ]);

    } else {
      if (sheet.getLastRow() === 0) {
        sheet.appendRow(["Timestamp", "Payload JSON"]);
      }
      sheet.appendRow([new Date(), JSON.stringify(payload)]);
    }

    // AUTOMATIC AESTHETIC STYLING & TEXT WRAPPING FOR ALL LOG SHEETS
    formatLogSheetAestheticV2(sheet);

    return { success: true, message: "Submission recorded successfully!" };
  } catch (err) {
    return { success: false, message: err.toString() };
  }
}

/**
 * Backend API: Submit Weekly Pending Issue
 */

function submitFormV3(formType, payload, token) {
  return submitFormV2(formType, payload, token);
}

function submitForm(formType, payload) {
  return submitFormV2(formType, payload);
}

function saveCommissioningDataV3(payload) {
  return submitFormV2('commissioning', payload);
}

function saveCommissioningFormV3(payload) {
  return submitFormV2('commissioning', payload);
}


/**
 * Helper to safely format dates to YYYY-MM-DD string
 */
function formatDateOnlyV2(val) {
  if (!val) return "";
  if (val instanceof Date) {
    var yyyy = val.getFullYear();
    var mm = ("0" + (val.getMonth() + 1)).slice(-2);
    var dd = ("0" + val.getDate()).slice(-2);
    return yyyy + "-" + mm + "-" + dd;
  }
  var str = val.toString().trim();
  if (str.length >= 10 && str.indexOf('T') !== -1) {
    return str.split('T')[0];
  }
  return str;
}

function submitWeeklyIssueV2(payload) {
  try {
    var ss = getSpreadsheetV3();
    var sheetName = (CONFIG_V2 && CONFIG_V2.SHEET_WEEKLY_PENDING) ? CONFIG_V2.SHEET_WEEKLY_PENDING : 'Weekly_Pending_Issues_Log';
    var sheet = ss.getSheetByName(sheetName);
    if (!sheet) {
      sheet = ss.insertSheet(sheetName);
    }

    var weeklyIssueHeaders = ["Issue ID", "Timestamp", "ENGINEER", "Station Name", "Report Date", "Issue Title", "Issue Description", "Status", "HOD Remarks"];
    if (sheet.getLastRow() === 0) {
      sheet.appendRow(weeklyIssueHeaders);
    }
    ensureTrailingHeadersV3(sheet, weeklyIssueHeaders.length, ["Issue Type"]);

    var issueId = "ISSUE-" + (1000 + sheet.getLastRow());

    sheet.appendRow([
      issueId,
      new Date(),
      payload.engineer || payload.engineerName || "",
      payload.station || "",
      payload.date || "",
      payload.title || "",
      payload.description || "",
      "Pending",
      "",
      payload.issueType || ""
    ]);

    if (typeof formatLogSheetAestheticV2 === 'function') {
      formatLogSheetAestheticV2(sheet);
    }

    return { success: true, message: "Weekly pending issue #" + issueId + " logged successfully!", issueId: issueId };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

/**
 * Backend API: Get Weekly Pending Issues for a specific engineer or ALL if empty
 */
function getEngineerWeeklyIssuesV2(engineerName) {
  try {
    var ss = getSpreadsheetV3();
    var sheetName = (CONFIG_V2 && CONFIG_V2.SHEET_WEEKLY_PENDING) ? CONFIG_V2.SHEET_WEEKLY_PENDING : 'Weekly_Pending_Issues_Log';
    var sheet = ss ? ss.getSheetByName(sheetName) : null;
    if (!sheet) return [];

    var data = sheet.getDataRange().getValues();
    if (data.length <= 1) return [];

    var engInput = (engineerName && engineerName.toString().trim() !== "ALL") ? engineerName.toString().trim().toLowerCase() : "";
    var issues = [];

    for (var i = 1; i < data.length; i++) {
      var row = data[i];
      if (!row[0] && !row[2] && !row[5]) continue; // Skip empty rows

      var issueId = row[0] ? row[0].toString() : ("ISSUE-" + (1000 + i));
      var engVal = row[2] ? row[2].toString().trim() : "";
      var station = row[3] ? row[3].toString().trim() : "";
      var date = row[4] ? formatDateOnlyV2(row[4]) : "";
      var title = row[5] ? row[5].toString().trim() : "";
      var desc = row[6] ? row[6].toString().trim() : "";
      var status = row[7] ? row[7].toString().trim() : "Pending";
      var hodRemarks = row[8] ? row[8].toString().trim() : "";
      var issueType = row[9] ? row[9].toString().trim() : "";

      if (!engInput || engVal.toLowerCase() === engInput || engInput.indexOf(engVal.toLowerCase()) !== -1 || engVal.toLowerCase().indexOf(engInput) !== -1) {
        issues.push({
          issueId: issueId,
          rowIndex: i + 1,
          engineer: engVal,
          station: station,
          date: date,
          title: title,
          description: desc,
          status: status,
          hodRemarks: hodRemarks,
          issueType: issueType
        });
      }
    }

    return issues.reverse(); // Latest issues first
  } catch (e) {
    Logger.log("getEngineerWeeklyIssuesV2 error: " + e.toString());
    return [];
  }
}

/**
 * Backend API: Get ALL Weekly Issues for HOD View
 */
function getAllWeeklyIssuesV2(token) {
  var scope = getHodEngineerScopeV3(token);
  if (!scope.ok) return [];
  var allIssues = getEngineerWeeklyIssuesV2("");
  if (scope.scoped) {
    return allIssues.filter(function(issue) { return engineerInHodScopeV3(scope, issue.engineer); });
  }
  return allIssues;
}

// Pending-only Station x Issue Type matrix for the Weekly Updates report -
// same HOD scoping as everything else (reuses getAllWeeklyIssuesV2, which
// already applies it). Export to CSV/PDF happens entirely client-side from
// this same JSON, matching the existing downloadWeeklyIssuesXLSXV3/PDFV3
// pattern already in WeeklyPending_V3.html - no server-side file generation needed.
function getWeeklyPendingReportMatrixV3(token) {
  try {
    var issues = getAllWeeklyIssuesV2(token) || [];
    var pending = issues.filter(function(i) { return (i.status || 'Pending').toString().trim().toLowerCase() === 'pending'; });

    var stationsSet = {};
    var issueTypesSet = {};
    var cellMap = {}; // "station||issueType" -> [descriptions]

    pending.forEach(function(item) {
      var station = (item.station || '').toString().trim() || 'Unknown Station';
      var issueType = (item.issueType || '').toString().trim() || 'Uncategorized';
      var description = (item.description || item.title || '').toString().trim();

      stationsSet[station] = true;
      issueTypesSet[issueType] = true;

      var key = station + '||' + issueType;
      if (!cellMap[key]) cellMap[key] = [];
      cellMap[key].push(description);
    });

    var stations = Object.keys(stationsSet).sort();
    var issueTypes = Object.keys(issueTypesSet).sort();

    var matrix = {};
    stations.forEach(function(st) {
      matrix[st] = {};
      issueTypes.forEach(function(it) {
        var key = st + '||' + it;
        matrix[st][it] = cellMap[key] ? cellMap[key].join(' | ') : '';
      });
    });

    return { success: true, stations: stations, issueTypes: issueTypes, matrix: matrix };
  } catch (e) {
    return { success: false, message: e.toString(), stations: [], issueTypes: [], matrix: {} };
  }
}

/**
 * Backend API: Update Issue Status (Pending / In Progress / Resolved) and HOD Remarks
 */
function updateWeeklyIssueStatusV2(issueId, newStatus, hodRemarks, token) {
  var access = requireSession(token, null);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var ss = getSpreadsheetV3();
    var sheetName = (CONFIG_V2 && CONFIG_V2.SHEET_WEEKLY_PENDING) ? CONFIG_V2.SHEET_WEEKLY_PENDING : 'Weekly_Pending_Issues_Log';
    var sheet = ss ? ss.getSheetByName(sheetName) : null;
    if (!sheet || !issueId) return { success: false, message: "Sheet or Issue ID missing." };

    var data = sheet.getDataRange().getValues();
    var idInput = issueId.toString().trim().toLowerCase();
    var targetRow = -1;

    for (var i = 1; i < data.length; i++) {
      var idVal = data[i][0] ? data[i][0].toString().trim().toLowerCase() : "";
      if (idVal === idInput) {
        targetRow = i + 1;
        break;
      }
    }

    if (targetRow > 0) {
      if (newStatus) sheet.getRange(targetRow, 8).setValue(newStatus);
      if (hodRemarks !== undefined && hodRemarks !== null) sheet.getRange(targetRow, 9).setValue(hodRemarks);
      return { success: true, message: "Issue #" + issueId + " updated to " + newStatus + "!" };
    }

    return { success: false, message: "Issue ID #" + issueId + " not found." };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

function getEngineerWeeklyIssuesV3(engineerName, token) {
  var access = requireSession(token, null);
  if (!access.ok) return [];
  var role = (access.session.role || "").toString().trim().toLowerCase();
  var effectiveEngineer = (role === 'admin' || role === 'hod') ? engineerName : (access.session.fullName || access.session.username);
  return getEngineerWeeklyIssuesV2(effectiveEngineer);
}

function updateWeeklyIssueStatusV3(issueId, newStatus, hodRemarks, token) {
  return updateWeeklyIssueStatusV2(issueId, newStatus, hodRemarks, token);
}





// ============================================================================
// SIM INVENTORY MANAGEMENT BACKEND ENGINE
// ============================================================================

/**
 * 1. Fetches SIM Inventory records.
 * If sheet "Sim Inventory" does not exist, it is initialized with standard headers.
 */
/**
 * 1. Fetches SIM Inventory records.
 * Gracefully parses 3-column sheets (Sim Number, Engineer, Location) and multi-column sheets.
 */
function getSimInventoryDataV2(role, engineerName, token) {
  try {
    var hodScope = getHodEngineerScopeV3(token);
    if (!hodScope.ok) return { success: false, message: hodScope.message, sessionExpired: hodScope.sessionExpired, items: [], engineers: [] };
    var ss = getSpreadsheetV3();
    var sheetName = CONFIG_V3.SHEET_SIM || "Sim Inventory";
    var sheet = ss.getSheetByName(sheetName);

    if (!sheet) {
      sheet = ss.insertSheet(sheetName);
      sheet.appendRow(["Sim Number", "Engineer", "Location", "Status", "Remarks", "Date Updated"]);
      formatLogSheetAestheticV2(sheet);
    }

    var data = sheet.getDataRange().getValues();
    if (data.length <= 1) {
      var engsRes = getAllEngineersListV2();
      var engList = (engsRes && Array.isArray(engsRes.engineers)) ? engsRes.engineers : (Array.isArray(engsRes) ? engsRes : []);
      return { success: true, items: [], engineers: engList };
    }

    var info = findHeaderRowAndIndexes(data);
    var colSim = info.colSim;
    var colEng = info.colEng;
    var colLoc = info.colLoc;
    var colStatus = info.colStatus;
    var colRemarks = info.colRemarks;
    var colDate = info.colDate;

    var items = [];
    var rLower = role ? role.toString().trim().toLowerCase() : "";
    var isHOD = rLower.indexOf("hod") !== -1 || rLower.indexOf("head") !== -1 || rLower.indexOf("admin") !== -1;
    var isEngineer = !isHOD;
    var engSearch = engineerName ? engineerName.toString().trim().toLowerCase() : "";

    for (var i = info.headerRowIdx + 1; i < data.length; i++) {
      var row = data[i];
      if (!row) continue;

      var simNum = (colSim >= 0 && row[colSim] !== undefined) ? row[colSim].toString().trim() : "";
      if (!simNum) continue;

      var sLow = simNum.toLowerCase().replace(/[^a-z0-9]/g, "");
      if (sLow === "sim" || sLow === "simnum" || sLow === "simnumber" || sLow === "simcard") continue;

      var eng = (colEng >= 0 && row[colEng] !== undefined && row[colEng] !== "") ? row[colEng].toString().trim() : "Unassigned";
      var loc = (colLoc >= 0 && row[colLoc] !== undefined && row[colLoc] !== "") ? row[colLoc].toString().trim() : "In Stock / Warehouse";

      if (isEngineer && engSearch && engSearch !== "all") {
        var engLower = eng.toLowerCase();
        var engFirst = engLower.split(" ")[0];
        var searchFirst = engSearch.split(" ")[0];
        var isMatch = engLower === engSearch || engLower.indexOf(engSearch) !== -1 || engSearch.indexOf(engLower) !== -1 || (engFirst.length >= 3 && engFirst === searchFirst);
        if (!isMatch) continue;
      }

      if (hodScope.ok && hodScope.scoped && !engineerInHodScopeV3(hodScope, eng)) continue;

      var status = (colStatus >= 0 && row[colStatus] !== undefined && row[colStatus] !== "") ? row[colStatus].toString().trim() : "";
      if (!status) {
        if (loc && loc !== "In Stock / Warehouse") {
          status = "Deployed";
        } else if (eng && eng.toLowerCase() !== "unassigned") {
          status = "Assigned";
        } else {
          status = "Available";
        }
      }

      var remarks = (colRemarks >= 0 && row[colRemarks] !== undefined) ? row[colRemarks].toString().trim() : "";
      var dateUpdated = (colDate >= 0 && row[colDate] !== undefined) ? row[colDate].toString().trim() : "";

      items.push({
        rowIndex: i + 1,
        simNumber: simNum,
        engineer: eng,
        location: loc,
        status: status,
        remarks: remarks,
        dateUpdated: dateUpdated
      });
    }

    var stationsResult = getInventoryStationsV2();
    var stationsList = (stationsResult && Array.isArray(stationsResult.stations)) ? stationsResult.stations : [];
    if (hodScope.ok && hodScope.scoped) {
      stationsList = stationsList.filter(function(s) { return engineerInHodScopeV3(hodScope, s.engineer); });
    }

    var engineersRes = getEngineersVisibleToCallerV3(token);
    var engineersList = (engineersRes && Array.isArray(engineersRes.engineers)) ? engineersRes.engineers : [];

    return {
      success: true,
      items: items,
      engineers: engineersList,
      stations: stationsList
    };
  } catch (e) {
    return { success: false, message: e.toString(), items: [], engineers: [], stations: [] };
  }
}

function getAllEngineersListV2() {
  try {
    var ss = getSpreadsheetV3();
    var engSet = {};

    var canonicalMap = {
      "sojith": "Sojith M",
      "sojith m": "Sojith M",
      "yadhu": "Yadhu Krishnan",
      "yadhu krishna": "Yadhu Krishnan",
      "yadhukrishnan": "Yadhu Krishnan",
      "athul": "Athul Krishna",
      "athul krishna": "Athul Krishna",
      "shafiad": "Shaflad",
      "shaflad": "Shaflad",
      "sidharth": "Sidharth",
      "nithin": "Nithin",
      "rudraksh": "Rudraksh",
      "vikas": "Vikas",
      "bibin": "Bibin",
      "chandrakant": "Chandrakant",
      "hameed": "Hameed",
      "althaf": "Althaf",
      "safnan": "Safnan"
    };

    var defaultEngineers = [
      "Althaf", "Athul Krishna", "Bibin", "Chandrakant", "Hameed", 
      "Nithin", "Rudraksh", "Safnan", "Shaflad", "Sidharth", 
      "Sojith M", "Vikas", "Yadhu Krishnan"
    ];

    defaultEngineers.forEach(function(e) { engSet[e] = true; });

    // 1. Check Users sheet - columns are Username(0), Password(1), FullName(2), Role(3).
    // Only include actual field Engineers, by exact role match - this also
    // correctly excludes Admin/HOD and any custom role (e.g. "HR") an admin
    // creates later, none of which belong in an engineer picker.
    var userSheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_USERS || "Users") : null;
    if (userSheet && userSheet.getLastRow() > 1) {
      var uData = userSheet.getDataRange().getValues();
      for (var i = 1; i < uData.length; i++) {
        var rawName = uData[i][2] ? uData[i][2].toString().trim() : (uData[i][0] ? uData[i][0].toString().trim() : "");
        var uRole = uData[i][3] ? uData[i][3].toString().trim() : "";
        if (rawName && uRole.toLowerCase() === 'engineer') {
          var cleanKey = rawName.toLowerCase();
          var normName = canonicalMap[cleanKey] || rawName;
          engSet[normName] = true;
        }
      }
    }

    // 2. Check Master Inventory sheet (Column H)
    var invSheet = ss ? (ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory")) : null;
    if (invSheet && invSheet.getLastRow() > 1) {
      var iData = invSheet.getDataRange().getValues();
      for (var j = 1; j < iData.length; j++) {
        var engName = iData[j][7] ? iData[j][7].toString().trim() : "";
        if (engName && engName.toLowerCase() !== 'system administrator' && engName.toLowerCase() !== 'admin' && engName.toLowerCase() !== 'hod') {
          var cKey = engName.toLowerCase();
          var nName = canonicalMap[cKey] || engName;
          engSet[nName] = true;
        }
      }
    }

    // 3. Helper to collect from activity log sheets
    function collectEngineers(sheetName, engColIdx) {
      var sh = ss ? ss.getSheetByName(sheetName) : null;
      if (sh && sh.getLastRow() > 1) {
        var d = sh.getDataRange().getValues();
        for (var k = 1; k < d.length; k++) {
          var name = d[k][engColIdx] ? d[k][engColIdx].toString().trim() : "";
          if (name && name.toLowerCase() !== 'admin' && name.toLowerCase() !== 'hod' && name.toLowerCase() !== 'system administrator') {
            var kKey = name.toLowerCase();
            var mName = canonicalMap[kKey] || name;
            engSet[mName] = true;
          }
        }
      }
    }

    collectEngineers(CONFIG_V2.SHEET_DAILY_WORK || 'Daily_Work_Report', 1);
    collectEngineers(CONFIG_V2.SHEET_PM_CIVIL || 'PM_ElectricalCivil_Log', 1);
    collectEngineers(CONFIG_V2.SHEET_PM_CHARGER || 'PM_Charger_Log', 1);
    collectEngineers(CONFIG_V2.SHEET_COMMISSIONING || 'Commissioning Log', 1);
    collectEngineers(CONFIG_V2.SHEET_TADA || 'TADA_Log', 1);

    var list = Object.keys(engSet).sort(function(a, b) {
      return a.localeCompare(b);
    });

    return { success: true, engineers: list };
  } catch (err) {
    return { success: false, error: err.toString(), engineers: [
      "Althaf", "Athul Krishna", "Bibin", "Chandrakant", "Hameed", 
      "Nithin", "Rudraksh", "Safnan", "Shaflad", "Sidharth", 
      "Sojith M", "Vikas", "Yadhu Krishnan"
    ] };
  }
}


function addSingleSimV2(simNumber, assignedEngineer, location, status, remarks, token) {
  var access = requireSession(token, ['HOD', 'Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };
  try {
    if (!simNumber || simNumber.toString().trim() === '') {
      return { success: false, message: "SIM Number is required." };
    }

    var ss = getSpreadsheetV3();
    var sheetName = CONFIG_V2.SHEET_SIM || "Sim Inventory";
    var sheet = ss.getSheetByName(sheetName);

    if (!sheet) {
      sheet = ss.insertSheet(sheetName);
      sheet.appendRow(["SIM Number", "Assigned Engineer", "Station Location", "Status", "Remarks", "Date Updated"]);
      formatLogSheetAestheticV2(sheet);
    }

    var data = sheet.getDataRange().getValues();
    var cleanSim = simNumber.toString().trim();
    var targetRow = -1;

    for (var i = 1; i < data.length; i++) {
      var existingSim = data[i][0] ? data[i][0].toString().trim() : "";
      if (existingSim.toLowerCase() === cleanSim.toLowerCase()) {
        targetRow = i + 1;
        break;
      }
    }

    var updatedDate = new Date().toLocaleDateString();
    var finalStatus = status || (location && location !== "In Stock / Warehouse" ? "Deployed" : "Assigned");

    if (targetRow > 0) {
      sheet.getRange(targetRow, 2).setValue(assignedEngineer || "Unassigned");
      sheet.getRange(targetRow, 3).setValue(location || "In Stock / Warehouse");
      sheet.getRange(targetRow, 4).setValue(finalStatus);
      sheet.getRange(targetRow, 5).setValue(remarks || "");
      sheet.getRange(targetRow, 6).setValue(updatedDate);
    } else {
      sheet.appendRow([
        cleanSim,
        assignedEngineer || "Unassigned",
        location || "In Stock / Warehouse",
        finalStatus,
        remarks || "",
        updatedDate
      ]);
    }

    formatLogSheetAestheticV2(sheet);
    return { success: true, message: "SIM #" + cleanSim + " saved to inventory successfully!" };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

/**
 * 3. Bulk Import SIM Cards from Excel / CSV array.
 */
function bulkImportSimsV2(simList, token) {
  var access = requireSession(token, ['HOD', 'Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };
  try {
    if (!simList || !Array.isArray(simList) || simList.length === 0) {
      return { success: false, message: "No SIM records provided for bulk import." };
    }

    var ss = getSpreadsheetV3();
    var sheetName = CONFIG_V2.SHEET_SIM || "Sim Inventory";
    var sheet = ss.getSheetByName(sheetName);

    if (!sheet) {
      sheet = ss.insertSheet(sheetName);
      sheet.appendRow(["SIM Number", "Assigned Engineer", "Station Location", "Status", "Remarks", "Date Updated"]);
      formatLogSheetAestheticV2(sheet);
    }

    var data = sheet.getDataRange().getValues();
    var simMap = {};
    for (var i = 1; i < data.length; i++) {
      var sNum = data[i][0] ? data[i][0].toString().trim().toLowerCase() : "";
      if (sNum) simMap[sNum] = i + 1;
    }

    var todayStr = new Date().toLocaleDateString();
    var importedCount = 0;

    simList.forEach(function(item) {
      var simNum = item.simNumber ? item.simNumber.toString().trim() : "";
      if (!simNum) return;

      var eng = item.engineer ? item.engineer.toString().trim() : "Unassigned";
      var loc = item.location ? item.location.toString().trim() : "In Stock / Warehouse";
      var status = item.status ? item.status.toString().trim() : (loc && loc !== "In Stock / Warehouse" ? "Deployed" : "Assigned");
      var remarks = item.remarks ? item.remarks.toString().trim() : "Bulk Imported";

      var existingRow = simMap[simNum.toLowerCase()];
      if (existingRow) {
        sheet.getRange(existingRow, 2).setValue(eng);
        sheet.getRange(existingRow, 3).setValue(loc);
        sheet.getRange(existingRow, 4).setValue(status);
        sheet.getRange(existingRow, 5).setValue(remarks);
        sheet.getRange(existingRow, 6).setValue(todayStr);
      } else {
        sheet.appendRow([simNum, eng, loc, status, remarks, todayStr]);
        simMap[simNum.toLowerCase()] = sheet.getLastRow();
      }
      importedCount++;
    });

    formatLogSheetAestheticV2(sheet);
    return { success: true, count: importedCount, message: "Successfully imported " + importedCount + " SIM cards!" };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

/**
 * 4. Updates SIM Deployment / Location and Remarks (Engineer action).
 */
function updateSimDeploymentV2(simNumber, location, remarks, newStatus, token) {
  var access = requireSession(token, ['HOD', 'Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };
  try {
    if (!simNumber) return { success: false, message: "SIM Number is required." };

    var ss = getSpreadsheetV3();
    var sheetName = CONFIG_V2.SHEET_SIM || "Sim Inventory";
    var sheet = ss.getSheetByName(sheetName);
    if (!sheet) return { success: false, message: "Sim Inventory sheet not found." };

    var data = sheet.getDataRange().getValues();
    var cleanSim = simNumber.toString().trim().toLowerCase();
    var targetRow = -1;

    for (var i = 1; i < data.length; i++) {
      var sNum = data[i][0] ? data[i][0].toString().trim().toLowerCase() : "";
      if (sNum === cleanSim) {
        targetRow = i + 1;
        break;
      }
    }

    if (targetRow > 0) {
      if (location) sheet.getRange(targetRow, 3).setValue(location);
      if (newStatus) sheet.getRange(targetRow, 4).setValue(newStatus);
      else if (location && location !== "In Stock / Warehouse") sheet.getRange(targetRow, 4).setValue("Deployed");
      
      if (remarks !== undefined && remarks !== null) sheet.getRange(targetRow, 5).setValue(remarks);
      sheet.getRange(targetRow, 6).setValue(new Date().toLocaleDateString());

      return { success: true, message: "SIM #" + simNumber + " updated successfully!" };
    }

    return { success: false, message: "SIM Card #" + simNumber + " not found in inventory." };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

// ============================================================================
// PM REPORT & CUSTOM EMAIL DISPATCH BACKEND // ============================================================================
// PM REPORT & CUSTOM EMAIL DISPATCH BACKEND ENGINE
// ============================================================================

/**
 * Helper to normalize string for comparison
 */
function cleanPMStrV2(str) {
  return str ? str.toString().trim().toLowerCase().replace(/[^a-z0-9]/g, "") : "";
}

/**
 * 1. Re/**
 * Helper to normalize string for comparison
 */
function cleanPMStrV2(str) {
  return str ? str.toString().trim().toLowerCase().replace(/[^a-z0-9]/g, " ") : "";
}

function isPMStationMatchV2(logStation, searchStation) {
  if (!logStation || !searchStation) return false;
  var s1 = cleanPMStrV2(logStation).replace(/\s+/g, "");
  var s2 = cleanPMStrV2(searchStation).replace(/\s+/g, "");
  if (!s1 || !s2) return false;
  if (s1 === s2 || s1.indexOf(s2) !== -1 || s2.indexOf(s1) !== -1) return true;

  var words1 = cleanPMStrV2(logStation).split(/\s+/).filter(function(w) { return w.length >= 4; });
  var words2 = cleanPMStrV2(searchStation).split(/\s+/).filter(function(w) { return w.length >= 4; });
  
  if (words1.length === 0 || words2.length === 0) return false;

  var matches = 0;
  for (var i = 0; i < words1.length; i++) {
    if (s2.indexOf(words1[i]) !== -1) matches++;
  }
  return matches >= 2 || (words1.length === 1 && matches === 1);
}

/**
 * 1. Re// ============================================================================
// PM REPORT & CUSTOM EMAIL DISPATCH BACKEND ENGINE
// ============================================================================

/**
 * Helper to normalize station string to a canonical dictionary key
 */
function cleanPMKeyV2(str) {
  if (!str) return "";
  return str.toString()
    .toLowerCase()
    .replace(/\u00A0/g, " ") // replace non-breaking spaces
    .replace(/[^a-z0-9]/g, "") // strip all non-alphanumeric
    .trim();
}

/**
 * 1. Returns station PM overview list with last Civil & Charger PM month/year and verification status.
 */
function getPMReportOverviewV2(token, monthStr) {
  try {
    var scope = getHodEngineerScopeV3(token);
    if (!scope.ok) return { success: false, message: scope.message, sessionExpired: scope.sessionExpired, items: [] };
    var callerRole = (scope.session.role || "").toLowerCase();
    if (callerRole === "engineer") {
      return { success: false, message: "Access Restricted: PM Audit Reports are reserved for HOD and Supervisors.", items: [] };
    }
    var ss = getSpreadsheetV3();
    var stationsMap = {};

    // Optional "YYYY-MM" filter (also accepts just a year, "YYYY"). When
    // given, each station's civil/charger PM status reflects THAT specific
    // period's newest matching submission, not the all-time newest one -
    // otherwise a station serviced again in a later month makes its earlier
    // month's PM invisible to this overview entirely (it's a single row per
    // station), which is exactly what made month-filtering look like it was
    // silently dropping real submissions.
    var targetYear = null, targetMonth = null;
    if (monthStr) {
      var mmStr = monthStr.toString().trim();
      var mFull = mmStr.match(/^(\d{4})-(\d{2})$/);
      var mYearOnly = mmStr.match(/^(\d{4})$/);
      if (mFull) { targetYear = parseInt(mFull[1], 10); targetMonth = parseInt(mFull[2], 10) - 1; }
      else if (mYearOnly) { targetYear = parseInt(mYearOnly[1], 10); }
    }
    function rowMatchesTargetPeriodV3(dObj) {
      if (!dObj || isNaN(dObj.getTime())) return false;
      if (targetYear !== null && dObj.getFullYear() !== targetYear) return false;
      if (targetMonth !== null && dObj.getMonth() !== targetMonth) return false;
      return true;
    }
    var hasTargetPeriod = (targetYear !== null || targetMonth !== null);
    var keyList = []; // Array of keys for fast fuzzy matching
    
    // 1. Read Charger Inventory
    var invSheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY || "Charger Inventory") : null;
    if (invSheet) {
      var iData = invSheet.getDataRange().getValues();
      if (iData.length > 1) {
        var iHeaders = iData[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
        
        var colId = 0;
        var colSt = iHeaders.indexOf("location name");
        if (colSt === -1) colSt = iHeaders.indexOf("evcs location name");
        if (colSt === -1) colSt = iHeaders.indexOf("station name");
        if (colSt === -1) colSt = iHeaders.indexOf("station");
        if (colSt === -1) colSt = 1;

        var colEng = iHeaders.indexOf("engineer");
        if (colEng === -1) colEng = iHeaders.indexOf("assigned engineer");
        if (colEng === -1) colEng = 7;

        var colDue = iHeaders.indexOf("pm due date");
        if (colDue === -1) colDue = 8; // Column H (0-indexed is 7 or 8)
        if (colDue === -1 || colDue >= iData[0].length) colDue = iData[0].length - 1;

        for (var i = 1; i < iData.length; i++) {
          var stId = iData[i][colId] ? iData[i][colId].toString().trim() : "";
          var stName = (colSt >= 0 && iData[i][colSt]) ? iData[i][colSt].toString().trim() : stId;
          var eng = (colEng >= 0 && iData[i][colEng]) ? iData[i][colEng].toString().trim() : "Unassigned";

          var rawDueDate = (colDue >= 0 && colDue < iData[i].length && iData[i][colDue]) ? iData[i][colDue] : "";
          var formattedDueDate = "";
          if (rawDueDate) {
            var dObjDue = new Date(rawDueDate);
            if (!isNaN(dObjDue.getTime())) {
              var dd = String(dObjDue.getDate()).padStart(2, '0');
              var mm = String(dObjDue.getMonth() + 1).padStart(2, '0');
              var yyyy = dObjDue.getFullYear();
              formattedDueDate = dd + '/' + mm + '/' + yyyy;
            } else {
              formattedDueDate = rawDueDate.toString().trim();
            }
          }

          var displayName = stName || stId;
          if (!displayName) continue;

          var normKey = cleanPMKeyV2(displayName);
          var idKey = cleanPMKeyV2(stId);

          if (!stationsMap[normKey]) {
            stationsMap[normKey] = {
              stationName: displayName,
              stationId: stId,
              engineer: eng,
              lastPmDate: "",
              nextPmDueDate: formattedDueDate,
              isVerified: false,
              verifier: "",
              verifiedDate: "",
              hasCivilThisMonth: false,
              hasChargerThisMonth: false
            };
            keyList.push(normKey);
          } else if (!stationsMap[normKey].nextPmDueDate && formattedDueDate) {
            stationsMap[normKey].nextPmDueDate = formattedDueDate;
          }
          if (stId && idKey && !stationsMap[idKey]) {
            stationsMap[idKey] = stationsMap[normKey]; // alias pointer
          }
        }
      }
    }

    var now = new Date();
    var currentYear = now.getFullYear();
    var currentMonth = now.getMonth();

    // Helper to find matching station object (strict fuzzy matching to prevent key collisions)
    function findStationObj(rawName) {
      if (!rawName) return null;
      var k = cleanPMKeyV2(rawName);
      if (!k) return null;
      if (stationsMap[k]) return stationsMap[k];

      // Only fuzzy-match if both keys are long enough (>=8 chars) and very close in length
      // This prevents short keys like 'goec' swallowing all 'GO EC ...' station names
      for (var j = 0; j < keyList.length; j++) {
        var existingKey = keyList[j];
        if (existingKey && existingKey.length >= 8 && k.length >= 8) {
          if (k === existingKey ||
              (k.indexOf(existingKey) !== -1 && Math.abs(k.length - existingKey.length) < 5)) {
            return stationsMap[existingKey];
          }
        }
      }

      // If not found, create distinct new station record
      stationsMap[k] = {
        stationName: rawName,
        stationId: "",
        engineer: "Unassigned",
        lastPmDate: "",
        nextPmDueDate: "",
        isVerified: false,
        verifier: "",
        verifiedDate: "",
        hasCivilThisMonth: false,
        hasChargerThisMonth: false
      };
      keyList.push(k);
      return stationsMap[k];
    }

    var monthNamesV3Overview = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    // Civil and charger dates are resolved fully independently (each keyed
    // by station), then merged afterwards - previously they shared one
    // "lastPmDate" field on the same object, so whichever section ran first
    // (civil) silently blocked the other (charger) from ever recording its
    // own date once civil had set one, understating stations whose most
    // recent - or requested-month - activity was actually a charger PM.
    var civilResultByKey = {};   // key -> { dateObj, verified }
    var chargerResultByKey = {}; // key -> { dateObj, verified }

    // 2. Read Civil PM Logs
    var civilSheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_PM_CIVIL || "PM_ElectricalCivil_Log") : null;
    if (civilSheet) {
      var cData = civilSheet.getDataRange().getValues();
      if (cData.length > 1) {
        for (var c = cData.length - 1; c >= 1; c--) {
          var rawStName = cData[c][2] ? cData[c][2].toString().trim() : "";
          if (!rawStName) continue;

          var stObj = findStationObj(rawStName);
          if (!stObj) continue;
          var civilKey = cleanPMKeyV2(stObj.stationName);
          if (civilResultByKey.hasOwnProperty(civilKey)) continue; // already resolved (newest match found)

          var rawDate = cData[c][3] || cData[c][0];
          var dObj = rawDate ? new Date(rawDate) : null;
          var dateValid = dObj && !isNaN(dObj.getTime());

          if (hasTargetPeriod) {
            // Only accept a row that actually falls in the requested
            // period - keep scanning older rows for this station otherwise.
            if (!rowMatchesTargetPeriodV3(dObj)) continue;
          } else if (!dateValid) {
            // All-time mode preserves the old fallback: an unparsable date
            // still counts as "the newest record" so the station isn't
            // reported as having no PM at all.
            civilResultByKey[civilKey] = { dateObj: null, rawLabel: rawDate ? rawDate.toString() : "", verified: false };
            continue;
          }

          // verifyStationPMV2 actually writes "VERIFIED" at index 25 (the
          // column right after RecordID at 24) when no named header is
          // found - 22-24 were kept here as a defensive hedge but never
          // included the real column, so a verified civil PM could show as
          // "Pending" here while the detail view (which scans the whole
          // row) correctly showed it as Verified.
          var civilVerified = (cData[c][22] === "VERIFIED" || cData[c][23] === "VERIFIED" || cData[c][24] === "VERIFIED" || cData[c][25] === "VERIFIED");
          civilResultByKey[civilKey] = { dateObj: dateValid ? dObj : null, rawLabel: dateValid ? null : (rawDate ? rawDate.toString() : ""), verified: civilVerified };

          if (dateValid && dObj.getFullYear() === currentYear && dObj.getMonth() === currentMonth) {
            stObj.hasCivilThisMonth = true;
          }
          // If next PM Due Date is empty, calculate same day next month
          // (always from this resolved row, whichever period it belongs to).
          if (dateValid && !stObj.nextPmDueDate) {
            var nextM = new Date(dObj.getFullYear(), dObj.getMonth() + 1, dObj.getDate());
            var ndd = String(nextM.getDate()).padStart(2, '0');
            var nmm = String(nextM.getMonth() + 1).padStart(2, '0');
            stObj.nextPmDueDate = ndd + "/" + nmm + "/" + nextM.getFullYear();
          }
        }
      }
    }

    // 3. Read Charger PM Logs
    var chgSheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_PM_CHARGER || "PM_Charger_Log") : null;
    if (chgSheet) {
      var chgData = chgSheet.getDataRange().getValues();
      if (chgData.length > 1) {
        // Track the newest row seen per charger (CP ID) so an old verified
        // PM on a charger can't keep it marked Verified after a newer,
        // still-unverified PM came in for that same charger (or, in
        // month-filtered mode, so verification reflects THAT charger's
        // newest visit within the requested period specifically).
        var seenChgCpIdsOverviewV3 = {};
        for (var h = chgData.length - 1; h >= 1; h--) {
          var rawStNameChg = chgData[h][2] ? chgData[h][2].toString().trim() : "";
          if (!rawStNameChg) continue;

          var stObjChg = findStationObj(rawStNameChg);
          if (!stObjChg) continue;
          var chgKey = cleanPMKeyV2(stObjChg.stationName);

          var rawDateChg = chgData[h][3] || chgData[h][0];
          var dObjChg = rawDateChg ? new Date(rawDateChg) : null;
          var dateValidChg = dObjChg && !isNaN(dObjChg.getTime());
          var rowInPeriod = hasTargetPeriod ? rowMatchesTargetPeriodV3(dObjChg) : true;

          if (!chargerResultByKey.hasOwnProperty(chgKey) && rowInPeriod) {
            if (hasTargetPeriod && !dateValidChg) {
              // can't confirm this row falls in the requested period - skip it
            } else if (!hasTargetPeriod && !dateValidChg) {
              chargerResultByKey[chgKey] = { dateObj: null, rawLabel: rawDateChg ? rawDateChg.toString() : "", verified: false };
            } else {
              chargerResultByKey[chgKey] = { dateObj: dObjChg, rawLabel: null, verified: false };
              if (dObjChg.getFullYear() === currentYear && dObjChg.getMonth() === currentMonth) {
                stObjChg.hasChargerThisMonth = true;
              }
            }
          }

          var chgCpIdKey = (chgData[h][4] ? chgData[h][4].toString().trim().toLowerCase() : ("row_" + h));
          var chgStationCpKey = cleanPMKeyV2(rawStNameChg) + "|" + chgCpIdKey;
          if (!seenChgCpIdsOverviewV3[chgStationCpKey] && rowInPeriod) {
            seenChgCpIdsOverviewV3[chgStationCpKey] = true;
            // Index 30 is the current Verification Status column (past
            // RecordID at 29); index 26 is checked too for rows verified
            // before that column existed, back when verification was
            // (mistakenly) written into the Payload JSON slot.
            if (chgData[h][30] === "VERIFIED" || chgData[h][26] === "VERIFIED" || chgData[h][26] === true) {
              if (chargerResultByKey[chgKey]) chargerResultByKey[chgKey].verified = true;
              else chargerResultByKey[chgKey] = { dateObj: dateValidChg ? dObjChg : null, rawLabel: dateValidChg ? null : (rawDateChg ? rawDateChg.toString() : ""), verified: true };
            }
          }
        }
      }
    }

    // Merge civil + charger results: lastPmDate is the true MORE RECENT of
    // the two (previously it was just "whichever section ran first"), and
    // isVerified is true if either the resolved civil or charger record for
    // this period was verified.
    for (var mergeKey in stationsMap) {
      if (!stationsMap.hasOwnProperty(mergeKey)) continue;
      var mObj = stationsMap[mergeKey];
      var civilRes = civilResultByKey[mergeKey];
      var chgRes = chargerResultByKey[mergeKey];
      if (!civilRes && !chgRes) continue;

      var winner = null;
      if (civilRes && chgRes) {
        if (civilRes.dateObj && chgRes.dateObj) winner = (chgRes.dateObj.getTime() > civilRes.dateObj.getTime()) ? chgRes : civilRes;
        else winner = civilRes.dateObj ? civilRes : (chgRes.dateObj ? chgRes : civilRes);
      } else {
        winner = civilRes || chgRes;
      }

      if (winner.dateObj) {
        var wd = winner.dateObj;
        var wdd = String(wd.getDate()).padStart(2, '0');
        mObj.lastPmDate = wdd + " " + monthNamesV3Overview[wd.getMonth()] + " " + wd.getFullYear();
      } else if (winner.rawLabel) {
        mObj.lastPmDate = winner.rawLabel;
      }
      mObj.isVerified = !!((civilRes && civilRes.verified) || (chgRes && chgRes.verified));
    }

    // Return unique items list
    var uniqueList = [];
    var seenKeys = {};
    for (var k in stationsMap) {
      var item = stationsMap[k];
      var uniqueId = cleanPMKeyV2(item.stationName);
      if (!seenKeys[uniqueId]) {
        seenKeys[uniqueId] = true;
        uniqueList.push(item);
      }
    }

    if (scope.scoped) {
      uniqueList = uniqueList.filter(function(item) { return engineerInHodScopeV3(scope, item.engineer); });
    }

    return { success: true, items: uniqueList };
  } catch (e) {
    return { success: false, message: e.toString(), items: [] };
  }
}


/**
 * 2. Fetches complete PM report details (Civil & Charger) for a specific station.
 * Canonical key matching ensures reliable fetching.
 */
/**
 * Helper to safely serialize cell values into JSON-friendly strings
 */
function safePMStrV2(val) {
  if (val === null || val === undefined) return "";
  if (val instanceof Date) {
    if (isNaN(val.getTime())) return "";
    try {
      return Utilities.formatDate(val, Session.getScriptTimeZone() || "GMT", "yyyy-MM-dd HH:mm");
    } catch(eDate) {
      return val.toISOString().split("T")[0];
    }
  }
  return val.toString().trim();
}

/**
 * 2. Fetches complete PM report details (Civil & Charger) for a specific station.
 * Converts all cell values to clean strings to ensure 100% JSON serialization success.
 */
/**
 * 2. Fetches complete PM report details (Civil & ALL Chargers) for a specific station.
 * Supports multi-charger stations (1 to 10+ CP IDs per station).
 */
function getStationFullPMReportV2(searchQuery, token) {
  var access = requireSession(token, ['HOD', 'Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };
  try {
    var ss = getSpreadsheetV3();
    var civilLogs = [];
    var chargerLogs = [];
    var isVerified = false;
    var verifier = "";
    var verifiedDate = "";

    var qKey = cleanPMKeyV2(searchQuery);

    // Target count of Civil & Electrical PM submissions per location
    var LOCATION_CIVIL_PM_TARGETS = {
      'goectrivandrumlulumall': 2,
      'goeckochiedappallydaffodils': 2
    };
    var targetCivilCount = LOCATION_CIVIL_PM_TARGETS[qKey] || 1;

    // 1. Scan Civil PM Sheet (Station level)
    var civilSheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_PM_CIVIL || "PM_ElectricalCivil_Log") : null;
    if (civilSheet) {
      var cData = civilSheet.getDataRange().getValues();
      for (var c = cData.length - 1; c >= 1; c--) {
        var stLogKey = cleanPMKeyV2(cData[c][2]);
        if (!stLogKey) continue;

        if (stLogKey === qKey || stLogKey.indexOf(qKey) !== -1 || qKey.indexOf(stLogKey) !== -1) {
          // Payload JSON is always at fixed index 23 (PM_ElectricalCivil_Log's
          // declared header length is 24) - don't use "last column", since
          // RecordID now lives in a trailing column after it.
          var rawPayload = safePMStrV2(cData[c].length > 23 ? cData[c][23] : cData[c][cData[c].length - 1]);
          var pObj = {};
          try { if (rawPayload && rawPayload.indexOf("{") !== -1) pObj = JSON.parse(rawPayload); } catch(e){}

          var cLogObj = {
            recordId: cData[c].length > 24 ? safePMStrV2(cData[c][24]) : '',
            timestamp: safePMStrV2(cData[c][0]),
            engineer: pObj.engineer || safePMStrV2(cData[c][1]),
            locationName: pObj.locationName || safePMStrV2(cData[c][2]),
            pmDate: pObj.pmDate || safePMStrV2(cData[c][3]),

            transformerInstalled: pObj.transformerInstalled || safePMStrV2(cData[c][4]),
            beforePmMedia: pObj.beforePmMedia || safePMStrV2(cData[c][5]),
            panelMaintenance: pObj.panelMaintenance || safePMStrV2(cData[c][6]),
            panelVoltage: pObj.panelVoltage || safePMStrV2(cData[c][7]),
            earthPitVoltage: pObj.earthPitVoltage || safePMStrV2(cData[c][8]),
            spdStatus: pObj.spdStatus || pObj.spdElrStatus || safePMStrV2(cData[c][9]),
            elrStatus: pObj.elrStatus || pObj.spdElrStatus || safePMStrV2(cData[c][10]),
            mfmMeterStatus: pObj.mfmMeterStatus || safePMStrV2(cData[c][11]),
            unauthorizedLoad: pObj.unauthorizedLoad || safePMStrV2(cData[c][12]),
            canopyLeakageStatus: pObj.canopyLeakageStatus || pObj.canopyGreenMatStatus || safePMStrV2(cData[c][13]),
            cctvModemStatus: pObj.cctvModemStatus || safePMStrV2(cData[c][14]),
            canopyLightingStatus: pObj.canopyLightingStatus || pObj.lightingSignageStatus || safePMStrV2(cData[c][15]),
            brandingBoardStatus: pObj.brandingBoardStatus || pObj.lightingSignageStatus || safePMStrV2(cData[c][16]),
            instructionSignageStatus: pObj.instructionSignageStatus || pObj.lightingSignageStatus || safePMStrV2(cData[c][17]),
            fireExtinguisherStatus: pObj.fireExtinguisherStatus || safePMStrV2(cData[c][18]),
            fireExtinguisherPhoto: pObj.fireExtinguisherPhoto || safePMStrV2(cData[c][19]),
            civilBayBollardsStatus: pObj.civilBayBollardsStatus || safePMStrV2(cData[c][20]),
            afterPmMedia: pObj.afterPmMedia || safePMStrV2(cData[c][21]),
            remarks: pObj.remarks || safePMStrV2(cData[c][22])
          };

          civilLogs.push(cLogObj);

          for (var colIdx = 0; colIdx < cData[c].length; colIdx++) {
            var valStr = safePMStrV2(cData[c][colIdx]);
            if (valStr === "VERIFIED") {
              isVerified = true;
              verifier = safePMStrV2(cData[c][colIdx + 1]) || "HOD";
              verifiedDate = safePMStrV2(cData[c][colIdx + 2]);
              break;
            }
          }

          if (civilLogs.length >= targetCivilCount) {
            break;
          }
        }
      }
    }

    // 2. Scan Charger PM Sheet for ALL Chargers at this station
    var chgSheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_PM_CHARGER || "PM_Charger_Log") : null;
    if (chgSheet) {
      var chgData = chgSheet.getDataRange().getValues();
      var seenCpIds = {};

      // Scan from newest to oldest to get the latest PM for each CP ID
      for (var h = chgData.length - 1; h >= 1; h--) {
        var chgStKey = cleanPMKeyV2(chgData[h][2]);
        var cpIdKey = cleanPMKeyV2(chgData[h][4]);

        if (chgStKey === qKey || cpIdKey === qKey || chgStKey.indexOf(qKey) !== -1 || qKey.indexOf(chgStKey) !== -1) {
          var cpIdVal = safePMStrV2(chgData[h][4]) || ("charger_" + h);
          
          if (!seenCpIds[cpIdVal]) {
            seenCpIds[cpIdVal] = true;

            chargerLogs.push({
              recordId: chgData[h].length > 29 ? safePMStrV2(chgData[h][29]) : '',
              timestamp: safePMStrV2(chgData[h][0]),
              engineer: safePMStrV2(chgData[h][1]),
              locationName: safePMStrV2(chgData[h][2]),
              pmDate: safePMStrV2(chgData[h][3]),
              cpId: safePMStrV2(chgData[h][4]),
              serialNo: safePMStrV2(chgData[h][5]),
              capacityAndType: safePMStrV2(chgData[h][6]),
              beforePmMedia: safePMStrV2(chgData[h][7]),
              alarmsStatus: safePMStrV2(chgData[h][8]),
              cleaningStatus: safePMStrV2(chgData[h][9]),
              filterReplacement: safePMStrV2(chgData[h][10]),
              cablesTightness: safePMStrV2(chgData[h][11]),
              gunsAndSockets: safePMStrV2(chgData[h][12]),
              rodentProofing: safePMStrV2(chgData[h][13]),
              displayTouchStatus: safePMStrV2(chgData[h][14]),
              doorsHingesStatus: safePMStrV2(chgData[h][15]),
              powerModuleStatus: safePMStrV2(chgData[h][16]),
              inputVoltages: safePMStrV2(chgData[h][17]),
              neutralEarthVoltage: safePMStrV2(chgData[h][18]),
              emergencyStopTest: safePMStrV2(chgData[h][19]),
              internetStatus: safePMStrV2(chgData[h][20]),
              mcbRccbSmpsStatus: safePMStrV2(chgData[h][21]),
              vehicleChargingTest: safePMStrV2(chgData[h][22]),
              rfidStatus: safePMStrV2(chgData[h][23]),
              afterPmMedia: safePMStrV2(chgData[h][24]),
              remarks: safePMStrV2(chgData[h][25])
            });

            // Index 30 is the current Verification Status column (past
            // RecordID at 29); index 26 is the old (pre-RecordID) location,
            // kept for backward-compat with rows verified before this fix.
            if (chgData[h][30] === "VERIFIED") {
              isVerified = true;
              verifier = safePMStrV2(chgData[h][31]) || "HOD";
              verifiedDate = safePMStrV2(chgData[h][32]);
            } else if (chgData[h][26] === "VERIFIED") {
              isVerified = true;
              verifier = safePMStrV2(chgData[h][27]) || "HOD";
              verifiedDate = safePMStrV2(chgData[h][28]);
            }
          }
        }
      }
    }

    // An HOD assigned specific engineers can only drill into stations one of
    // their engineers actually serviced - refuse rather than expose a
    // station outside their scope just because they knew/guessed its name.
    var hodScope = getHodEngineerScopeV3(token);
    if (hodScope.ok && hodScope.scoped) {
      var allLogsForScope = civilLogs.concat(chargerLogs);
      var inScope = allLogsForScope.length === 0 || allLogsForScope.some(function(l) { return engineerInHodScopeV3(hodScope, l.engineer); });
      if (!inScope) return { success: false, message: "Access Restricted: this station isn't assigned to any engineer in your team." };
    }

    return {
      success: true,
      stationName: searchQuery,
      targetCivilCount: targetCivilCount,
      civilLog: civilLogs.length > 0 ? civilLogs[0] : {},
      civilLogs: civilLogs,
      chargerLog: chargerLogs.length > 0 ? chargerLogs[0] : {},
      chargerLogs: chargerLogs,
      isVerified: isVerified,
      verifier: verifier,
      verifiedDate: verifiedDate
    };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

function verifyStationPMV2(stationName, verifierName, token) {
  var access = requireSession(token, ['HOD', 'Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };
  verifierName = access.session.fullName || access.session.username || verifierName || "HOD";
  try {
    var ss = getSpreadsheetV3();
    var nowStr = Utilities.formatDate(new Date(), Session.getScriptTimeZone() || "GMT", "yyyy-MM-dd HH:mm");
    var qKey = cleanPMKeyV2(stationName);

    var civilSheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_PM_CIVIL || "PM_ElectricalCivil_Log") : null;
    if (civilSheet) {
      var cData = civilSheet.getDataRange().getValues();
      if (cData.length > 1) {
        var cHeaders = cData[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
        var colVerif = cHeaders.indexOf("verification status");
        if (colVerif === -1) colVerif = cHeaders.indexOf("verified");
        if (colVerif === -1) colVerif = 25; // Default column Z (26th col)

        var colBy = cHeaders.indexOf("verified by");
        if (colBy === -1) colBy = colVerif + 1;

        var colDate = cHeaders.indexOf("verified date");
        if (colDate === -1) colDate = colVerif + 2;

        for (var c = cData.length - 1; c >= 1; c--) {
          var st = cleanPMKeyV2(cData[c][2]);
          if (isPMStationMatchV2(st, qKey)) {
            civilSheet.getRange(c + 1, colVerif + 1).setValue("VERIFIED");
            civilSheet.getRange(c + 1, colBy + 1).setValue(verifierName || "HOD");
            civilSheet.getRange(c + 1, colDate + 1).setValue(nowStr);
            break;
          }
        }
      }
    }

    var chgSheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_PM_CHARGER || "PM_Charger_Log") : null;
    if (chgSheet) {
      var chgData = chgSheet.getDataRange().getValues();
      if (chgData.length > 1) {
        var chgHeaders = chgData[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
        var colVerifChg = chgHeaders.indexOf("verification status");
        if (colVerifChg === -1) colVerifChg = chgHeaders.indexOf("verified");
        // Index 26 is "Payload JSON" (pmChargerHeaders' 27th declared column)
        // and 29 is RecordID - writing verification there used to silently
        // destroy the row's JSON payload. Use 30/31/32, past both, and label
        // them so the name-based lookup above can find them from now on.
        if (colVerifChg === -1) colVerifChg = 30;
        ensureTrailingHeadersV3(chgSheet, 30, ["Verification Status", "Verified By", "Verified Date"]);

        var colByChg = chgHeaders.indexOf("verified by");
        if (colByChg === -1) colByChg = colVerifChg + 1;

        var colDateChg = chgHeaders.indexOf("verified date");
        if (colDateChg === -1) colDateChg = colVerifChg + 2;

        for (var h = chgData.length - 1; h >= 1; h--) {
          var stChg = cleanPMKeyV2(chgData[h][2]);
          var cpIdKey = cleanPMKeyV2(chgData[h][4]);

          if (isPMStationMatchV2(stChg, qKey) || isPMStationMatchV2(cpIdKey, qKey)) {
            chgSheet.getRange(h + 1, colVerifChg + 1).setValue("VERIFIED");
            chgSheet.getRange(h + 1, colByChg + 1).setValue(verifierName || "HOD");
            chgSheet.getRange(h + 1, colDateChg + 1).setValue(nowStr);
          }
        }
      }
    }

    return {
      success: true,
      message: "PM Report for '" + stationName + "' has been successfully verified by " + (verifierName || "HOD") + "."
    };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}


/**
 * 4. Dispatches a custom HTML PM Report email to recipient via operations@example.com.
 */
/**
 * 4. Dispatches a custom HTML PM Report email to recipient via operations@example.com.
 * Uses 100% email-client compatible table layout and clean text badges.
 */
function sendPMReportEmailV2(recipientEmail, recipientName, stationName, selectedItems, customNotes, token) {
  var access = requireSession(token, ['HOD', 'Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };
  try {
    if (!recipientEmail || recipientEmail.indexOf("@") === -1) {
      return { success: false, message: "Valid recipient email address is required." };
    }

    var reportData = getStationFullPMReportV2(stationName, token);
    if (!reportData.success) {
      return { success: false, message: "Could not fetch report details for email." };
    }

    var civilList = (reportData.civilLogs && reportData.civilLogs.length > 0) ? reportData.civilLogs : (reportData.civilLog && reportData.civilLog.pmDate ? [reportData.civilLog] : []);
    var civil = civilList[0] || {};
    var chargerList = (reportData.chargerLogs && reportData.chargerLogs.length > 0) ? reportData.chargerLogs : (reportData.chargerLog && reportData.chargerLog.pmDate ? [reportData.chargerLog] : []);
    var items = selectedItems || {};

    // Helper to check if item is enabled (default to true if items map is simple)
    function isItemChecked(key) {
      if (items[key] === undefined) return true;
      return items[key] === true;
    }

    var bodyHtml = '<div style="font-family: Arial, sans-serif; background-color:#0f172a; color:#f8fafc; padding:24px; border-radius:12px; max-width:680px; margin:0 auto;">';
    
    var statusBadgeBg = reportData.isVerified ? "#0284c7" : "#10b981";
    var statusBadgeText = reportData.isVerified ? "VERIFIED REPORT" : "PM REPORT";

    // Header Table with HTML Table Cell Alignment (Email Client Compatible)
    bodyHtml += '<table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-bottom:2px solid #00e5ff; padding-bottom:16px; margin-bottom:22px;">';
    bodyHtml += '<tr>';
    bodyHtml += '<td width="130" align="left" valign="middle" style="padding-right:12px;">';
    bodyHtml += '<img src="cid:goecLogo" height="48" style="height:48px; max-height:48px; width:auto; display:block; border:0;" alt="GOEC Logo" />';
    bodyHtml += '</td>';
    bodyHtml += '<td align="left" valign="middle">';
    bodyHtml += '<h2 style="color:#00e5ff; margin:0; font-size:18px; font-weight:bold; font-family:Arial, Helvetica, sans-serif; line-height:1.2;">EVCS Service and Maintenance</h2>';
    bodyHtml += '<p style="color:#94a3b8; margin:4px 0 0 0; font-size:12px; font-family:Arial, Helvetica, sans-serif;">Official Station PM Inspection Report</p>';
    bodyHtml += '</td>';
    bodyHtml += '<td align="right" valign="middle" style="padding-left:10px;">';
    bodyHtml += '<span style="background-color:' + statusBadgeBg + '; color:#ffffff; padding:6px 12px; border-radius:6px; font-weight:bold; font-size:11px; display:inline-block; font-family:Arial, Helvetica, sans-serif; white-space:nowrap;">' + statusBadgeText + '</span>';
    bodyHtml += '</td>';
    bodyHtml += '</tr>';
    bodyHtml += '</table>';

    bodyHtml += '<p style="font-size:14px; line-height:1.5; color:#f8fafc; font-family:Arial, sans-serif;">Dear <strong>' + recipientName + '</strong>,</p>';
    bodyHtml += '<p style="font-size:14px; line-height:1.5; color:#cbd5e1; font-family:Arial, sans-serif; margin-bottom:20px;">Please find below the detailed Preventive Maintenance (PM) Inspection Report for <strong>' + stationName + '</strong>.</p>';

    // Executive Summary
    if (isItemChecked('exec_summary')) {
      var cpidCapacityHtml = "";
      if (chargerList.length > 1) {
        var itemsArr = [];
        for (var cIdx = 0; cIdx < chargerList.length; cIdx++) {
          var cObj = chargerList[cIdx];
          var cId = cObj.cpId || ("Charger " + (cIdx + 1));
          var cCap = cObj.capacityAndType || "-";
          if (cCap.toLowerCase().indexOf("kw") === -1 && cCap !== "-") cCap += " kW";
          itemsArr.push('<div style="margin-bottom:2px;"><strong>Charger ' + (cIdx + 1) + ':</strong> ' + cId + ' / ' + cCap + '</div>');
        }
        cpidCapacityHtml = itemsArr.join("");
      } else {
        var singleObj = chargerList[0] || {};
        var cId = singleObj.cpId || "-";
        var cCap = singleObj.capacityAndType || "-";
        if (cCap.toLowerCase().indexOf("kw") === -1 && cCap !== "-") cCap += " kW";
        cpidCapacityHtml = cId + ' / ' + cCap;
      }

      var civilSummaryLabel = civilList.length > 1 ? (civilList.length + ' Substation / Civil Structures Verified') : (civil.transformerInstalled || 'Completed');

      bodyHtml += '<div style="background-color:#1e293b; border:1px solid #334155; border-radius:8px; padding:16px; margin-bottom:18px;">';
      bodyHtml += '<h3 style="color:#ffffff; margin:0 0 10px 0; font-size:14px; border-bottom:1px solid #334155; padding-bottom:6px; font-family:Arial, sans-serif;">\ud83d\udccc Executive Summary</h3>';
      bodyHtml += '<table width="100%" cellpadding="4" cellspacing="0" border="0" style="font-size:13px; color:#cbd5e1; font-family:Arial, sans-serif;">';
      bodyHtml += '<tr><td width="35%" style="color:#94a3b8; valign:top;">Station Name:</td><td style="font-weight:bold; color:#ffffff;">' + stationName + '</td></tr>';
      bodyHtml += '<tr><td style="color:#94a3b8; valign:top;">Assigned Engineer:</td><td style="color:#00e5ff; font-weight:bold;">' + (civil.engineer || (chargerList[0] ? chargerList[0].engineer : "Field Operations")) + '</td></tr>';
      bodyHtml += '<tr><td style="color:#94a3b8; valign:top;">Civil Structures:</td><td style="color:#ffffff; font-weight:bold;">' + civilSummaryLabel + '</td></tr>';
      bodyHtml += '<tr><td style="color:#94a3b8; valign:top;">CP ID / Capacity:</td><td style="color:#ffffff;">' + cpidCapacityHtml + '</td></tr>';
      bodyHtml += '</table></div>';
    }

    // Electrical & Civil Inspection (Support Multiple Structures)
    if (civilList.length > 0) {
      for (var cvIdx = 0; cvIdx < civilList.length; cvIdx++) {
        var cvItem = civilList[cvIdx];
        var civilRows = [];
        var structLabel = civilList.length > 1 ? (' Structure ' + (cvIdx + 1)) : '';

        if ((isItemChecked('civ_transformer') || isItemChecked('civ_substation')) && cvItem.transformerInstalled) civilRows.push('<tr><td width="40%" style="color:#94a3b8;">Transformer Type:</td><td style="color:#ffffff; font-weight:bold;">' + cvItem.transformerInstalled + '</td></tr>');
        if ((isItemChecked('civ_panel_main') || isItemChecked('civ_panel')) && cvItem.panelMaintenance) civilRows.push('<tr><td style="color:#94a3b8;">Electrical Panel Maintenance:</td><td style="color:#ffffff; font-weight:bold;">' + cvItem.panelMaintenance + '</td></tr>');
        if ((isItemChecked('civ_panel_voltage') || isItemChecked('civ_panel_main')) && cvItem.panelVoltage) civilRows.push('<tr><td style="color:#94a3b8;">Panel Voltages (L-L & L-N):</td><td style="color:#00e5ff; font-weight:bold;">' + cvItem.panelVoltage + '</td></tr>');
        if ((isItemChecked('civ_earth_voltage') || isItemChecked('civ_earth')) && cvItem.earthPitVoltage) civilRows.push('<tr><td style="color:#94a3b8;">Earth Pit Voltage:</td><td style="color:#00e676; font-weight:bold;">' + cvItem.earthPitVoltage + ' V</td></tr>');
        if ((isItemChecked('civ_spd_status') || isItemChecked('civ_earth')) && cvItem.spdStatus) civilRows.push('<tr><td style="color:#94a3b8;">SPD Status:</td><td style="color:#ffffff; font-weight:bold;">' + cvItem.spdStatus + '</td></tr>');
        if ((isItemChecked('civ_elr_status') || isItemChecked('civ_elr_mfm')) && cvItem.elrStatus) civilRows.push('<tr><td style="color:#94a3b8;">ELR Tripping Status:</td><td style="color:#ffffff; font-weight:bold;">' + cvItem.elrStatus + '</td></tr>');
        if ((isItemChecked('civ_mfm_meter') || isItemChecked('civ_elr_mfm')) && cvItem.mfmMeterStatus) civilRows.push('<tr><td style="color:#94a3b8;">MFM Meter Reading:</td><td style="color:#ffffff; font-weight:bold;">' + cvItem.mfmMeterStatus + '</td></tr>');
        if ((isItemChecked('civ_unauth_load') || isItemChecked('civ_elr_mfm')) && cvItem.unauthorizedLoad) civilRows.push('<tr><td style="color:#94a3b8;">Unauthorized Load Check:</td><td style="color:#ffffff; font-weight:bold;">' + cvItem.unauthorizedLoad + '</td></tr>');
        if ((isItemChecked('civ_canopy_structure') || isItemChecked('civ_canopy_mat')) && cvItem.canopyLeakageStatus) civilRows.push('<tr><td style="color:#94a3b8;">Canopy Structural Integrity:</td><td style="color:#ffffff; font-weight:bold;">' + cvItem.canopyLeakageStatus + '</td></tr>');
        if ((isItemChecked('civ_cctv_modem') || isItemChecked('civ_canopy_mat')) && cvItem.cctvModemStatus) civilRows.push('<tr><td style="color:#94a3b8;">Modem & CCTV Status:</td><td style="color:#ffffff; font-weight:bold;">' + cvItem.cctvModemStatus + '</td></tr>');
        if ((isItemChecked('civ_canopy_lighting') || isItemChecked('civ_safety_fire')) && cvItem.canopyLightingStatus) civilRows.push('<tr><td style="color:#94a3b8;">Canopy Lighting:</td><td style="color:#ffffff; font-weight:bold;">' + cvItem.canopyLightingStatus + '</td></tr>');
        if ((isItemChecked('civ_branding_board') || isItemChecked('civ_safety_fire')) && cvItem.brandingBoardStatus) civilRows.push('<tr><td style="color:#94a3b8;">External Branding Board:</td><td style="color:#ffffff; font-weight:bold;">' + cvItem.brandingBoardStatus + '</td></tr>');
        if ((isItemChecked('civ_instruction_signage') || isItemChecked('civ_safety_fire')) && cvItem.instructionSignageStatus) civilRows.push('<tr><td style="color:#94a3b8;">Instruction Signage:</td><td style="color:#ffffff; font-weight:bold;">' + cvItem.instructionSignageStatus + '</td></tr>');
        if ((isItemChecked('civ_fire_extinguisher') || isItemChecked('civ_safety_fire')) && cvItem.fireExtinguisherStatus) civilRows.push('<tr><td style="color:#94a3b8;">Fire Extinguisher Status:</td><td style="color:#ffffff; font-weight:bold;">' + cvItem.fireExtinguisherStatus + '</td></tr>');
        if ((isItemChecked('civ_civil_bay_bollards') || isItemChecked('civ_interlock_parking')) && cvItem.civilBayBollardsStatus) civilRows.push('<tr><td style="color:#94a3b8;">Civil Bay & Bollards:</td><td style="color:#ffffff; font-weight:bold;">' + cvItem.civilBayBollardsStatus + '</td></tr>');

        if (civilRows.length > 0) {
          bodyHtml += '<div style="background-color:#1e293b; border:1px solid #334155; border-radius:8px; padding:16px; margin-bottom:18px;">';
          bodyHtml += '<h3 style="color:#00e5ff; margin:0 0 10px 0; font-size:14px; border-bottom:1px solid #334155; padding-bottom:6px; font-family:Arial, sans-serif;">&#9889; Electrical & Civil Inspection' + structLabel + '</h3>';
          bodyHtml += '<table width="100%" cellpadding="4" cellspacing="0" border="0" style="font-size:12px; color:#cbd5e1; font-family:Arial, sans-serif;">';
          bodyHtml += civilRows.join('');
          bodyHtml += '</table></div>';
        }
      }
    }

    // Charger PM Checklists (Every Item Checkable Individually)
    if (chargerList.length > 0) {
      for (var k = 0; k < chargerList.length; k++) {
        var chgObj = chargerList[k];
        var chgRows = [];

        if ((isItemChecked('chg_alarms')) && chgObj.alarmsStatus) chgRows.push('<tr><td width="40%" style="color:#94a3b8;">Alarms Status:</td><td style="color:#ffffff; font-weight:bold;">' + chgObj.alarmsStatus + '</td></tr>');
        if ((isItemChecked('chg_cleaning')) && chgObj.cleaningStatus) chgRows.push('<tr><td style="color:#94a3b8;">Cleaning Status:</td><td style="color:#ffffff; font-weight:bold;">' + chgObj.cleaningStatus + '</td></tr>');
        if ((isItemChecked('chg_filter') || isItemChecked('chg_alarms')) && chgObj.filterReplacement) chgRows.push('<tr><td style="color:#94a3b8;">Dust Filter Replacement:</td><td style="color:#ffffff; font-weight:bold;">' + chgObj.filterReplacement + '</td></tr>');
        if ((isItemChecked('chg_cables') || isItemChecked('chg_cleaning')) && chgObj.cablesTightness) chgRows.push('<tr><td style="color:#94a3b8;">Cable Tightness:</td><td style="color:#ffffff; font-weight:bold;">' + chgObj.cablesTightness + '</td></tr>');
        if ((isItemChecked('chg_guns')) && chgObj.gunsAndSockets) chgRows.push('<tr><td style="color:#94a3b8;">Guns & Sockets:</td><td style="color:#ffffff; font-weight:bold;">' + chgObj.gunsAndSockets + '</td></tr>');
        if ((isItemChecked('chg_rodent') || isItemChecked('chg_guns')) && chgObj.rodentProofing) chgRows.push('<tr><td style="color:#94a3b8;">Rodent Proofing:</td><td style="color:#ffffff; font-weight:bold;">' + chgObj.rodentProofing + '</td></tr>');
        if ((isItemChecked('chg_display')) && chgObj.displayTouchStatus) chgRows.push('<tr><td style="color:#94a3b8;">Display & Touch:</td><td style="color:#ffffff; font-weight:bold;">' + chgObj.displayTouchStatus + '</td></tr>');
        if ((isItemChecked('chg_doors') || isItemChecked('chg_display_doors')) && chgObj.doorsHingesStatus) chgRows.push('<tr><td style="color:#94a3b8;">Doors & Locks:</td><td style="color:#ffffff; font-weight:bold;">' + chgObj.doorsHingesStatus + '</td></tr>');
        if ((isItemChecked('chg_power_module')) && chgObj.powerModuleStatus) chgRows.push('<tr><td style="color:#94a3b8;">Power Module Status:</td><td style="color:#ffffff; font-weight:bold;">' + chgObj.powerModuleStatus + '</td></tr>');
        if ((isItemChecked('chg_input_voltage')) && chgObj.inputVoltages) chgRows.push('<tr><td style="color:#94a3b8;">Input Voltages:</td><td style="color:#00e5ff; font-weight:bold;">' + chgObj.inputVoltages + '</td></tr>');
        if ((isItemChecked('chg_ne_voltage') || isItemChecked('chg_voltages')) && chgObj.neutralEarthVoltage) chgRows.push('<tr><td style="color:#94a3b8;">Neutral-Earth Voltage:</td><td style="color:#00e676; font-weight:bold;">' + chgObj.neutralEarthVoltage + ' V</td></tr>');
        if ((isItemChecked('chg_emergency_stop') || isItemChecked('chg_power_modules')) && chgObj.emergencyStopTest) chgRows.push('<tr><td style="color:#94a3b8;">Emergency Stop Test:</td><td style="color:#ffffff; font-weight:bold;">' + chgObj.emergencyStopTest + '</td></tr>');
        if ((isItemChecked('chg_internet') || isItemChecked('chg_tests')) && chgObj.internetStatus) chgRows.push('<tr><td style="color:#94a3b8;">Internet / Modem:</td><td style="color:#ffffff; font-weight:bold;">' + chgObj.internetStatus + '</td></tr>');
        if ((isItemChecked('chg_mcb_smps')) && chgObj.mcbRccbSmpsStatus) chgRows.push('<tr><td style="color:#94a3b8;">SMPS/MCB/RCCB Operation:</td><td style="color:#ffffff; font-weight:bold;">' + chgObj.mcbRccbSmpsStatus + '</td></tr>');
        if ((isItemChecked('chg_vehicle_test') || isItemChecked('chg_tests')) && chgObj.vehicleChargingTest) chgRows.push('<tr><td style="color:#94a3b8;">Vehicle Charging Test:</td><td style="color:#ffffff; font-weight:bold;">' + chgObj.vehicleChargingTest + '</td></tr>');
        if ((isItemChecked('chg_rfid')) && chgObj.rfidStatus) chgRows.push('<tr><td style="color:#94a3b8;">RFID Status:</td><td style="color:#ffffff; font-weight:bold;">' + chgObj.rfidStatus + '</td></tr>');

        if (chgRows.length > 0) {
          var chgTitle = chargerList.length > 1 ? ("&#128268; Charger " + (k + 1) + " PM Maintenance Checklist (" + (chgObj.cpId || "CP ID N/A") + ")") : "&#128268; Charger PM Maintenance Checklist";
          bodyHtml += '<div style="background-color:#1e293b; border:1px solid #334155; border-radius:8px; padding:16px; margin-bottom:18px;">';
          bodyHtml += '<h3 style="color:#00e676; margin:0 0 10px 0; font-size:14px; border-bottom:1px solid #334155; padding-bottom:6px; font-family:Arial, sans-serif;">' + chgTitle + '</h3>';
          bodyHtml += '<table width="100%" cellpadding="4" cellspacing="0" border="0" style="font-size:12px; color:#cbd5e1; font-family:Arial, sans-serif;">';
          bodyHtml += '<tr><td width="40%" style="color:#94a3b8;">CP ID / Serial:</td><td style="color:#ffffff; font-weight:bold;">' + (chgObj.cpId || "-") + ' / ' + (chgObj.serialNo || "-") + '</td></tr>';
          bodyHtml += '<tr><td style="color:#94a3b8;">Capacity:</td><td style="color:#ffffff; font-weight:bold;">' + (chgObj.capacityAndType || "-") + '</td></tr>';
          bodyHtml += chgRows.join('');
          bodyHtml += '</table></div>';
        }
      }
    }

    // Photo Proofs
    if (isItemChecked('photos')) {
      var photoLinks = [];
      if (civil.beforePmMedia) photoLinks.push('<a href="' + civil.beforePmMedia + '" style="color:#00e5ff; text-decoration:underline;">Civil Before PM Video</a>');
      if (civil.afterPmMedia) photoLinks.push('<a href="' + civil.afterPmMedia + '" style="color:#00e676; text-decoration:underline;">Civil After PM Video</a>');
      if (civil.fireExtinguisherPhoto) photoLinks.push('<a href="' + civil.fireExtinguisherPhoto + '" style="color:#ffb74d; text-decoration:underline;">Fire Extinguisher Photo</a>');

      for (var p = 0; p < chargerList.length; p++) {
        var pChg = chargerList[p];
        if (pChg.beforePmMedia) photoLinks.push('<a href="' + pChg.beforePmMedia + '" style="color:#00e5ff; text-decoration:underline;">Charger ' + (pChg.cpId ? '('+pChg.cpId+') ' : '') + 'Before PM Video</a>');
        if (pChg.afterPmMedia) photoLinks.push('<a href="' + pChg.afterPmMedia + '" style="color:#00e676; text-decoration:underline;">Charger ' + (pChg.cpId ? '('+pChg.cpId+') ' : '') + 'After PM Photo</a>');
      }
      
      if (photoLinks.length > 0) {
        bodyHtml += '<div style="margin-bottom:18px; font-size:13px; color:#94a3b8; font-family:Arial, sans-serif;">';
        bodyHtml += '<strong style="color:#ffffff;">\ud83c\udfac Inspection Proof Media & Photos:</strong><br><div style="margin-top:6px;">' + photoLinks.join(' &nbsp;|&nbsp; ') + '</div>';
        bodyHtml += '</div>';
      }
    }

    // Remarks
    if (isItemChecked('remarks')) {
      var allRem = [];
      if (civil.remarks) allRem.push('<strong>Civil & Electrical Remarks:</strong> ' + civil.remarks);
      for (var r = 0; r < chargerList.length; r++) {
        if (chargerList[r].remarks) allRem.push('<strong>Charger ' + (chargerList[r].cpId ? '('+chargerList[r].cpId+') ' : '') + 'Remarks:</strong> ' + chargerList[r].remarks);
      }
      if (allRem.length > 0) {
        bodyHtml += '<div style="background-color:#1e293b; border:1px solid #334155; border-radius:8px; padding:14px; font-size:12px; color:#cbd5e1; margin-bottom:18px;">';
        bodyHtml += allRem.join('<br>');
        bodyHtml += '</div>';
      }
    }

        if (customNotes) {
      bodyHtml += '<div style="background-color:#1e293b; border-left:4px solid #00e5ff; border:1px solid #334155; border-radius:8px; padding:14px; margin-bottom:18px; font-size:13px; color:#e2e8f0; font-family:Arial, sans-serif;">';
      bodyHtml += '<strong style="color:#00e5ff;">\u00f0\u0178\u201c\u009d HOD / Custom Notes:</strong> ' + customNotes;
      bodyHtml += '</div>';
    }

    bodyHtml += '<p style="font-size:12px; color:#94a3b8; margin-top:24px; border-top:1px solid #334155; padding-top:12px; font-family:Arial, sans-serif;">This is an automated PM Inspection Report generated by GOEC EVCS Service and Maintenance Portal.</p>';
    bodyHtml += '</div>';

    var subject = "PM Inspection Report: " + stationName + " [" + (reportData.isVerified ? "VERIFIED" : "COMPLETED") + "]";
    
    var logoBlob = Utilities.newBlob(Utilities.base64Decode(GOEC_LOGO_BASE64), 'image/png', 'goec_logo.png');

    MailApp.sendEmail({
      to: recipientEmail,
      subject: subject,
      htmlBody: bodyHtml,
      inlineImages: {
        goecLogo: logoBlob
      }
    });

    return {
      success: true,
      message: "PM Report email for '" + stationName + "' successfully sent to " + recipientEmail + "."
    };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

function authorizeEmailPermissionsV2() {
  var quota = MailApp.getRemainingDailyQuota();
  Logger.log("Email daily quota remaining: " + quota);
  try {
    var gmailQuota = GmailApp.getAliases();
    Logger.log("Gmail aliases: " + JSON.stringify(gmailQuota));
  } catch(e) {
    Logger.log("Gmail alias check: " + e.toString());
  }
}

/**
 * Automatically updates the PM Due Date in Charger Inventory sheet to same day next month
 */
function updateStationPMDueDateV2(locationName, pmDateStr) {
  try {
    if (!locationName) return;
    var ss = getSpreadsheetV3();
    if (!ss) return;

    var dateObj = parseDateAnyV2(pmDateStr);
    if (!dateObj || isNaN(dateObj.getTime())) dateObj = new Date();

    // Calculate same day next month
    var year = dateObj.getFullYear();
    var month = dateObj.getMonth(); // 0-indexed
    var day = dateObj.getDate();

    var nextMonthDate = new Date(year, month + 1, day);
    // Handle month overflow (e.g. Jan 31 -> Feb 28)
    if (nextMonthDate.getMonth() !== ((month + 1) % 12)) {
      nextMonthDate = new Date(year, month + 2, 0);
    }

    var dd = String(nextMonthDate.getDate()).padStart(2, '0');
    var mm = String(nextMonthDate.getMonth() + 1).padStart(2, '0');
    var yyyy = nextMonthDate.getFullYear();
    var formattedDueDate = dd + '/' + mm + '/' + yyyy;

    var invSheet = ss.getSheetByName(CONFIG_V3.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory") || ss.getSheetByName("Sheet1");
    if (invSheet) {
      var iData = invSheet.getDataRange().getValues();
      if (iData.length > 1) {
        var info = findHeaderRowAndIndexes(iData);
        var iHeaders = iData[info.headerRowIdx].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
        
        var colSt = iHeaders.indexOf("station name");
        if (colSt === -1) colSt = iHeaders.indexOf("location name");
        if (colSt === -1) colSt = iHeaders.indexOf("evcs location name");
        if (colSt === -1) colSt = 1;

        var colDue = iHeaders.indexOf("pm due date");
        if (colDue === -1) colDue = iHeaders.indexOf("due date");
        if (colDue === -1) colDue = 7; // Column H

        var targetClean = locationName.toString().trim().toLowerCase().replace(/[^a-z0-9]/g, "");

        for (var i = info.headerRowIdx + 1; i < iData.length; i++) {
          var stNameRow = iData[i][colSt] ? iData[i][colSt].toString().trim() : "";
          if (!stNameRow) continue;

          var rowClean = stNameRow.toLowerCase().replace(/[^a-z0-9]/g, "");
          if (rowClean === targetClean || rowClean.indexOf(targetClean) !== -1 || targetClean.indexOf(rowClean) !== -1) {
            invSheet.getRange(i + 1, colDue + 1).setValue(formattedDueDate);
          }
        }
      }
    }
  } catch (err) {
    Logger.log("Error updating PM Due Date: " + err.toString());
  }
}

function updateStationPMDueDateV3(locationName, pmDateStr) {
  return updateStationPMDueDateV2(locationName, pmDateStr);
}
/**
 * Helper to parse dynamic dates (ISO, DD/MM/YYYY, YYYY-MM-DD, Date objects).
 */
function parseDateAnyV2(dateVal) {
  if (!dateVal) return null;
  if (dateVal instanceof Date) return dateVal;
  
  var str = dateVal.toString().trim();
  if (!str) return null;

  if (str.indexOf('T') !== -1 || str.indexOf('Z') !== -1) {
    var dIso = new Date(str);
    if (!isNaN(dIso.getTime())) return dIso;
  }

  var parts = str.split(/[\/\-\s:]/);
  if (parts.length >= 3) {
    if (parts[0].length === 4) {
      // yyyy-mm-dd
      var year = parseInt(parts[0], 10);
      var month = parseInt(parts[1], 10) - 1;
      var day = parseInt(parts[2], 10);
      var d = new Date(year, month, day);
      if (!isNaN(d.getTime())) return d;
    } else {
      // dd-mm-yyyy or dd/mm/yyyy
      var day = parseInt(parts[0], 10);
      var month = parseInt(parts[1], 10) - 1;
      var year = parseInt(parts[2], 10);
      var d = new Date(year, month, day);
      if (!isNaN(d.getTime())) return d;
    }
  }

  var dFallback = new Date(str);
  if (!isNaN(dFallback.getTime())) return dFallback;
  return null;
}

/**
 * Fetches submitted TA/DA claims for a specific engineer filtered by month (YYYY-MM).
 */
function getEngineerTadaHistoryV2(engineerName, monthStr, token) {
  try {
    var hodScope = getHodEngineerScopeV3(token);
    if (!hodScope.ok) return { success: false, message: hodScope.message, sessionExpired: hodScope.sessionExpired, claims: [] };
    var ss = getSpreadsheetV3();
    if (!ss) ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_TADA) : null;
    if (!sheet) sheet = ss ? ss.getSheetByName("TADA_Log") : null;
    if (!sheet) return { success: true, claims: [] };

    ensureSubmissionIdsBackfilledV3(sheet, SUBMISSION_SHEETS_V3.tada);
    var data = sheet.getDataRange().getValues();
    if (data.length <= 1) return { success: true, claims: [] };

    var headers = data[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
    
    var colEng = headers.indexOf("engineer");
    var colDate = headers.indexOf("claim date");
    var colTravel = headers.indexOf("travel total (\u20b9)");
    var colFood = headers.indexOf("food total (\u20b9)");
    var colStay = headers.indexOf("accommodation total (\u20b9)");
    var colCons = headers.indexOf("consumables total (\u20b9)");
    var colGrand = headers.indexOf("grand total (\u20b9)");
    var colRecordId = headers.indexOf("recordid");

    var targetEngClean = engineerName ? engineerName.toString().trim().toLowerCase().replace(/[^a-z]/g, '') : "";
    var targetMonth = monthStr ? monthStr.toString().trim() : "";

    var claims = [];

    for (var i = data.length - 1; i >= 1; i--) {
      var row = data[i];
      if (!row || row.length === 0 || (!row[0] && !row[1])) continue;

      var rawTimestamp = row[0];
      var payload = {};

      for (var c = 0; c < row.length; c++) {
        var cellVal = row[c];
        if (typeof cellVal === 'string' && cellVal.trim().indexOf('{') === 0) {
          try {
            payload = JSON.parse(cellVal);
            break;
          } catch(e) {}
        }
      }

      var engInClaim = payload.engineer || payload.engineerName || (colEng !== -1 ? row[colEng] : "") || (row.length > 1 && typeof row[1] === 'string' && row[1].indexOf('{') === -1 ? row[1] : "");
      engInClaim = engInClaim.toString().trim();
      var engInClaimClean = engInClaim ? engInClaim.toLowerCase().replace(/[^a-z]/g, '') : "";

      if (targetEngClean && targetEngClean !== 'all' && engInClaimClean) {
        if (engInClaimClean.indexOf(targetEngClean) === -1 && targetEngClean.indexOf(engInClaimClean) === -1) {
          continue;
        }
      }

      if (hodScope.ok && hodScope.scoped && !engineerInHodScopeV3(hodScope, engInClaim)) continue;

      var rawDate = payload.claimDate || payload.timestamp || (colDate !== -1 ? row[colDate] : "") || rawTimestamp;
      var dateObj = parseDateAnyV2(rawDate);
      if (!dateObj || isNaN(dateObj.getTime())) continue;

      var year = dateObj.getFullYear();
      var month = ("0" + (dateObj.getMonth() + 1)).slice(-2);
      var claimMonthStr = year + "-" + month;

      if (targetMonth && claimMonthStr !== targetMonth) {
        continue;
      }

      var travelAmt = Number(payload.travelTotal) || (colTravel !== -1 ? Number(row[colTravel]) || 0 : 0);
      var foodAmt = Number(payload.foodTotal) || (colFood !== -1 ? Number(row[colFood]) || 0 : 0);
      var stayAmt = Number(payload.stayTotal) || (colStay !== -1 ? Number(row[colStay]) || 0 : 0);
      var consAmt = Number(payload.consTotal) || (colCons !== -1 ? Number(row[colCons]) || 0 : 0);
      var dayTotal = Number(payload.grandTotal) || (colGrand !== -1 ? Number(row[colGrand]) || 0 : (travelAmt + foodAmt + stayAmt + consAmt));

      var detailsSummary = [];
      if (payload.travelLogs && payload.travelLogs.length) {
        payload.travelLogs.forEach(function(t) { detailsSummary.push((t.method || 'Travel') + ': ' + (t.location || t.purpose || 'Trip')); });
      }
      if (payload.foodLogs && payload.foodLogs.length) {
        payload.foodLogs.forEach(function(f) { detailsSummary.push("Food: " + (f.meal || f.location || 'Meal')); });
      }
      if (payload.stayLogs && payload.stayLogs.length) {
        payload.stayLogs.forEach(function(s) { detailsSummary.push("Stay: " + (s.hotelName || s.location || 'Hotel')); });
      }
      if (payload.consumableLogs && payload.consumableLogs.length) {
        payload.consumableLogs.forEach(function(c) { detailsSummary.push("Consumable: " + (c.description || "Item")); });
      }

      if (detailsSummary.length === 0) {
        if (row[9] && row[9] !== '-') detailsSummary.push(row[9]);
        if (row[10] && row[10] !== '-') detailsSummary.push(row[10]);
        if (row[11] && row[11] !== '-') detailsSummary.push(row[11]);
        if (row[12] && row[12] !== '-') detailsSummary.push(row[12]);
      }

      claims.push({
        rowIndex: i + 1,
        recordId: colRecordId !== -1 && row[colRecordId] ? row[colRecordId].toString().trim() : '',
        claimId: 'CLM-' + (1000 + i),
        engineer: engInClaim || 'Field Engineer',
        dateStr: ("0" + dateObj.getDate()).slice(-2) + "/" + month + "/" + year,
        claimDate: year + "-" + month + "-" + ("0" + dateObj.getDate()).slice(-2),
        dayNum: dateObj.getDate(),
        travelAmt: travelAmt,
        foodAmt: foodAmt,
        stayAmt: stayAmt,
        consAmt: consAmt,
        dayTotal: dayTotal,
        summary: detailsSummary.join(', ') || 'Claim Record',
        payload: payload
      });
    }

    return { success: true, claims: claims };
  } catch (e) {
    return { success: false, message: e.toString(), claims: [] };
  }
}

/**
 * Fast Ultra-Responsive Fortnightly TA/DA PDF Report Generator (0.5 sec)
 */

function generateFortnightlyPDF(engineerName, year, month, cyclePeriod, reportType, token) {
  var access = requireSession(token, null);
  if (!access.ok) return { success: false, error: access.message, sessionExpired: access.sessionExpired };
  var callerRole = (access.session.role || "").toString().trim().toLowerCase();
  if (callerRole !== 'admin' && callerRole !== 'hod') {
    engineerName = access.session.fullName || access.session.username;
  }
  try {
    var ss = getSpreadsheetV3();
    if (!ss) ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_TADA) : null;
    if (!sheet) sheet = ss ? ss.getSheetByName("TADA_Log") : null;
    if (!sheet) {
      return { success: false, error: "TADA_Log sheet not found." };
    }

    var data = sheet.getDataRange().getValues();
    if (data.length <= 1) {
      return { success: false, error: "No claim records exist in the database." };
    }

    var yNum = parseInt(year, 10);
    var mNum = parseInt(month, 10);
    var targetEngClean = engineerName ? engineerName.toString().trim().toLowerCase().replace(/[^a-z]/g, '') : "";

    var matchingClaims = [];
    var itemizedEntries = [];

    for (var i = 1; i < data.length; i++) {
      var row = data[i];
      if (!row || row.length === 0 || (!row[0] && !row[1])) continue;

      var rawTimestamp = row[0];
      var payload = {};

      for (var c = 0; c < row.length; c++) {
        var cellVal = row[c];
        if (typeof cellVal === 'string' && cellVal.trim().indexOf('{') === 0) {
          try {
            payload = JSON.parse(cellVal);
            break;
          } catch(e) {}
        }
      }

      var engInClaim = (payload.engineer || payload.engineerName || (row.length > 1 ? row[1] : "") || "").toString().trim();
      var engInClaimClean = engInClaim ? engInClaim.toLowerCase().replace(/[^a-z]/g, '') : "";

      if (targetEngClean && targetEngClean !== 'all' && engInClaimClean) {
        if (engInClaimClean.indexOf(targetEngClean) === -1 && targetEngClean.indexOf(engInClaimClean) === -1) {
          continue;
        }
      }

      var dateObj = parseDateAnyV2(payload.claimDate || payload.timestamp || rawTimestamp);
      if (!dateObj || isNaN(dateObj.getTime())) continue;

      if (dateObj.getFullYear() !== yNum) continue;
      if ((dateObj.getMonth() + 1) !== mNum) continue;

      var day = dateObj.getDate();
      if (cyclePeriod === "1-15") {
        if (day < 1 || day > 15) continue;
      } else {
        if (day < 16) continue;
      }

      var formattedDate = ("0" + dateObj.getDate()).slice(-2) + "/" + ("0" + (dateObj.getMonth() + 1)).slice(-2) + "/" + dateObj.getFullYear();

      var travelAmt = Number(payload.travelTotal) || 0;
      var foodAmt = Number(payload.foodTotal) || 0;
      var stayAmt = Number(payload.stayTotal) || 0;
      var consAmt = Number(payload.consTotal) || 0;
      var dayTotal = Number(payload.grandTotal) || Number(payload.amount) || (travelAmt + foodAmt + stayAmt + consAmt);

      matchingClaims.push({
        claimId: 'CLM-' + (1000 + i),
        dateStr: formattedDate,
        engineer: engInClaim,
        travelAmt: travelAmt,
        foodAmt: foodAmt,
        stayAmt: stayAmt,
        consAmt: consAmt,
        dayTotal: dayTotal
      });

      // Extract individual line items
      if (payload.travelLogs && payload.travelLogs.length) {
        payload.travelLogs.forEach(function(t) {
          itemizedEntries.push({
            date: t.date || formattedDate,
            category: "Travel",
            mode: t.method || "Travel",
            remark: (t.location ? t.location + " - " : "") + (t.purpose || t.details || t.description || "Travel Trip") + (t.km ? " (" + t.km + " km)" : ""),
            attachment: t.attachmentUrl || t.attachment || "",
            amount: Number(t.amount) || 0
          });
        });
      }

      if (payload.foodLogs && payload.foodLogs.length) {
        payload.foodLogs.forEach(function(f) {
          itemizedEntries.push({
            date: f.date || formattedDate,
            category: "Food",
            mode: f.meal || "Meal",
            remark: (f.location ? f.location + " - " : "") + (f.description || f.remark || "Food Expense"),
            attachment: f.attachmentUrl || f.attachment || "",
            amount: Number(f.amount) || 0
          });
        });
      }

      if (payload.stayLogs && payload.stayLogs.length) {
        payload.stayLogs.forEach(function(s) {
          itemizedEntries.push({
            date: s.date || formattedDate,
            category: "Accommodation",
            mode: s.hotelName || "Hotel Stay",
            remark: (s.location ? s.location + " - " : "") + (s.description || "Accommodation Expense"),
            attachment: s.attachmentUrl || s.attachment || "",
            amount: Number(s.amount) || 0
          });
        });
      }

      if (payload.consumableLogs && payload.consumableLogs.length) {
        payload.consumableLogs.forEach(function(c) {
          itemizedEntries.push({
            date: c.date || formattedDate,
            category: "Consumable",
            mode: "Item",
            remark: c.description || "Consumable Item",
            attachment: c.attachmentUrl || c.attachment || "",
            amount: Number(c.amount) || 0
          });
        });
      }
    }

    if (matchingClaims.length === 0) {
      var cycleName = (cyclePeriod === "1-15" ? "Cycle 1 (1st-15th)" : "Cycle 2 (16th-30th/31st)");
      return {
        success: false,
        error: "No daily claim records found for " + (engineerName || "Engineer") + " in " + cycleName + " of " + month + "/" + year
      };
    }

    var isItemized = (reportType === "itemized");
    var periodLabel = cyclePeriod === "1-15" ? "01 to 15" : "16 to End";

    var lastDayOfMonth = new Date(yNum, mNum, 0).getDate();
    var startDateStr = (cyclePeriod === "1-15" ? "01" : "16") + " " + getMonthAbbrevV2(mNum) + " " + yNum;
    var endDateStr = (cyclePeriod === "1-15" ? "15" : ("0" + lastDayOfMonth).slice(-2)) + " " + getMonthAbbrevV2(mNum) + " " + yNum;

    var docName = "GOEC_" + (isItemized ? "Itemized" : "Daily_Summary") + "_TADA_" + (engineerName || "Engineer").replace(/\s+/g, "_") + "_" + year + "_" + month + "_" + (cyclePeriod === "1-15" ? "P1" : "P2");

    var sumTravel = 0;
    var sumFood = 0;
    var sumStay = 0;
    var sumCons = 0;
    var sumGrand = 0;

    var summaryRowsHtml = "";
    matchingClaims.forEach(function(item) {
      sumTravel += item.travelAmt;
      sumFood += item.foodAmt;
      sumStay += item.stayAmt;
      sumCons += item.consAmt;
      sumGrand += item.dayTotal;

      summaryRowsHtml += '<tr>' +
        '<td style="border:1px solid #cbd5e1; padding:6px; font-weight:bold; color:#0f172a;">' + item.claimId + '</td>' +
        '<td style="border:1px solid #cbd5e1; padding:6px;">' + item.dateStr + '</td>' +
        '<td style="border:1px solid #cbd5e1; padding:6px; text-align:right; color:#059669; font-weight:bold;">\u20b9' + item.travelAmt.toFixed(2) + '</td>' +
        '<td style="border:1px solid #cbd5e1; padding:6px; text-align:right; color:#d97706; font-weight:bold;">\u20b9' + item.foodAmt.toFixed(2) + '</td>' +
        '<td style="border:1px solid #cbd5e1; padding:6px; text-align:right; color:#2563eb; font-weight:bold;">\u20b9' + item.stayAmt.toFixed(2) + '</td>' +
        '<td style="border:1px solid #cbd5e1; padding:6px; text-align:right; color:#7c3aed; font-weight:bold;">\u20b9' + item.consAmt.toFixed(2) + '</td>' +
        '<td style="border:1px solid #cbd5e1; padding:6px; text-align:right; font-weight:bold; color:#0f172a;">\u20b9' + item.dayTotal.toFixed(2) + '</td>' +
      '</tr>';
    });

    var itemizedRowsHtml = "";
    itemizedEntries.forEach(function(entry) {
      var catClass = "badge-travel";
      if (entry.category === "Food") catClass = "badge-food";
      else if (entry.category === "Accommodation") catClass = "badge-stay";
      else if (entry.category === "Consumable") catClass = "badge-cons";

      var attachHtml = '<span style="color:#94a3b8; font-size:10px;">-</span>';
      if (entry.attachment && entry.attachment.toString().trim().length > 0) {
        var rawAttach = entry.attachment.toString();
        var urls = rawAttach.split(',');
        var links = [];
        urls.forEach(function(u, idx) {
          var cleanUrl = u.trim();
          if (cleanUrl.indexOf('http') === 0) {
            links.push('<a href="' + cleanUrl + '" target="_blank" style="color:#0284c7; font-weight:bold; text-decoration:underline; font-size:10px;">\ud83d\udcce View Proof' + (urls.length > 1 ? ' (' + (idx+1) + ')' : '') + '</a>');
          }
        });
        if (links.length > 0) attachHtml = links.join(' ');
      }

      itemizedRowsHtml += '<tr>' +
        '<td style="border:1px solid #cbd5e1; padding:6px;">' + entry.date + '</td>' +
        '<td style="border:1px solid #cbd5e1; padding:6px;"><span class="' + catClass + '">' + entry.category + '</span></td>' +
        '<td style="border:1px solid #cbd5e1; padding:6px; font-weight:600;">' + entry.mode + '</td>' +
        '<td style="border:1px solid #cbd5e1; padding:6px; color:#334155;">' + entry.remark + '</td>' +
        '<td style="border:1px solid #cbd5e1; padding:6px; text-align:center;">' + attachHtml + '</td>' +
        '<td style="border:1px solid #cbd5e1; padding:6px; text-align:right; font-weight:bold; color:#0f172a;">\u20b9' + entry.amount.toFixed(2) + '</td>' +
      '</tr>';
    });

    // Top Consolidated Summary Cards Box (Present on BOTH Reports)
    var consolidatedCardsBoxHtml = '<div style="border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px 14px; margin-bottom: 20px; background: #ffffff;">' +
      '<div style="font-size: 11px; font-weight: bold; color: #475569; margin-bottom: 8px;">' +
        'Duration: <span style="color:#0f172a;">' + startDateStr + ' - ' + endDateStr + '</span> &nbsp;|&nbsp; ' +
        'Engineer Name: <span style="color:#0f172a;">' + (engineerName || "Field Engineer") + '</span>' +
      '</div>' +
      '<table style="width: 100%; border: 1px solid #cbd5e1; border-collapse: collapse; margin-top: 4px;">' +
        '<thead>' +
          '<tr style="background: #f8fafc;">' +
            '<th style="padding: 8px; border: 1px solid #cbd5e1; text-align: center; width: 20%; color: #475569; font-size: 9px; font-weight: bold;">TOTAL TRAVEL</th>' +
            '<th style="padding: 8px; border: 1px solid #cbd5e1; text-align: center; width: 20%; color: #475569; font-size: 9px; font-weight: bold;">TOTAL FOOD</th>' +
            '<th style="padding: 8px; border: 1px solid #cbd5e1; text-align: center; width: 20%; color: #475569; font-size: 9px; font-weight: bold;">TOTAL STAY</th>' +
            '<th style="padding: 8px; border: 1px solid #cbd5e1; text-align: center; width: 20%; color: #475569; font-size: 9px; font-weight: bold;">TOTAL CONSUMABLES</th>' +
            '<th style="padding: 8px; border: 1px solid #0f172a; background: #0f172a; text-align: center; width: 20%; color: #ffffff; font-size: 9px; font-weight: bold;">TOTAL REIMBURSEMENT</th>' +
          '</tr>' +
        '</thead>' +
        '<tbody>' +
          '<tr>' +
            '<td style="padding: 8px; border: 1px solid #cbd5e1; text-align: center; font-size: 13px; font-weight: bold; color: #059669;">\u20b9' + sumTravel.toFixed(2) + '</td>' +
            '<td style="padding: 8px; border: 1px solid #cbd5e1; text-align: center; font-size: 13px; font-weight: bold; color: #d97706;">\u20b9' + sumFood.toFixed(2) + '</td>' +
            '<td style="padding: 8px; border: 1px solid #cbd5e1; text-align: center; font-size: 13px; font-weight: bold; color: #2563eb;">\u20b9' + sumStay.toFixed(2) + '</td>' +
            '<td style="padding: 8px; border: 1px solid #cbd5e1; text-align: center; font-size: 13px; font-weight: bold; color: #7c3aed;">\u20b9' + sumCons.toFixed(2) + '</td>' +
            '<td style="padding: 8px; border: 1px solid #0f172a; background: #0f172a; text-align: center; font-size: 14px; font-weight: bold; color: #38bdf8;">\u20b9' + sumGrand.toFixed(2) + '</td>' +
          '</tr>' +
        '</tbody>' +
      '</table>' +
    '</div>';

    var mainTitle = isItemized ? "GOEC SERVICE ENGINEER TA/DA ITEMIZED EXPENSE REPORT" : "GOEC SERVICE ENGINEER TA/DA EXPENSE REPORT";
    var mainSub = isItemized ? "ITEMIZED CLAIM DETAILS & PROOF BREAKDOWN REPORT" : "CONSOLIDATED EXPENSE REIMBURSEMENT REPORT";

    var mainTableSection = "";
    if (isItemized) {
      mainTableSection = '<div class="section-title">ITEMIZED CLAIM DETAILS BREAKDOWN (Total Entries: ' + itemizedEntries.length + ')</div>' +
        '<table>' +
          '<thead><tr>' +
            '<th style="width: 12%;">Date</th>' +
            '<th style="width: 12%;">Category</th>' +
            '<th style="width: 15%;">Type / Mode</th>' +
            '<th style="width: 37%;">Description / Remark</th>' +
            '<th style="width: 14%; text-align:center;">Attachment</th>' +
            '<th class="num" style="width: 10%;">Amount (\u20b9)</th>' +
          '</tr></thead>' +
          '<tbody>' + itemizedRowsHtml + '</tbody>' +
        '</table>';
    } else {
      mainTableSection = '<div class="section-title">DAILY CLAIM SUMMARY OVERVIEW</div>' +
        '<table>' +
          '<thead><tr>' +
            '<th>Claim ID</th>' +
            '<th>Date</th>' +
            '<th class="num">Travel (\u20b9)</th>' +
            '<th class="num">Food (\u20b9)</th>' +
            '<th class="num">Stay (\u20b9)</th>' +
            '<th class="num">Consumables (\u20b9)</th>' +
            '<th class="num">Day Total (\u20b9)</th>' +
          '</tr></thead>' +
          '<tbody>' + summaryRowsHtml + '</tbody>' +
        '</table>' +
        '<div class="summary-bar">' +
          'Total Fortnightly Reimbursement Amount: \u20b9' + sumGrand.toFixed(2) +
        '</div>';
    }

    var htmlContent = '<!DOCTYPE html><html><head><meta charset="utf-8"><style>' +
      'body { font-family: Arial, Helvetica, sans-serif; font-size: 11px; color: #1e293b; padding: 20px; line-height: 1.4; }' +
      '.title { font-size: 16px; font-weight: bold; text-align: center; color: #0f172a; margin-bottom: 2px; text-transform: uppercase; letter-spacing: 0.5px; }' +
      '.subtitle { text-align: center; font-size: 10px; font-weight: bold; color: #64748b; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 1px; }' +
      '.section-title { font-size: 12px; font-weight: bold; color: #0f172a; margin-top: 14px; margin-bottom: 8px; border-bottom: 1.5px solid #0f172a; padding-bottom: 4px; }' +
      'table { width: 100%; border-collapse: collapse; margin-top: 6px; font-size: 10px; }' +
      'th { background: #1e293b; color: #ffffff; padding: 7px 6px; border: 1px solid #1e293b; text-align: left; font-size: 10px; }' +
      'th.num, td.num { text-align: right; }' +
      'td { border: 1px solid #cbd5e1; padding: 6px; color: #1e293b; vertical-align: top; }' +
      'tr:nth-child(even) { background-color: #f8fafc; }' +
      '.summary-bar { font-size: 12px; font-weight: bold; text-align: right; margin-top: 12px; padding: 8px 12px; background: #e2e8f0; border-radius: 4px; color: #0f172a; }' +
      '.badge-travel { color: #059669; font-weight: bold; }' +
      '.badge-food { color: #d97706; font-weight: bold; }' +
      '.badge-stay { color: #2563eb; font-weight: bold; }' +
      '.badge-cons { color: #7c3aed; font-weight: bold; }' +
      '</style></head><body>' +
      '<div class="title">' + mainTitle + '</div>' +
      '<div class="subtitle">' + mainSub + '</div>' +
      consolidatedCardsBoxHtml +
      mainTableSection +
      '</body></html>';

    var pdfBlob = Utilities.newBlob(htmlContent, "text/html", docName + ".html").getAs("application/pdf");
    pdfBlob.setName(docName + ".pdf");

    var base64Pdf = Utilities.base64Encode(pdfBlob.getBytes());

    return {
      success: true,
      pdfData: base64Pdf,
      filename: docName + ".pdf"
    };

  } catch (err) {
    return { success: false, error: err.toString() };
  }
}

function getMonthAbbrevV2(mNum) {
  var months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return months[mNum - 1] || "Month";
}



/**
 * Retrieves daily work history logs for engineer
 */
function getEngineerDailyWorkHistoryV2(engineerName, yearMonth) {
  try {
    var ss = getSpreadsheetV3();
    if (!ss) return { success: true, logs: [] };

    var sheet = ss.getSheetByName(CONFIG_V2.SHEET_DAILY_WORK || 'Daily_Work_Report');
    if (!sheet) sheet = ss.getSheetByName('Daily_Work_Report');
    if (!sheet) sheet = ss.getSheetByName('Daily Work Report');
    if (!sheet) {
      var sheets = ss.getSheets();
      for (var s = 0; s < sheets.length; s++) {
        var sName = sheets[s].getName().toLowerCase();
        if (sName.indexOf('daily') !== -1 || sName.indexOf('work') !== -1) {
          sheet = sheets[s];
          break;
        }
      }
    }

    if (!sheet || sheet.getLastRow() < 2) {
      return { success: true, logs: [] };
    }

    var data = sheet.getDataRange().getValues();
    var allLogs = [];
    var filteredLogs = [];
    var engClean = (engineerName || "").toString().trim().toLowerCase();
    var ymTarget = (yearMonth || "").toString().trim();

    for (var i = 1; i < data.length; i++) {
      var row = data[i];
      var rEng = row[1] ? row[1].toString().trim() : "";
      var rRole = row[2] ? row[2].toString().trim() : "";
      var rType = row[3] ? row[3].toString().trim() : "CM";
      
      if (!row[0] && !rEng && !row[5] && !row[7]) continue;

      var rawDate = row[4] ? row[4] : row[0];
      var formattedDateStr = "";

      if (rawDate) {
        var dObj = (rawDate instanceof Date || typeof rawDate.getTime === 'function') ? new Date(rawDate) : null;
        if (dObj && !isNaN(dObj.getTime())) {
          try {
            formattedDateStr = Utilities.formatDate(dObj, Session.getScriptTimeZone() || "GMT", "yyyy-MM-dd");
          } catch(e) {
            formattedDateStr = dObj.getFullYear() + "-" + ("0" + (dObj.getMonth() + 1)).slice(-2) + "-" + ("0" + dObj.getDate()).slice(-2);
          }
        } else {
          var str = rawDate.toString().trim();
          if (str.match(/^\d{4}-\d{2}-\d{2}/)) {
            formattedDateStr = str.substring(0, 10);
          } else if (str.indexOf('/') !== -1) {
            var p = str.split(' ')[0].split('/');
            if (p.length === 3 && p[2].length === 4) {
              formattedDateStr = p[2] + "-" + ("0" + p[1]).slice(-2) + "-" + ("0" + p[0]).slice(-2);
            }
          }
          if (!formattedDateStr) formattedDateStr = str.substring(0, 10);
        }
      }

      var item = {
        rowIndex: i + 1,
        timestamp: row[0] ? row[0].toString() : "",
        engineer: rEng,
        role: rRole,
        reportType: rType,
        dateStr: formattedDateStr || (row[4] ? row[4].toString().substring(0, 10) : ""),
        locationName: row[5] ? row[5].toString() : "",
        cpId: row[6] ? row[6].toString() : "",
        details: row[7] ? row[7].toString() : "",
        action: row[8] ? row[8].toString() : "",
        spares: row[9] ? row[9].toString() : "",
        workStatus: row[10] ? row[10].toString() : "",
        remarks: row[11] ? row[11].toString() : "",
        attachmentUrl: row[12] ? row[12].toString() : ""
      };

      allLogs.push(item);

      // Check month match
      var dMatch = true;
      if (ymTarget) {
        var dateValStr = (formattedDateStr || (rawDate ? rawDate.toString() : "")).trim();
        if (dateValStr.indexOf(ymTarget) === -1) {
          if (ymTarget.indexOf('-') !== -1) {
            var ymP = ymTarget.split('-');
            var yStr = ymP[0];
            var mStr = ("0" + parseInt(ymP[1], 10)).slice(-2);
            if (dateValStr.indexOf(yStr) === -1 || (dateValStr.indexOf("-" + mStr) === -1 && dateValStr.indexOf("/" + mStr) === -1 && dateValStr.indexOf("-" + parseInt(mStr, 10)) === -1)) {
              dMatch = false;
            }
          } else {
            dMatch = false;
          }
        }
      }

      // Check engineer match
      var eMatch = true;
      if (engClean && engClean !== 'all' && engClean !== 'all engineers overview' && engClean !== 'loading profile...' && engClean !== 'field engineer' && engClean !== 'system administrator' && engClean !== 'head of department' && engClean !== 'admin' && engClean !== 'hod') {
        var rEngLower = rEng.toLowerCase();
        var eFirstName = engClean.split(' ')[0];
        var rFirstName = rEngLower.split(' ')[0];
        if (rEngLower.indexOf(engClean) === -1 && engClean.indexOf(rEngLower) === -1 && (!eFirstName || !rFirstName || eFirstName !== rFirstName)) {
          eMatch = false;
        }
      }

      if (dMatch && eMatch) {
        filteredLogs.push(item);
      }
    }

    // Only fall back to the unfiltered set when the caller genuinely asked for
    // an "everyone" view (no engineer filter, no month filter) - an empty
    // result for a SPECIFIC engineer/month must stay empty, never leak every
    // other engineer's history just because this one had nothing that month.
    var engFilterActive = !!(engClean && engClean !== 'all' && engClean !== 'all engineers overview' && engClean !== 'loading profile...' && engClean !== 'field engineer' && engClean !== 'system administrator' && engClean !== 'head of department' && engClean !== 'admin' && engClean !== 'hod');
    var finalLogs = (!engFilterActive && !ymTarget) ? allLogs : filteredLogs;

    finalLogs.sort(function(a, b) {
      return (b.dateStr || "").localeCompare(a.dateStr || "");
    });

    return { success: true, logs: finalLogs };
  } catch (err) {
    return { success: false, error: err.toString(), logs: [] };
  }
}

/**
 * Calculates HOD Monthly Work & Standby/Comp-Off Matrix
 */
function getHODMonthlyWorkMatrixV2(engineerName, yearMonth, token) {
  try {
    var hodScope = getHodEngineerScopeV3(token);
    if (!hodScope.ok) return { success: false, message: hodScope.message, sessionExpired: hodScope.sessionExpired, matrix: [] };
    var ss = getSpreadsheetV3();
    var engTarget = (engineerName || "ALL").toString().trim();
    var engClean = engTarget.toLowerCase();

    if (!yearMonth || yearMonth.indexOf('-') === -1) {
      var now = new Date();
      yearMonth = now.getFullYear() + "-" + ("0" + (now.getMonth() + 1)).slice(-2);
    }

    var parts = yearMonth.split('-');
    var year = parseInt(parts[0], 10);
    var month = parseInt(parts[1], 10);
    var daysInMonth = new Date(year, month, 0).getDate();

    var activityMap = {};

    function collectFromSheet(sheetName, defaultDateIdx, defaultEngIdx, descFn) {
      var sh = ss ? ss.getSheetByName(sheetName) : null;
      if (!sh || sh.getLastRow() < 2) return;
      var d = sh.getDataRange().getValues();
      var headers = d[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });

      var dateIdx = defaultDateIdx;
      var engIdx = defaultEngIdx;
      var foundWorkDate = false;

      for (var h = 0; h < headers.length; h++) {
        var hName = headers[h];
        if (hName === 'engineer' || hName === 'engineer name') {
          engIdx = h;
        }
        if (hName === 'work date' || hName === 'pm date' || hName === 'commissioning date' || hName === 'report date' || hName === 'date') {
          dateIdx = h;
          foundWorkDate = true;
        }
        if (!foundWorkDate && hName === 'timestamp') {
          dateIdx = h;
        }
      }

      for (var r = 1; r < d.length; r++) {
        var rowEng = d[r][engIdx] ? d[r][engIdx].toString().trim() : "";
        if (hodScope.ok && hodScope.scoped && !engineerInHodScopeV3(hodScope, rowEng)) continue;
        if (engClean !== 'all' && engClean !== 'all engineers overview') {
          var rClean = rowEng.toLowerCase();
          if (rClean.indexOf(engClean) === -1 && engClean.indexOf(rClean) === -1) {
            var eFirstName = engClean.split(' ')[0];
            var rFirstName = rClean.split(' ')[0];
            if (!eFirstName || !rFirstName || eFirstName !== rFirstName) continue;
          }
        }

        var rawDate = d[r][dateIdx];
                var dStr = "";
        if (rawDate instanceof Date) {
          try {
            dStr = Utilities.formatDate(rawDate, Session.getScriptTimeZone() || "GMT", "yyyy-MM-dd");
          } catch(e) {
            dStr = rawDate.toISOString().substring(0, 10);
          }
        } else if (rawDate) {
          var str = rawDate.toString().trim();
          if (/^\d{4}-\d{2}-\d{2}/.test(str)) {
            dStr = str.substring(0, 10);
          } else {
            var parts = str.split(/[\/\-\s]/);
            if (parts.length >= 3) {
              var p1 = parseInt(parts[0], 10);
              var p2 = parseInt(parts[1], 10);
              var p3 = parseInt(parts[2], 10);
              if (p1 > 1000) {
                dStr = p1 + "-" + ("0" + p2).slice(-2) + "-" + ("0" + p3).slice(-2);
              } else if (p3 > 1000) {
                dStr = p3 + "-" + ("0" + p2).slice(-2) + "-" + ("0" + p1).slice(-2);
              }
            }
            if (!dStr) {
              try {
                var dObj = new Date(str);
                if (!isNaN(dObj.getTime())) {
                  dStr = Utilities.formatDate(dObj, Session.getScriptTimeZone() || "GMT", "yyyy-MM-dd");
                }
              } catch(e) {}
            }
          }
        }
        if (!dStr) dStr = rawDate ? rawDate.toString().trim().substring(0, 10) : "";

        if (dStr && dStr.length >= 10) {
          dStr = dStr.substring(0, 10);
          if (!activityMap[dStr]) activityMap[dStr] = [];
          activityMap[dStr].push(descFn(d[r]));
        }
      }
    }

    // 1. Commissioning
    collectFromSheet(CONFIG_V2.SHEET_COMMISSIONING, 3, 1, function(r) {
      var engName = r[1] ? r[1].toString().trim() : "Eng";
      var prefix = (engClean === 'all' || engClean === 'all engineers overview') ? ("\ud83d\udc64 " + engName + ": ") : "";
      return prefix + "Commissioning - " + (r[2] || "Site");
    });

    // 2. PM Civil & Electrical
    collectFromSheet(CONFIG_V2.SHEET_PM_CIVIL, 3, 1, function(r) {
      var engName = r[1] ? r[1].toString().trim() : "Eng";
      var prefix = (engClean === 'all' || engClean === 'all engineers overview') ? ("\ud83d\udc64 " + engName + ": ") : "";
      return prefix + "PM (Civil/Elec) - " + (r[2] || "Site");
    });

    // 3. PM Charger
    collectFromSheet(CONFIG_V2.SHEET_PM_CHARGER || 'PM_Charger', 3, 1, function(r) {
      var engName = r[1] ? r[1].toString().trim() : "Eng";
      var prefix = (engClean === 'all' || engClean === 'all engineers overview') ? ("\ud83d\udc64 " + engName + ": ") : "";
      return prefix + "PM Charger - " + (r[2] || "Site");
    });

    // 4. Daily Work Report
    collectFromSheet(CONFIG_V2.SHEET_DAILY_WORK || 'Daily_Work_Report', 4, 1, function(r) {
      var t = r[3] || "CM";
      var val6 = r[6] ? r[6].toString().trim() : "";
      var hrsSuffix = "";
      if (val6) {
        if (val6.toLowerCase().indexOf("hr") === -1 && val6.toLowerCase().indexOf("hour") === -1) {
          hrsSuffix = " (" + val6 + " hrs)";
        } else {
          hrsSuffix = " (" + val6 + ")";
        }
      }
      var engName = r[1] ? r[1].toString().trim() : "Eng";
      var prefix = (engClean === 'all' || engClean === 'all engineers overview') ? ("\ud83d\udc64 " + engName + ": ") : "";
      if (t === 'CM') {
        return prefix + "CM - " + (r[5] || 'Site') + hrsSuffix;
      } else {
        return prefix + "Others - " + (r[5] || 'Site') + hrsSuffix;
      }
    });

    // Load HOD overrides
    var overrideMap = {};
    var ovSheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_HOD_OVERRIDE || 'HOD_Override_Log') : null;
    if (ovSheet && ovSheet.getLastRow() >= 2) {
      var ovData = ovSheet.getDataRange().getValues();
      for (var o = 1; o < ovData.length; o++) {
        var oEng = ovData[o][0] ? ovData[o][0].toString().trim().toLowerCase() : "";
        var rawODate = ovData[o][1];
        var oDate = parseWorkDateToYYYYMMDD(rawODate);
        var oStat = ovData[o][2] ? ovData[o][2].toString().trim() : "";

        var isEngMatch = (engClean === 'all' || engClean === 'all engineers overview');
        if (!isEngMatch && oEng) {
          if (oEng === engClean || oEng.indexOf(engClean) !== -1 || engClean.indexOf(oEng) !== -1) {
            isEngMatch = true;
          } else {
            var eToken = engClean.split(' ')[0];
            var oToken = oEng.split(' ')[0];
            if (eToken && oToken && (eToken === oToken || eToken.indexOf(oToken) !== -1 || oToken.indexOf(eToken) !== -1)) {
              isEngMatch = true;
            }
          }
        }

        if (isEngMatch && oDate && oStat) {
          overrideMap[oDate] = oStat;
        }
      }
    }

    // Carryover calculation from prior months in the year
    var compOffCarriedOver = 0;
    if (engClean !== 'all' && engClean !== 'all engineers overview') {
      try {
        for (var pm = 1; pm < month; pm++) {
          var pYM = year + "-" + ("0" + pm).slice(-2);
          var pDays = new Date(year, pm, 0).getDate();
          for (var pd = 1; pd <= pDays; pd++) {
            var pDateObj = new Date(year, pm - 1, pd);
            var pFullDate = pYM + "-" + ("0" + pd).slice(-2);
            var pDayOfWeek = pDateObj.getDay();
            var pIsSun = (pDayOfWeek === 0);
            var pIs3rdSat = (pDayOfWeek === 6 && pd >= 15 && pd <= 21);
            var pOff = pIsSun || pIs3rdSat;

            var pAct = activityMap[pFullDate] || [];
            var pWorked = pAct.length > 0;

            var pStat = pWorked ? (pOff ? "Comp-Off Earned" : "Work Done") : (pOff ? "Official Off" : "Standby Day");
            if (overrideMap[pFullDate] && overrideMap[pFullDate] !== 'AUTO') {
              pStat = overrideMap[pFullDate];
            }

            if (pStat === 'Comp-Off Earned') compOffCarriedOver++;
            else if (pStat === 'Comp-Off Availed') compOffCarriedOver--;
          }
        }
        if (compOffCarriedOver < 0) compOffCarriedOver = 0;
      } catch(e){}
    }

    var matrix = [];
    var daysWorked = 0;
    var standbyDays = 0;
    var offDays = 0;
    var compOffEarned = 0;
    var compOffAvailed = 0;

    var dayNames = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

    for (var day = 1; day <= daysInMonth; day++) {
      var dayStr = ("0" + day).slice(-2);
      var dateObj = new Date(year, month - 1, day);
      var fullDateStr = year + "-" + ("0" + month).slice(-2) + "-" + dayStr;
      var dayOfWeek = dateObj.getDay();
      var dayName = dayNames[dayOfWeek];

      var isSunday = (dayOfWeek === 0);
      var isThirdSaturday = (dayOfWeek === 6 && day >= 15 && day <= 21);
      var isOfficialOff = isSunday || isThirdSaturday;
      var offReason = isSunday ? "Sunday Off" : (isThirdSaturday ? "3rd Saturday Off" : "");

      var activities = activityMap[fullDateStr] || [];
      var hasWork = activities.length > 0;
      var actSummary = activities.join(" | ");

      var systemStatus = "";
      if (hasWork) {
        if (isOfficialOff) {
          systemStatus = "Comp-Off Earned";
          compOffEarned++;
          daysWorked++;
        } else {
          systemStatus = "Work Done";
          daysWorked++;
        }
      } else {
        if (isOfficialOff) {
          systemStatus = "Official Off";
          offDays++;
        } else {
          systemStatus = "Standby Day";
          standbyDays++;
        }
      }

      var effectiveStatus = systemStatus;
      var isOverridden = false;

      if (overrideMap[fullDateStr] && overrideMap[fullDateStr] !== 'AUTO') {
        effectiveStatus = overrideMap[fullDateStr];
        isOverridden = true;

        if (effectiveStatus === 'Comp-Off Declined') {
          if (systemStatus === 'Comp-Off Earned') compOffEarned--;
        } else if (effectiveStatus === 'Comp-Off Availed') {
          compOffAvailed++;
        } else if (effectiveStatus === 'Comp-Off Earned' && systemStatus !== 'Comp-Off Earned') {
          compOffEarned++;
        }
      }

      matrix.push({
        dateStr: fullDateStr,
        dayNum: day,
        dayName: dayName,
        isOfficialOff: isOfficialOff,
        offReason: offReason,
        hasWork: hasWork,
        activitySummary: actSummary,
        systemStatus: systemStatus,
        effectiveStatus: effectiveStatus,
        isOverridden: isOverridden
      });
    }

    var compOffBalance = compOffCarriedOver + compOffEarned - compOffAvailed;

    return {
      success: true,
      summary: {
        daysWorked: daysWorked,
        standbyDays: standbyDays,
        offDays: offDays,
        compOffCarriedOver: compOffCarriedOver,
        compOffEarned: compOffEarned,
        compOffAvailed: compOffAvailed,
        compOffBalance: Math.max(0, compOffBalance)
      },
      matrix: matrix
    };
  } catch (err) {
    return { success: false, error: err.toString(), matrix: [] };
  }
}

function getHODMonthlyWorkMatrixV3(engineerName, yearMonth, token) {
  return getHODMonthlyWorkMatrixV2(engineerName, yearMonth, token);
}

function saveHODStatusOverrideV2(engineerName, dateStr, newStatus, token) {
  var access = requireSession(token, ['HOD', 'Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  // An HOD may only override the status of one of their OWN assigned
  // engineers, not anyone company-wide - the read-side matrix already
  // enforces this scope, the write side must match it.
  var hodScope = getHodEngineerScopeV3(token);
  if (hodScope.ok && hodScope.scoped && !engineerInHodScopeV3(hodScope, engineerName)) {
    return { success: false, message: "You can only override the status of engineers assigned to you." };
  }

  try {
    var ss = getSpreadsheetV3();
    if (!ss) return { success: false, message: "Spreadsheet error" };
    var ovSheet = ss.getSheetByName(CONFIG_V2.SHEET_HOD_OVERRIDE || 'HOD_Override_Log');
    if (!ovSheet) {
      ovSheet = ss.insertSheet(CONFIG_V2.SHEET_HOD_OVERRIDE || 'HOD_Override_Log');
    }
    if (ovSheet.getLastRow() === 0) {
      ovSheet.appendRow(["Engineer", "Date", "HOD Override Status", "Timestamp", "HOD User"]);
    }

    var engClean = (engineerName || "").toString().trim();
    var dStrClean = (dateStr || "").toString().trim();
    var statClean = (newStatus || "AUTO").toString().trim();

    var data = ovSheet.getDataRange().getValues();
    var existingRow = -1;

    for (var i = 1; i < data.length; i++) {
      var eVal = data[i][0] ? data[i][0].toString().trim().toLowerCase() : "";
      var dVal = data[i][1] ? data[i][1].toString().trim() : "";
      if (eVal === engClean.toLowerCase() && dVal === dStrClean) {
        existingRow = i + 1;
        break;
      }
    }

    var user = access.session.fullName || access.session.username || "HOD";

    if (existingRow > 0) {
      ovSheet.getRange(existingRow, 3).setValue(statClean);
      ovSheet.getRange(existingRow, 4).setValue(new Date());
      ovSheet.getRange(existingRow, 5).setValue(user);
    } else {
      ovSheet.appendRow([engClean, dStrClean, statClean, new Date(), user]);
    }

    return { success: true, message: "HOD status override saved successfully for " + dStrClean };
  } catch(e) {
    return { success: false, message: e.toString() };
  }
}

function saveHODStatusOverrideV3(engineerName, dateStr, newStatus, token) {
  return saveHODStatusOverrideV2(engineerName, dateStr, newStatus, token);
}
function getInventoryStationsV2(engineerName) {
  try {
    var ss = getSpreadsheetV3();
    var invSheet = ss ? (ss.getSheetByName(CONFIG_V3.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory") || ss.getSheetByName("Sheet1")) : null;
    if (!invSheet || invSheet.getLastRow() < 2) {
      return { success: true, stations: [] };
    }

    var data = invSheet.getDataRange().getValues();
    var stationMapFiltered = {};
    var stationMapAll = {};

    var engInput = engineerName ? engineerName.toString().trim().toLowerCase() : "";

    for (var i = 1; i < data.length; i++) {
      var stName = data[i][1] ? data[i][1].toString().trim() : "";
      var cpId = data[i][2] ? data[i][2].toString().trim() : "";
      var serialNo = data[i][3] ? data[i][3].toString().trim() : "";
      var oem = data[i][4] ? data[i][4].toString().trim() : "";
      var capacity = data[i][6] ? data[i][6].toString().trim() : "";
      var eng = data[i][7] ? data[i][7].toString().trim() : "";

      if (!stName) continue;

      var key = stName.toLowerCase();
      
      // Build ALL stations map
      if (!stationMapAll[key]) {
        stationMapAll[key] = { locationName: stName, stationName: stName, chargers: [] };
      }
      if (cpId || serialNo || oem || capacity) {
        stationMapAll[key].chargers.push({ cpId: cpId, serialNo: serialNo, oem: oem, capacity: capacity });
      }

      // Build FILTERED stations map
      var isMatched = true;
      if (engInput && !isAdminOrHodUserV3(engInput)) {
        var engVal = eng ? eng.toString().trim().toLowerCase() : "";
        if (!engVal || (engVal !== engInput && engInput.indexOf(engVal) === -1 && engVal.indexOf(engInput) === -1)) {
          isMatched = false;
        }
      }

      if (isMatched) {
        if (!stationMapFiltered[key]) {
          stationMapFiltered[key] = { locationName: stName, stationName: stName, chargers: [] };
        }
        if (cpId || serialNo || oem || capacity) {
          stationMapFiltered[key].chargers.push({ cpId: cpId, serialNo: serialNo, oem: oem, capacity: capacity });
        }
      }
    }

    var targetMap = isAdminOrHodUserV3(engInput) ? stationMapAll : stationMapFiltered;

    var stations = [];
    Object.keys(targetMap).forEach(function(k) {
      stations.push(targetMap[k]);
    });

    stations.sort(function(a, b) {
      return (a.locationName || "").localeCompare(b.locationName || "");
    });

    return { success: true, stations: stations };
  } catch (err) {
    return { success: false, error: err.toString(), stations: [] };
  }
}

function getInventoryStationsV3(engineerName, token) {
  var access = requireSession(token, null);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired, stations: [] };
  var role = (access.session.role || "").toString().trim().toLowerCase();
  var effectiveEngineer = (role === 'admin' || role === 'hod') ? engineerName : (access.session.fullName || access.session.username);
  return getInventoryStationsV2(effectiveEngineer);
}

function getInventoryStations(engineerName) {
  return getInventoryStationsV2(engineerName);
}

function getEngineerPendingPMsV2(engineerName) {
  try {
    var ss = getSpreadsheetV3();
    var invSheet = ss ? (ss.getSheetByName(CONFIG_V2.SHEET_INVENTORY) || ss.getSheetByName("Charger Inventory") || ss.getSheetByName("Sheet1")) : null;
    if (!invSheet) return { success: true, allStations: [] };

    var iData = invSheet.getDataRange().getValues();
    if (iData.length <= 1) return { success: true, allStations: [] };

    var iHeaders = iData[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });

    var colId = iHeaders.indexOf("cp id");
    if (colId === -1) colId = iHeaders.indexOf("station id");
    if (colId === -1) colId = iHeaders.indexOf("cpid");
    if (colId === -1) colId = 0;

    var colSt = iHeaders.indexOf("location name");
    if (colSt === -1) colSt = iHeaders.indexOf("evcs location name");
    if (colSt === -1) colSt = iHeaders.indexOf("station name");
    if (colSt === -1) colSt = iHeaders.indexOf("station");
    if (colSt === -1) colSt = 1;

    var colCap = iHeaders.indexOf("capacity");
    if (colCap === -1) colCap = iHeaders.indexOf("capacity (kw)");
    if (colCap === -1) colCap = iHeaders.indexOf("power (kw)");
    if (colCap === -1) colCap = 3;

    var colEng = iHeaders.indexOf("engineer");
    if (colEng === -1) colEng = iHeaders.indexOf("assigned engineer");
    if (colEng === -1) colEng = iHeaders.indexOf("service engineer");
    if (colEng === -1) colEng = 7;

    var colDue = iHeaders.indexOf("pm due date");
    if (colDue === -1) colDue = iHeaders.indexOf("due date");
    if (colDue === -1) colDue = 8;
    if (colDue >= iData[0].length) colDue = iData[0].length - 1;

    var now = new Date();
    var todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();

    // Map stations grouped by station name
    var stationMap = {};
    var eLower = engineerName ? engineerName.toString().trim().toLowerCase() : "";

    for (var j = 1; j < iData.length; j++) {
      var stName = iData[j][colSt] ? iData[j][colSt].toString().trim() : "";
      var assignedEng = iData[j][colEng] ? iData[j][colEng].toString().trim() : "";
      var cpId = (colId >= 0 && iData[j][colId]) ? iData[j][colId].toString().trim() : "";
      var cap = (colCap >= 0 && iData[j][colCap]) ? iData[j][colCap].toString().trim() : "";
      var dueDateStr = (colDue >= 0 && colDue < iData[j].length) ? iData[j][colDue] : "";

      if (!stName) continue;

      // Filter by engineer if engineerName is provided
      if (eLower) {
        var engFirstToken = eLower.split(" ")[0];
        var assignedLower = assignedEng.toLowerCase();
        if (assignedLower !== eLower && assignedLower.indexOf(engFirstToken) === -1) {
          continue;
        }
      }

      var sKey = stName.toLowerCase();
      if (!stationMap[sKey]) {
        var formattedDueDate = "Pending Schedule";
        var isDelayed = false;
        var delayedDays = 0;

        if (dueDateStr) {
          var due = new Date(dueDateStr);
          if (!isNaN(due.getTime())) {
            var dd = String(due.getDate()).padStart(2, '0');
            var mm = String(due.getMonth() + 1).padStart(2, '0');
            var yyyy = due.getFullYear();
            formattedDueDate = dd + '/' + mm + '/' + yyyy;

            var dueTime = new Date(due.getFullYear(), due.getMonth(), due.getDate()).getTime();
            if (dueTime < todayStart) {
              isDelayed = true;
              delayedDays = Math.ceil((todayStart - dueTime) / (1000 * 60 * 60 * 24));
            }
          } else {
            formattedDueDate = dueDateStr.toString().trim();
          }
        }

        stationMap[sKey] = {
          stationName: stName,
          cpIdSet: {},
          capacitySet: {},
          dueDateDisplay: formattedDueDate,
          isDelayed: isDelayed,
          delayedDays: delayedDays
        };
      }

      if (cpId) stationMap[sKey].cpIdSet[cpId] = true;
      if (cap) stationMap[sKey].capacitySet[cap] = true;
    }

    var allStations = Object.keys(stationMap).map(function(k) {
      var obj = stationMap[k];
      var cpIds = Object.keys(obj.cpIdSet);
      var capacities = Object.keys(obj.capacitySet);

      return {
        stationName: obj.stationName,
        cpIdDisplay: cpIds.length > 0 ? cpIds.join(", ") : "N/A",
        capacityDisplay: capacities.length > 0 ? capacities.join(", ") : "N/A",
        dueDateDisplay: obj.dueDateDisplay,
        isDelayed: obj.isDelayed,
        delayedDays: obj.delayedDays
      };
    });

    return {
      success: true,
      allStations: allStations
    };
  } catch (err) {
    return { success: false, error: err.toString(), allStations: [] };
  }
}

function getEngineerPendingPMsV3(engineerName, token) {
  var access = requireSession(token, null);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired, allStations: [] };
  var role = (access.session.role || "").toString().trim().toLowerCase();
  var effectiveEngineer = (role === 'admin' || role === 'hod') ? engineerName : (access.session.fullName || access.session.username);
  return getEngineerPendingPMsV2(effectiveEngineer);
}


function getDashboardKpiMetricsV3(engineerName, monthStr, token) {
  return getDashboardKpiMetricsV2(engineerName, monthStr, token);
}


function getSimInventoryDataV3(role, engineerName, token) {
  return getSimInventoryDataV2(role, engineerName, token);
}

function addSingleSimV3(simNumber, assignedEngineer, location, status, remarks, token) {
  return addSingleSimV2(simNumber, assignedEngineer, location, status, remarks, token);
}

function bulkImportSimsV3(simList, token) {
  return bulkImportSimsV2(simList, token);
}

function updateSimDeploymentV3(simNumber, location, remarks, newStatus, token) {
  return updateSimDeploymentV2(simNumber, location, remarks, newStatus, token);
}

function getAvailableSimsForEngineerV3(engineerName, token) {
  var access = requireSession(token, null);
  if (!access.ok) return ["Other"];
  var role = (access.session.role || "").toString().trim().toLowerCase();
  var effectiveEngineer = (role === 'admin' || role === 'hod') ? engineerName : (access.session.fullName || access.session.username);
  return getAvailableSimsForEngineerV2(effectiveEngineer);
}


function getOemsAndCapacitiesV3() {
  return getOemsAndCapacitiesV2();
}


function uploadMediaChunkV3(fileId, chunkBase64, isLastChunk, fileName, mimeType) {
  try {
    var cache = CacheService.getUserCache();
    var cacheKey = "chunk_" + (fileId || "temp");
    var existing = cache.get(cacheKey) || "";
    
    existing += chunkBase64;
    
    if (!isLastChunk) {
      cache.put(cacheKey, existing, 600);
      return { success: true, pending: true };
    }

    cache.remove(cacheKey);
    return uploadMediaToDriveV2(existing, fileName, mimeType);
  } catch (e) {
    return uploadMediaToDriveV2(chunkBase64, fileName, mimeType);
  }
}


/**
 * 1. Initialize Drive API Resumable Upload Session
 */
function initDriveResumableSessionV3(fileName, mimeType) {
  try {
    var folderName = "GOEC_TADA_Attachments";
    var folder;
    try {
      var folders = DriveApp.getFoldersByName(folderName);
      folder = folders.hasNext() ? folders.next() : DriveApp.createFolder(folderName);
    } catch(errFolder) {
      folder = DriveApp.getRootFolder();
    }

    try {
      folder.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    } catch(eShare) {}

    var token = ScriptApp.getOAuthToken();
    var finalMime = mimeType || 'video/mp4';
    var metadata = {
      name: fileName || ("video_" + Date.now() + ".mp4"),
      mimeType: finalMime,
      parents: [folder.getId()]
    };

    var response = UrlFetchApp.fetch("https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable", {
      method: "post",
      contentType: "application/json; charset=UTF-8",
      headers: {
        Authorization: "Bearer " + token,
        "X-Upload-Content-Type": finalMime
      },
      payload: JSON.stringify(metadata),
      muteHttpExceptions: true
    });

    var headers = response.getHeaders();
    var sessionUrl = headers["Location"] || headers["location"] || headers["LOCATION"];

    if (!sessionUrl) {
      return { success: false, message: "Failed to initialize Drive session: " + response.getContentText() };
    }

    return {
      success: true,
      sessionUrl: sessionUrl
    };
  } catch(e) {
    Logger.log("initDriveResumableSessionV3 Error: " + e.toString());
    return { success: false, message: e.toString() };
  }
}

/**
 * 2. Upload a single binary chunk directly into the Drive Resumable Session URL via UrlFetchApp (Zero CORS, Zero File Size Limit)
 */
function uploadChunkStreamV3(uploadId, chunkIndex, totalChunks, chunkBase64, fileName, mimeType, sessionUrl, startByte, totalSize) {
  try {
    if (!sessionUrl || typeof sessionUrl !== 'string' || sessionUrl.indexOf('upload_id=') === -1) {
      var initRes = initDriveResumableSessionV3(fileName, mimeType);
      if (!initRes.success) return initRes;
      sessionUrl = initRes.sessionUrl;
    }

    var chunkBytes = Utilities.base64Decode(chunkBase64);
    var start = (startByte !== undefined && startByte !== null) ? startByte : (chunkIndex * (2 * 1024 * 1024));
    var end = start + chunkBytes.length - 1;
    var total = (totalSize !== undefined && totalSize !== null) ? totalSize : (end + 1);

    var response = UrlFetchApp.fetch(sessionUrl, {
      method: "put",
      headers: {
        "Content-Range": "bytes " + start + "-" + end + "/" + total,
        "Content-Type": mimeType || "video/mp4"
      },
      payload: chunkBytes,
      muteHttpExceptions: true
    });

    var code = response.getResponseCode();

    if (code === 200 || code === 201) {
      var resJson = {};
      try {
        resJson = JSON.parse(response.getContentText());
      } catch(eJson) {}

      var fileId = resJson.id;
      var fileUrl = "https://drive.google.com/uc?export=view&id=" + fileId;

      if (fileId) {
        try {
          var driveFile = DriveApp.getFileById(fileId);
          driveFile.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
          fileUrl = driveFile.getUrl();
        } catch(ePerm) {}
      }

      return {
        success: true,
        complete: true,
        url: fileUrl,
        fileId: fileId,
        fileName: fileName,
        sessionUrl: sessionUrl
      };
    }

    if (code === 308) {
      return {
        success: true,
        complete: false,
        sessionUrl: sessionUrl,
        chunkIndex: chunkIndex,
        totalChunks: totalChunks,
        percent: Math.round(((end + 1) / total) * 100)
      };
    }

    return {
      success: false,
      message: "Drive Upload HTTP Error " + code + ": " + response.getContentText()
    };
  } catch (e) {
    Logger.log("uploadChunkStreamV3 Error: " + e.toString());
    return { success: false, message: e.toString() };
  }
}


/* Old getSubTemplateV3 / getHtmlOutputV4 removed &mdash; clean V4 versions below */


function getSubTemplateV4(filename, tabId, token) {
  var access = requireSession(token, null);
  if (!access.ok) {
    return "<div style='padding:40px; text-align:center; color:#f43f5e;'>Your session has expired. Please sign in again.</div>"
      + "<script>if (typeof handleV4Logout === 'function') { handleV4Logout(); } else { alert('Session expired. Please refresh and sign in again.'); }<\/script>";
  }
  if (!roleHasPageAccessV3(access.session.role, tabId)) {
    return "<div style='padding:60px 20px; text-align:center; color:#f43f5e;'><div style='font-size:32px; margin-bottom:12px;'>&#128274;</div><div style='font-weight:600; margin-bottom:6px;'>Access restricted</div><div style='font-size:12px; color:#94a3b8;'>Your role does not have access to this page.</div></div>";
  }
  if (!filename) return "<div style='color:red;'>No template name provided</div>";
  var raw = filename.toString();
  var cleanName = raw.replace(/\.html$/i, "");
  var baseName = cleanName.replace(/_V\d+$/i, "");
  
  var fileNamesToTry = [
    cleanName,
    raw,
    cleanName + '.html',
    baseName + '_V3',
    baseName + '_V3.html',
    baseName + '_V2',
    baseName + '_V2.html',
    baseName,
    baseName + '.html'
  ];

  var uniqueNames = [];
  fileNamesToTry.forEach(function(fn) {
    if (fn && uniqueNames.indexOf(fn) === -1) uniqueNames.push(fn);
  });

  var errors = [];

  // 1. Try createHtmlOutputFromFile first (Fastest & most reliable for HTML sub-templates)
  for (var i = 0; i < uniqueNames.length; i++) {
    try {
      var out = HtmlService.createHtmlOutputFromFile(uniqueNames[i]);
      if (out) {
        var content = out.getContent();
        if (content && content.trim().length > 0) return content;
      }
    } catch(e) {
      errors.push("HTML(" + uniqueNames[i] + "): " + e.message);
    }
  }

  // 2. Try createTemplateFromFile for templates requiring server-side evaluation (e.g. Index_V3)
  for (var i = 0; i < uniqueNames.length; i++) {
    try {
      var template = HtmlService.createTemplateFromFile(uniqueNames[i]);
      if (template) {
        try {
          if (baseName === 'Index') {
            template.sheet1DataJson = JSON.stringify(getSheet1DataV3(["engineers", "oems", "powers", "simInventory"]));
          } else if (baseName === 'PM_ElectricalCivil' || baseName === 'PM_Charger' || baseName === 'DailyWorkReport') {
            template.sheet1DataJson = JSON.stringify(getSheet1DataV3(["engineers"]));
          }
        } catch(err){}
        return template.evaluate().getContent();
      }
    } catch(e) {
      errors.push("TPL(" + uniqueNames[i] + "): " + e.message);
    }
  }

  return "<div style='padding:40px; color:#f43f5e; text-align:center;'><h3>Sub-template " + filename + " not found or failed to load</h3><p style='font-size:12px; color:#94a3b8; margin-top:8px;'>Debug details: " + errors.join(" | ") + "</p></div>";
}

function getSubTemplateV3(filename, tabId, token) { return getSubTemplateV4(filename, tabId, token); }

function changePasswordV3(oldPassword, newPassword, token) {
  var access = requireSession(token, null);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var ss = getSpreadsheetV3();
    var sheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_USERS || "Users") : null;
    if (!sheet) return { success: false, message: "Users database sheet not found" };

    var data = sheet.getDataRange().getValues();
    // Always derive the target account from the validated session, never from a
    // client-supplied username - otherwise any signed-in user could change anyone's password.
    var uLower = access.session.username ? access.session.username.toString().toLowerCase().trim() : "";
    var oldPass = oldPassword ? oldPassword.toString().trim() : "";
    var newPass = newPassword ? newPassword.toString().trim() : "";

    if (!newPass) return { success: false, message: "New password cannot be empty" };

    var oldHash = hashPasswordV2(oldPass);

    for (var i = 1; i < data.length; i++) {
      var rowUser = data[i][0] ? data[i][0].toString().toLowerCase().trim() : "";
      var rowPass = data[i][1] ? data[i][1].toString().trim() : "";
      var rowName = data[i][2] ? data[i][2].toString().toLowerCase().trim() : "";

      if (rowUser === uLower || (rowName && rowName === uLower)) {
        if (rowPass === oldPass || rowPass === oldHash) {
          // Update Password in Column B (Row i + 1, Column 2) - always store a hash now.
          sheet.getRange(i + 1, 2).setValue(hashPasswordV2(newPass));
          SpreadsheetApp.flush();
          return { success: true, message: "Password updated successfully in Users sheet!" };
        } else {
          return { success: false, message: "Incorrect current password" };
        }
      }
    }
    return { success: false, message: "User '" + access.session.username + "' not found in Users sheet" };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

function changePasswordV2(oldPassword, newPassword, token) {
  return changePasswordV3(oldPassword, newPassword, token);
}

// Lets Admin reset a forgotten password from inside the portal, without
// needing the old password (unlike self-service changePasswordV3) or direct
// Sheet access. Every reset is written to the Audit Log for accountability.
function adminResetUserPasswordV3(targetUsername, newPassword, token) {
  var access = requireSession(token, ['Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var newPass = (newPassword || "").toString().trim();
    if (!newPass) return { success: false, message: "New password cannot be empty." };
    if (newPass.length < 4) return { success: false, message: "New password must be at least 4 characters." };

    var sheet = getUsersSheetV3();
    if (!sheet) return { success: false, message: "Users database sheet not found." };

    var data = sheet.getDataRange().getValues();
    var key = (targetUsername || "").toString().trim().toLowerCase();

    for (var i = 1; i < data.length; i++) {
      var rowUser = data[i][0] ? data[i][0].toString().trim().toLowerCase() : "";
      if (rowUser === key) {
        sheet.getRange(i + 1, 2).setValue(hashPasswordV2(newPass));
        logAuditEntryV3(access.session, 'Edit', 'users', targetUsername, 'Password', '(reset by admin)', '(new password set)');
        return { success: true, message: "Password reset for '" + targetUsername + "'. Tell them their new password directly - it isn't shown anywhere else." };
      }
    }
    return { success: false, message: "User '" + targetUsername + "' not found." };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

var SHA256_HASH_SHAPE_V3 = /^[a-f0-9]{64}$/i;

function loginUserV3(username, password) {
  try {
    var ss = getSpreadsheetV3();
    var sheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_USERS || "Users") : null;
    if (!sheet) return { success: false, message: "Users database sheet not found" };
    var data = sheet.getDataRange().getValues();
    var uLower = username ? username.toString().toLowerCase().trim() : "";
    var inputPass = password ? password.toString().trim() : "";
    var inputHash = hashPasswordV2(inputPass);

    for (var i = 1; i < data.length; i++) {
      var rowUser = data[i][0] ? data[i][0].toString().toLowerCase().trim() : "";
      var rowPass = data[i][1] ? data[i][1].toString().trim() : "";
      var rowName = data[i][2] ? data[i][2].toString().toLowerCase().trim() : "";

      if (rowUser === uLower || (rowName && rowName === uLower)) {
        var isHashMatch = (rowPass === inputHash);
        var isLegacyPlaintextMatch = (!SHA256_HASH_SHAPE_V3.test(rowPass) && rowPass === inputPass);

        if (isHashMatch || isLegacyPlaintextMatch) {
          if (isLegacyPlaintextMatch) {
            // Self-healing migration: upgrade this row to a hash now that we've verified it.
            try { sheet.getRange(i + 1, 2).setValue(inputHash); } catch (e) {}
          }
          var canonicalUsername = data[i][0] ? data[i][0].toString().trim() : username;
          var fullName = data[i][2] ? data[i][2].toString().trim() : canonicalUsername;
          var role = data[i][3] ? data[i][3].toString().trim() : "Engineer";
          var token = createSessionV3(canonicalUsername, fullName, role);
          return { success: true, user: { username: canonicalUsername, fullName: fullName, role: role, token: token, allowedPages: getAllowedPagesForRoleV3(role) } };
        } else {
          return { success: false, message: "Invalid password" };
        }
      }
    }
    return { success: false, message: "User '" + username + "' not found in Users sheet" };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

function getUsersListV2() {
  try {
    var ss = getSpreadsheetV3();
    var sheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_USERS || "Users") : null;
    if (!sheet) return [];
    var data = sheet.getDataRange().getValues();
    var users = [];
    for (var i = 1; i < data.length; i++) {
      var u = data[i][0] ? data[i][0].toString().trim() : "";
      if (!u) continue;
      var name = data[i][2] ? data[i][2].toString().trim() : u;
      var r = data[i][3] ? data[i][3].toString().trim() : "Engineer";
      users.push({ username: u, fullName: name, role: r });
    }
    return users;
  } catch (e) {
    return [];
  }
}

// ============================================================================
// HOD -> ENGINEER SUPERVISORY SCOPING
// Admin assigns each HOD a set of engineers; that HOD's entire portal view
// (Stations, Dashboard, PM Report, Commissioning Audit, TA/DA, Work Monitor,
// Weekly Updates) is then filtered to only those engineers' stations/data.
// Stored as a 5th "AssignedEngineers" column (CSV) on the Users sheet,
// self-healed via ensureTrailingHeadersV3 the same way other trailing
// columns were added elsewhere. An HOD with nothing assigned sees nothing,
// prompting Admin to configure them, rather than silently seeing everyone.
// ============================================================================

var USERS_SHEET_BASE_HEADER_COUNT_V3 = 4; // Username, Password, FullName, Role

function getUsersSheetV3() {
  var ss = getSpreadsheetV3();
  var sheet = ss.getSheetByName(CONFIG_V2.SHEET_USERS || "Users");
  if (sheet) ensureTrailingHeadersV3(sheet, USERS_SHEET_BASE_HEADER_COUNT_V3, ["AssignedEngineers"]);
  return sheet;
}

function getHodAssignedEngineersV3(hodUsernameOrName) {
  try {
    var sheet = getUsersSheetV3();
    if (!sheet) return [];
    var data = sheet.getDataRange().getValues();
    var key = (hodUsernameOrName || "").toString().trim().toLowerCase();
    if (!key) return [];

    for (var i = 1; i < data.length; i++) {
      var rowUser = data[i][0] ? data[i][0].toString().trim().toLowerCase() : "";
      var rowName = data[i][2] ? data[i][2].toString().trim().toLowerCase() : "";
      if (rowUser === key || rowName === key) {
        var raw = data[i][4] ? data[i][4].toString().trim() : "";
        return raw ? raw.split(',').map(function(s) { return s.trim(); }).filter(Boolean) : [];
      }
    }
    return [];
  } catch (e) {
    return [];
  }
}

function getAllHodsWithAssignmentsV3(token) {
  var access = requireSession(token, ['Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var sheet = getUsersSheetV3();
    if (!sheet) return { success: true, hods: [] };
    var data = sheet.getDataRange().getValues();
    var hods = [];
    for (var i = 1; i < data.length; i++) {
      var role = data[i][3] ? data[i][3].toString().trim() : "";
      if (role.toLowerCase() !== 'hod') continue;
      var username = data[i][0] ? data[i][0].toString().trim() : "";
      if (!username) continue;
      var fullName = data[i][2] ? data[i][2].toString().trim() : username;
      var raw = data[i][4] ? data[i][4].toString().trim() : "";
      var assigned = raw ? raw.split(',').map(function(s) { return s.trim(); }).filter(Boolean) : [];
      hods.push({ username: username, fullName: fullName, assignedEngineers: assigned });
    }
    return { success: true, hods: hods };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

function updateHodAssignedEngineersV3(hodUsername, engineerNames, token) {
  var access = requireSession(token, ['Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var sheet = getUsersSheetV3();
    if (!sheet) return { success: false, message: "Users sheet not found." };
    var data = sheet.getDataRange().getValues();
    var key = (hodUsername || "").toString().trim().toLowerCase();
    var namesArr = Array.isArray(engineerNames) ? engineerNames : (engineerNames || "").toString().split(',');
    var csv = namesArr.map(function(s) { return s.toString().trim(); }).filter(Boolean).join(',');

    for (var i = 1; i < data.length; i++) {
      var rowUser = data[i][0] ? data[i][0].toString().trim().toLowerCase() : "";
      if (rowUser === key) {
        sheet.getRange(i + 1, 5).setValue(csv);
        return { success: true, message: "Assigned engineers updated." };
      }
    }
    return { success: false, message: "HOD user not found." };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

// Central scoping decision used by every HOD-facing report/dashboard function.
// Returns { ok:true, scoped:false, allowedEngineers:null } for Admin (sees
// everything), or { ok:true, scoped:true, allowedEngineers:[...] } for HOD
// (possibly an empty array if nothing's been assigned yet - callers should
// then show nothing rather than falling back to "show all").
function getHodEngineerScopeV3(token) {
  var access = requireSession(token, null);
  if (!access.ok) return { ok: false, message: access.message, sessionExpired: access.sessionExpired };

  var role = (access.session.role || "").toString().trim().toLowerCase();
  if (role === 'hod') {
    var list = getHodAssignedEngineersV3(access.session.username || access.session.fullName);
    // "ALL" is a sentinel meaning "every engineer, including ones added later" -
    // treat exactly like Admin's unrestricted view rather than a fixed name list.
    var isAllSentinel = list.length === 1 && list[0].toString().trim().toLowerCase() === 'all';
    if (isAllSentinel) {
      return { ok: true, scoped: false, allowedEngineers: null, session: access.session };
    }
    return { ok: true, scoped: true, allowedEngineers: list, session: access.session };
  }
  // Admin (and anything else, e.g. an Engineer calling a shared endpoint) is unscoped here -
  // Engineers are already restricted to their own data by the existing engineerName filters.
  return { ok: true, scoped: false, allowedEngineers: null, session: access.session };
}

function engineerInHodScopeV3(scope, engineerName) {
  if (!scope || !scope.scoped) return true;
  if (!engineerName) return false;
  var allowed = scope.allowedEngineers || [];
  var nameLower = engineerName.toString().trim().toLowerCase();
  for (var i = 0; i < allowed.length; i++) {
    if (allowed[i].toString().trim().toLowerCase() === nameLower) return true;
  }
  return false;
}

// Engineer-picker dropdowns (TA/DA Analytics, Work Monitor, Stations
// reassignment) should only ever offer an HOD their own assigned engineers,
// not the whole company - use this instead of getAllEngineersListV3 wherever
// the picker is HOD-facing.
function getEngineersVisibleToCallerV3(token) {
  var scope = getHodEngineerScopeV3(token);
  if (!scope.ok) return { success: false, message: scope.message, sessionExpired: scope.sessionExpired, engineers: [] };
  if (scope.scoped) {
    return { success: true, engineers: (scope.allowedEngineers || []).slice().sort() };
  }
  return getAllEngineersListV2();
}

function getUsersListV3(token) {
  var access = requireSession(token, ['Admin']);
  if (!access.ok) return [];
  return getUsersListV2();
}

function addUserV3(username, password, fullName, role, token) {
  var access = requireSession(token, ['Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var ss = getSpreadsheetV3();
    var sheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_USERS || "Users") : null;
    if (!sheet) return { success: false, message: "Users database sheet not found" };

    var data = sheet.getDataRange().getValues();
    var uLower = username.toLowerCase().trim();
    for (var i = 1; i < data.length; i++) {
      var rowUser = data[i][0] ? data[i][0].toString().toLowerCase().trim() : "";
      if (rowUser === uLower) {
        return { success: false, message: "User '" + username + "' already exists!" };
      }
    }

    sheet.appendRow([uLower, hashPasswordV2(password.toString().trim()), fullName.trim(), role.trim()]);
    return { success: true, message: "User '" + username + "' created successfully!" };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

function deleteUserV3(username, token) {
  var access = requireSession(token, ['Admin']);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  try {
    var ss = getSpreadsheetV3();
    var sheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_USERS || "Users") : null;
    if (!sheet) return { success: false, message: "Users database sheet not found" };

    var data = sheet.getDataRange().getValues();
    var uLower = username.toLowerCase().trim();
    if (uLower === 'admin') {
      return { success: false, message: "Cannot delete the root admin account!" };
    }

    for (var i = 1; i < data.length; i++) {
      var rowUser = data[i][0] ? data[i][0].toString().toLowerCase().trim() : "";
      if (rowUser === uLower) {
        sheet.deleteRow(i + 1);
        return { success: true, message: "User '" + username + "' deleted successfully!" };
      }
    }
    return { success: false, message: "User not found" };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

function getHtmlOutputV4(filename) {
  var cleanName = filename ? filename.toString().replace(/\.html$/i, "") : "Home_V4";
  if (cleanName !== 'Home_V4' && cleanName !== 'Home_V3' && cleanName !== 'Home') {
    return HtmlService.createHtmlOutput(getSubTemplateV4(cleanName))
      .setTitle("GOEC Service and Maintenance Portal V4")
      .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
  }

  var fileNamesToTry = [cleanName, cleanName + '.html', 'Home_V4', 'Home_V4.html', 'Home_V3', 'Home_V3.html', 'Home'];
  for (var i = 0; i < fileNamesToTry.length; i++) {
    try {
      var output = HtmlService.createHtmlOutputFromFile(fileNamesToTry[i]);
      if (output) {
        return output
          .setTitle("GOEC Service and Maintenance Portal V4")
          .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
          .addMetaTag('viewport', 'width=device-width, initial-scale=1');
      }
    } catch(e) {}
  }
  return HtmlService.createHtmlOutput("<div style='font-family:sans-serif; padding:40px; background:#07090e; color:#00e5ff; text-align:center;'><h2>GOEC V4 Engine Active</h2></div>");
}

function getHtmlOutputV3(filename) { return getHtmlOutputV4(filename); }

function doGet(e) {
  try {
    return getHtmlOutputV4('Home_V4');
  } catch (err) {
    return HtmlService.createHtmlOutput("<div style='color:red; font-family:sans-serif; padding:40px;'>Error: " + err.toString() + "</div>");
  }
}

function doPost(e) {
  return HtmlService.createHtmlOutput(
    '<!DOCTYPE html><html><head><script>window.top.location.href = window.location.href.split("?")[0];<\/script><\/head><body style="background:#07090e; color:#00e5ff; font-family:sans-serif; text-align:center; padding:40px; min-height:100vh;">Loading GOEC Portal V4...<\/body><\/html>'
  ).setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

CONFIG_V3 = CONFIG_V2;


// ===== HOD & SUPERVISOR V3 BACKEND WRAPPERS =====

function getPMReportOverviewV3(monthStr, token) {
  return getPMReportOverviewV2(token, monthStr);
}

function getStationFullPMReportV3(searchQuery, token) {
  return getStationFullPMReportV2(searchQuery, token);
}

function verifyStationPMV3(stationName, verifierName, token) {
  return verifyStationPMV2(stationName, verifierName, token);
}

function sendPMReportEmailV3(recipientEmail, recipientName, stationName, selectedSections, customNotes, token) {
  return sendPMReportEmailV2(recipientEmail, recipientName, stationName, selectedSections, customNotes, token);
}

function loadCommissioningLogsV3(token) {
  return loadCommissioningLogsV2(token);
}

function getAllEngineersListV3(token) {
  var access = requireSession(token, null);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired, engineers: [] };
  return getAllEngineersListV2();
}

function getAllWeeklyIssuesV3(token) {
  return getAllWeeklyIssuesV2(token);
}

function getHODWorkSummaryV3() {
  return getHODWorkSummaryV2();
}

function getHODTadaSummaryV3(monthStr, engineerName) {
  return getHODTadaSummaryV2(monthStr, engineerName);
}

function getHODSummaryV3(monthStr, token) {
  return getHODSummaryV2(monthStr, token);
}

function getCPDetailsForStationV3(stationName) {
  return getCPDetailsForStationV2(stationName);
}

function getEngineerDailyWorkHistoryV3(engineerName, yearMonth) {
  return getEngineerDailyWorkHistoryV2(engineerName, yearMonth);
}

function getEngineerTadaHistoryV3(engineerName, monthStr, token) {
  return getEngineerTadaHistoryV2(engineerName, monthStr, token);
}

function submitWeeklyIssueV3(payload, token) {
  var access = requireSession(token, null);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };
  var callerRole = (access.session.role || "").toString().trim().toLowerCase();
  if (callerRole !== 'admin' && callerRole !== 'hod') {
    var ownName = access.session.fullName || access.session.username;
    payload = payload || {};
    payload.engineer = ownName;
    payload.engineerName = ownName;
  }
  return submitWeeklyIssueV2(payload);
}

function parseWorkDateToYYYYMMDD(rawDate) {
  if (!rawDate) return "";
  if (rawDate instanceof Date) {
    try {
      return Utilities.formatDate(rawDate, Session.getScriptTimeZone() || "GMT", "yyyy-MM-dd");
    } catch(e) {
      return rawDate.toISOString().substring(0, 10);
    }
  }
  var str = rawDate.toString().trim();
  if (!str) return "";
  if (/^\d{4}-\d{2}-\d{2}/.test(str)) {
    return str.substring(0, 10);
  }
  var parts = str.split(/[\/\-\s]/);
  if (parts.length >= 3) {
    var p1 = parseInt(parts[0], 10);
    var p2 = parseInt(parts[1], 10);
    var p3 = parseInt(parts[2], 10);
    if (p1 > 1000) {
      return p1 + "-" + ("0" + p2).slice(-2) + "-" + ("0" + p3).slice(-2);
    } else if (p3 > 1000) {
      return p3 + "-" + ("0" + p2).slice(-2) + "-" + ("0" + p1).slice(-2);
    }
  }
  try {
    var dObj = new Date(str);
    if (!isNaN(dObj.getTime())) {
      return Utilities.formatDate(dObj, Session.getScriptTimeZone() || "GMT", "yyyy-MM-dd");
    }
  } catch(e) {}
  return str.substring(0, 10);
}


function deleteTadaClaimV2(rowIndex, engineerName, claimDateStr, token) {
  var access = requireSession(token, null);
  if (!access.ok) return { success: false, message: access.message, sessionExpired: access.sessionExpired };

  // This is the Engineer's own self-service "delete my claim" action (HOD/
  // Admin delete any engineer's claim through the separate, RecordID-based
  // adminDeleteSubmissionV3 path). So a non-Admin/HOD caller may only ever
  // target their OWN claims - never trust the client-supplied engineerName
  // for that decision, always use the caller's real session identity.
  var callerRole = (access.session.role || "").toString().trim().toLowerCase();
  var isPrivileged = (callerRole === 'admin' || callerRole === 'hod');
  var ownerName = isPrivileged ? engineerName : (access.session.fullName || access.session.username);

  try {
    var ss = getSpreadsheetV3();
    if (!ss) ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss ? ss.getSheetByName(CONFIG_V2.SHEET_TADA || 'TADA_Log') : null;
    if (!sheet) sheet = ss ? ss.getSheetByName("TADA_Log") : null;
    if (!sheet) return { success: false, message: "TADA_Log sheet not found" };

    var ownerTarget = (ownerName || "").toString().trim().toLowerCase();

    var rIdx = parseInt(rowIndex, 10);
    var lastRow = sheet.getLastRow();

    if (rIdx >= 2 && rIdx <= lastRow) {
      var targetRowVals = sheet.getRange(rIdx, 1, 1, 4).getValues()[0];
      var targetRowEng = targetRowVals[1] ? targetRowVals[1].toString().trim().toLowerCase() : "";
      if (!isPrivileged && (!targetRowEng || (targetRowEng.indexOf(ownerTarget) === -1 && ownerTarget.indexOf(targetRowEng) === -1))) {
        return { success: false, message: "You can only delete your own TA/DA claims." };
      }
      sheet.deleteRow(rIdx);
      return { success: true, message: "TA/DA claim deleted successfully." };
    }

    var data = sheet.getDataRange().getValues();
    var dateTarget = (claimDateStr || "").toString().trim();

    for (var r = data.length - 1; r >= 1; r--) {
      var rowEng = data[r][1] ? data[r][1].toString().trim().toLowerCase() : "";
      var rowDate = data[r][3] ? parseWorkDateToYYYYMMDD(data[r][3]) : "";
      if ((!ownerTarget || rowEng.indexOf(ownerTarget) !== -1 || ownerTarget.indexOf(rowEng) !== -1) && rowDate === dateTarget) {
        sheet.deleteRow(r + 1);
        return { success: true, message: "TA/DA claim deleted successfully." };
      }
    }

    return { success: false, message: "Target claim row not found." };
  } catch(e) {
    return { success: false, message: e.toString() };
  }
}

function deleteTadaClaimV3(rowIndex, engineerName, claimDateStr, token) {
  return deleteTadaClaimV2(rowIndex, engineerName, claimDateStr, token);
}


/**
 * Automatically sends Commissioning Report PDF to Management & HODs upon submission
 */
/**
 * Automatically sends Commissioning Report PDF to Management & HODs upon submission
 */
/**
 * Automatically sends Commissioning Report PDF to Management & HODs upon submission
 */
/**
 * Automatically sends Commissioning Report PDF to Management & HODs upon submission
 */
function sendCommissioningEmailWithPdfV2(payload) {
  try {
    Logger.log("Starting sendCommissioningEmailWithPdfV2...");
    var recipients = CONFIG_V2.NOTIFICATION_EMAILS || "";
    try {
      var propEmails = PropertiesService.getScriptProperties().getProperty('NOTIFICATION_EMAILS');
      if (propEmails && propEmails.trim() !== "") recipients = propEmails.trim();
    } catch (eProp) {}

    if (!recipients || recipients.trim() === "") {
      Logger.log("No notification recipients configured in NOTIFICATION_EMAILS Script Property. Skipping automatic email.");
      return;
    }

    var stationName = payload.locationName || payload.stationName || "EV Station";
    var engineerName = payload.engineer || payload.engineerName || "N/A";
    var visitDate = payload.visitDate || "N/A";

    Logger.log("Building Executive Report HTML for: " + stationName);
    var htmlContent = buildExecutiveCommissioningReportHtmlV2(payload);
    var htmlOutput = HtmlService.createHtmlOutput(htmlContent);
    var safeStationName = stationName.replace(/[^a-zA-Z0-9_-]/g, '_');
    var pdfBlob = htmlOutput.getAs('application/pdf').setName("GOEC_Commissioning_Report_" + safeStationName + ".pdf");

    var emailSubject = "[GO EC] EV Station Commissioning Report - " + stationName;
    var emailPlainBody = "Dear Team,\n\nPlease find attached the official Site Commissioning & Technical Safety Audit Report for " + stationName + ".\n\n" +
      "&bull; EV Station Location: " + stationName + "\n" +
      "&bull; Commissioning Engineer: " + engineerName + "\n" +
      "&bull; Visit Date: " + visitDate + "\n\n" +
      "This is an automated notification from GO EC Auto Tech Pvt Ltd Operations & Quality Control Division.\n\n" +
      "Best Regards,\nGO EC AUTO TECH PVT LTD";

    var htmlEmailBody = 
      '<div style="font-family: Arial, Tahoma, sans-serif; color: #1e293b; max-width: 650px; margin: 0 auto; border: 1px solid #cbd5e1; border-radius: 14px; overflow: hidden; background-color: #ffffff; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">' +
        '<div style="background: #0b1329; padding: 22px 24px; border-bottom: 3px solid #00e5ff;">' +
          '<h2 style="color: #ffffff; margin: 0; font-size: 20px; font-weight: 700; letter-spacing: 0.5px;">GO EC AUTO TECH PVT LTD</h2>' +
          '<p style="color: #00e5ff; margin: 6px 0 0 0; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">EV Station Commissioning & Technical Safety Audit Report</p>' +
        '</div>' +
        '<div style="padding: 24px;">' +
          '<p style="font-size: 15px; color: #334155; margin-top: 0;">Dear Team,</p>' +
          '<p style="font-size: 14px; color: #475569; line-height: 1.6;">The site commissioning audit for <strong>' + stationName + '</strong> has been successfully completed and recorded.</p>' +
          '<div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px; margin: 20px 0;">' +
            '<table style="width: 100%; border-collapse: collapse; font-size: 13px;">' +
              '<tr><td style="padding: 6px 0; color: #64748b; font-weight: 600; width: 40%;">EV Station Location:</td><td style="padding: 6px 0; color: #0f172a; font-weight: 700;">' + stationName + '</td></tr>' +
              '<tr><td style="padding: 6px 0; color: #64748b; font-weight: 600;">Commissioning Engineer:</td><td style="padding: 6px 0; color: #0f172a; font-weight: 600;">' + engineerName + '</td></tr>' +
              '<tr><td style="padding: 6px 0; color: #64748b; font-weight: 600;">Visit Date:</td><td style="padding: 6px 0; color: #0f172a; font-weight: 600;">' + visitDate + '</td></tr>' +
            '</table>' +
          '</div>' +
          '<p style="font-size: 13px; color: #0284c7; font-weight: 600; margin-bottom: 0;">&#128206; The detailed Executive Commissioning Audit PDF is attached to this email.</p>' +
        '</div>' +
        '<div style="background: #f1f5f9; padding: 14px 24px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #64748b;">' +
          '<strong>GO EC AUTO TECH PVT LTD</strong> &mdash; Operations & Quality Control Division | Confidential Engineering Notification' +
        '</div>' +
      '</div>';

    try {
      MailApp.sendEmail({
        to: recipients,
        subject: emailSubject,
        body: emailPlainBody,
        htmlBody: htmlEmailBody,
        attachments: [pdfBlob]
      });
      Logger.log("MailApp.sendEmail successfully sent commissioning report to: " + recipients);
    } catch (eMailApp) {
      Logger.log("MailApp.sendEmail failed: " + eMailApp.toString() + ". Attempting GmailApp fallback...");
      GmailApp.sendEmail(recipients, emailSubject, emailPlainBody, {
        htmlBody: htmlEmailBody,
        attachments: [pdfBlob]
      });
      Logger.log("GmailApp.sendEmail successfully sent commissioning report to: " + recipients);
    }
  } catch (eMail) {
    Logger.log("sendCommissioningEmailWithPdfV2 fatal error: " + eMail.toString());
  }
}

function buildExecutiveCommissioningReportHtmlV2(payload) {
  var stationName = payload.locationName || payload.stationName || "EV Station";
  var engineerName = payload.engineer || payload.engineerName || "-";
  var visitDate = payload.visitDate || "-";
  var cleanCode = stationName.replace(/[^a-zA-Z0-9]/g, '').toUpperCase().slice(0, 8) || "001";
  var docRef = "GOEC/COMM/2026/" + cleanCode + "_1";

  // Chargers HTML
  var chargersList = (payload.chargers && Array.isArray(payload.chargers) && payload.chargers.length > 0)
    ? payload.chargers
    : [{ oem: payload.oem || "", capacity: payload.capacity || "", serialNo: payload.serialNo || "", cpId: payload.cpId || "" }];

  var chgHtml = "";
  chargersList.forEach(function(c, i) {
    chgHtml += '<div style="background:#0b0f19; border:1px solid rgba(255,255,255,0.08); border-radius:10px; padding:12px; margin-bottom:10px;">' +
      '<div style="font-size:12px; font-weight:700; color:#00e5ff; margin-bottom:6px;">&#128268; Charger #' + (i + 1) + '</div>' +
      '<table style="width:100%; font-size:11px; color:#fff;">' +
        '<tr>' +
          '<td style="width:25%;"><strong>CP ID:</strong> ' + (c.cpId || "-") + '</td>' +
          '<td style="width:25%;"><strong>OEM:</strong> ' + (c.oem || payload.oem || "-") + '</td>' +
          '<td style="width:25%;"><strong>Capacity:</strong> ' + (c.capacity || payload.capacity || "-") + '</td>' +
          '<td style="width:25%;"><strong>Serial No:</strong> ' + (c.serialNo || payload.serialNo || "-") + '</td>' +
        '</tr>' +
      '</table>' +
    '</div>';
  });

  // SIM Cards
  var simTokens = [];
  var rawSims = (payload.sims && Array.isArray(payload.sims) && payload.sims.length > 0)
    ? payload.sims.map(function(s){ return s.sim || s.simOther || ""; })
    : [(payload.simNumber || "")];

  rawSims.forEach(function(raw) {
    if (raw && typeof raw === 'string') {
      raw.split(/[,;\n]+/).forEach(function(item) {
        var t = item.trim();
        if (t && simTokens.indexOf(t) === -1) simTokens.push(t);
      });
    }
  });

  var simPills = "";
  if (simTokens.length > 0) {
    simTokens.forEach(function(s) {
      simPills += '<span style="background:rgba(0,229,255,0.15); color:#00e5ff; border:1px solid rgba(0,229,255,0.3); padding:3px 8px; border-radius:12px; font-size:10px; font-weight:700; display:inline-block; margin-right:4px; margin-bottom:4px;">' + s + '</span>';
    });
  } else {
    simPills = '<span style="color:#94a3b8; font-size:11px;">No SIM cards logged.</span>';
  }

  // Panel Placement
  var pRaw = payload.placementOfPanel || "";
  var pMedia = payload.placementOfPanelMedia || "";
  var pTxt = pRaw;
  if (pRaw.indexOf('| Media:') !== -1) {
    var parts = pRaw.split('| Media:');
    pTxt = parts[0].trim();
    if (!pMedia) pMedia = parts[1].trim();
  }

  var fullStationImgHtml = payload.fullStationImage 
    ? '<img src="' + payload.fullStationImage + '" style="max-width:100%; max-height:300px; border-radius:8px; display:block; margin:0 auto;" />'
    : '<div style="color:#94a3b8; font-size:11px; text-align:center; padding:30px;">Full Station Photo Not Attached</div>';

  var panelPhotoHtml = payload.panelPhoto 
    ? '<img src="' + payload.panelPhoto + '" style="max-width:100%; max-height:180px; border-radius:8px; display:block; margin:0 auto;" />'
    : '<div style="color:#94a3b8; font-size:11px; text-align:center; padding:20px;">Panel Photo Not Attached</div>';

  var placementPhotoHtml = pMedia 
    ? '<img src="' + pMedia + '" style="max-width:100%; max-height:160px; border-radius:8px; display:block; margin:0 auto;" />'
    : '';

  return '<!DOCTYPE html><html><head><meta charset="utf-8"/><title>Commissioning Audit Report</title>' +
    '<style>' +
      'body { font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background:#070a12; color:#f8fafc; margin:0; padding:16px; font-size:12px; }' +
      '.card { background:rgba(15,23,42,0.85); border:1px solid rgba(255,255,255,0.08); border-radius:10px; padding:12px; margin-bottom:12px; }' +
      '.grid { display:table; width:100%; table-layout:fixed; }' +
      '.col { display:table-cell; vertical-align:top; padding:4px 8px; }' +
      '.lbl { font-size:9px; text-transform:uppercase; color:#94a3b8; font-weight:700; display:block; margin-bottom:2px; }' +
      '.val { font-size:11px; color:#ffffff; font-weight:600; word-break:break-all; }' +
      '.sec-title { font-size:13px; font-weight:700; color:#00e5ff; border-bottom:1px solid rgba(0,229,255,0.2); padding-bottom:4px; margin-bottom:10px; }' +
    '</style></head><body>' +

    '<!-- HEADER BORDER -->' +
    '<div style="background:#0b1329; border-bottom:3px solid #00e5ff; border-radius:12px; padding:14px 18px; margin-bottom:12px; display:table; width:100%; box-sizing:border-box;">' +
      '<div style="display:table-cell; vertical-align:middle;">' +
        '<div style="font-size:18px; font-weight:800; color:#ffffff; letter-spacing:0.5px;">GO EC AUTO TECH PVT LTD</div>' +
        '<div style="font-size:11px; font-weight:700; color:#00e5ff; margin-top:2px;">EV STATION COMMISSIONING & SAFETY AUDIT REPORT</div>' +
      '</div>' +
      '<div style="display:table-cell; text-align:right; vertical-align:middle;">' +
        '<div style="font-size:9px; color:#94a3b8; font-weight:700;">DOCUMENT REF.</div>' +
        '<div style="font-size:12px; font-weight:700; color:#00e676;">' + docRef + '</div>' +
      '</div>' +
    '</div>' +

    '<!-- SUMMARY CARD -->' +
    '<div class="card" style="background:linear-gradient(135deg, rgba(30,41,59,0.9), rgba(15,23,42,0.95)); border:1px solid rgba(0,229,255,0.25);">' +
      '<div class="grid">' +
        '<div class="col" style="width:40%;"><span class="lbl">EV Station Location Name</span><div class="val" style="font-size:14px; color:#fff; font-weight:700;">' + stationName + '</div></div>' +
        '<div class="col" style="width:30%;"><span class="lbl">Commissioning Engineer</span><div class="val" style="font-size:12px;">' + engineerName + '</div></div>' +
        '<div class="col" style="width:30%;"><span class="lbl">Visit Date</span><div class="val" style="font-size:12px;">' + visitDate + '</div></div>' +
      '</div>' +
    '</div>' +

    '<!-- FULL STATION OVERVIEW -->' +
    '<div class="card">' +
      '<div class="sec-title" style="color:#00e676;">&#128248; Full Station Overview</div>' +
      '<div style="background:#0b0f19; border-radius:8px; padding:8px;">' + fullStationImgHtml + '</div>' +
    '</div>' +

    '<!-- PANEL PHOTO & PLACEMENT -->' +
    '<div class="grid" style="margin-bottom:12px;">' +
      '<div class="col" style="width:50%; padding-left:0;">' +
        '<div class="card" style="height:100%; margin-bottom:0;">' +
          '<div class="sec-title">&#128736;\ufe0f LT Control Panel Inspection</div>' +
          '<div style="background:#0b0f19; border-radius:8px; padding:6px;">' + panelPhotoHtml + '</div>' +
        '</div>' +
      '</div>' +
      '<div class="col" style="width:50%; padding-right:0;">' +
        '<div class="card" style="height:100%; margin-bottom:0;">' +
          '<div class="sec-title">\ud83d\udccd LT Control Panel Location & Placement</div>' +
          (placementPhotoHtml ? '<div style="background:#0b0f19; border-radius:8px; padding:6px; margin-bottom:6px;">' + placementPhotoHtml + '</div>' : '') +
          '<div class="val" style="font-size:11px; color:#cbd5e1; background:rgba(255,255,255,0.03); padding:6px; border-radius:6px;">' + (pTxt || "No placement description provided.") + '</div>' +
        '</div>' +
      '</div>' +
    '</div>' +

    '<!-- SECTION 1: CHARGERS -->' +
    '<div class="card">' +
      '<div class="sec-title">&#128268; Section 1: Station Chargers & Hardware Configuration</div>' +
      chgHtml +
    '</div>' +

    '<!-- SECTION 2: BRANDING -->' +
    '<div class="card">' +
      '<div class="sec-title">&#10024; Section 2: Branding, Signage & Canopy Checklist</div>' +
      '<table style="width:100%; font-size:11px; color:#fff;" cellPadding="4">' +
        '<tr>' +
          '<td style="width:33%;"><strong>Branding Sticker, QR & Nameplate:</strong><br/>' + (payload.brandingStickerStatus || "-") + '</td>' +
          '<td style="width:33%;"><strong>Instruction Board Installation:</strong><br/>' + (payload.instructionBoardStatus || "-") + '</td>' +
          '<td style="width:33%;"><strong>Canopy Backdrop Branding:</strong><br/>' + (payload.canopyBackdropStatus || "-") + '</td>' +
        '</tr>' +
        '<tr>' +
          '<td><strong>External Light Board Status:</strong><br/>' + (payload.externalLightBoardStatus || "-") + '</td>' +
          '<td><strong>Syntax Box (SMPS) Installation:</strong><br/>' + (payload.syntaxBoxSmps || "-") + '</td>' +
          '<td><strong>Canopy Square Light Board:</strong><br/>' + (payload.canopySquareLightStatus || "-") + '</td>' +
        '</tr>' +
        '<tr>' +
          '<td colSpan="3"><strong>Canopy Branding Light Board:</strong><br/>' + (payload.canopyBrandingLightStatus || "-") + '</td>' +
        '</tr>' +
      '</table>' +
    '</div>' +

    '<!-- SECTION 3: SAFETY & ELECTRICAL -->' +
    '<div class="card">' +
      '<div class="sec-title">&#128737;\ufe0f Section 3: Safety, Hardware & Electrical Protection</div>' +
      '<table style="width:100%; font-size:11px; color:#fff;" cellPadding="4">' +
        '<tr>' +
          '<td style="width:33%;"><strong>SD Card Installation Status:</strong><br/>' + (payload.sdCardStatus || "-") + '</td>' +
          '<td style="width:33%;"><strong>CCTV Surveillance Status:</strong><br/>' + (payload.cctvStatus || "-") + '</td>' +
          '<td style="width:33%;"><strong>Fire Extinguisher Availability:</strong><br/>' + (payload.fireExtinguisherStatus || "-") + '</td>' +
        '</tr>' +
        '<tr>' +
          '<td><strong>Communication Modem Status:</strong><br/>' + (payload.modemStatus || "-") + '</td>' +
          '<td><strong>Protective Bollard Installation:</strong><br/>' + (payload.bollardStatus || "-") + '</td>' +
          '<td><strong>Transformer Capacity, Type & VCB/RMU:</strong><br/>' + (payload.transformerCapacity || "-") + '</td>' +
        '</tr>' +
        '<tr>' +
          '<td><strong>Transformer Yard to LT Cable Size:</strong><br/>' + (payload.cableSizeTransformerToLt || "-") + '</td>' +
          '<td colSpan="2"><strong>LT Panel to Charger Cable Size:</strong><br/>' + (payload.cableSizeLtToCharger || "-") + '</td>' +
        '</tr>' +
      '</table>' +
    '</div>' +

    '<!-- SECTION 4: PANEL CONDITION -->' +
    '<div class="card">' +
      '<div class="sec-title">&#9889; Section 4: Panel Condition & Protection Systems</div>' +
      '<table style="width:100%; font-size:11px; color:#fff;" cellPadding="4">' +
        '<tr>' +
          '<td style="width:33%;"><strong>Timer & Contactor Status:</strong><br/>' + (payload.timerContactorStatus || "-") + '</td>' +
          '<td style="width:33%;"><strong>Canopy Structural Integrity:</strong><br/>' + (payload.canopyHoleDamage || "-") + '</td>' +
          '<td style="width:33%;"><strong>LT Panel Coating & Enclosure:</strong><br/>' + (payload.ltPanelCoatingCondition || "-") + '</td>' +
        '</tr>' +
        '<tr>' +
          '<td><strong>MFM, SPD & ELR Protection:</strong><br/>' + (payload.mfmSpdElrWorking || "-") + '</td>' +
          '<td><strong>SPD Type & Rating:</strong><br/>' + (payload.spdRating || "-") + '</td>' +
          '<td><strong>Lightning Protection Conduit:</strong><br/>' + (payload.lightningConcealedConduit || "-") + '</td>' +
        '</tr>' +
      '</table>' +
    '</div>' +

    '<!-- SECTION 5: CIVIL, SIM & REMARKS -->' +
    '<div class="card">' +
      '<div class="sec-title">&#127959; Section 5: Civil Infrastructure, SIM Cards & MCB Mapping</div>' +
      '<table style="width:100%; font-size:11px; color:#fff;" cellPadding="4">' +
        '<tr>' +
          '<td style="width:33%;"><strong>Civil Structure Condition:</strong><br/>' + (payload.civilStructureCondition || "-") + '</td>' +
          '<td style="width:33%;"><strong>Parking Slot Markings & Painting:</strong><br/>' + (payload.parkingPaintingStatus || "-") + '</td>' +
          '<td style="width:33%;"><strong>Interlock Paving Status:</strong><br/>' + (payload.interlockStatus || "-") + '</td>' +
        '</tr>' +
        '<tr>' +
          '<td colSpan="3"><strong>MCB to Charger Circuit Mapping:</strong><br/>' + (payload.mcbMapping || "-") + '</td>' +
        '</tr>' +
      '</table>' +
      '<div style="margin-top:8px;"><strong>&#128241; Assigned SIM Card(s):</strong><br/>' + simPills + '</div>' +
      '<div style="margin-top:8px;"><strong>&#128172; Field Remarks & Observations:</strong><br/><div class="val" style="color:#cbd5e1;">' + (payload.remarks || "None") + '</div></div>' +
    '</div>' +

    '<!-- FOOTER -->' +
    '<div style="border-top:1px solid rgba(255,255,255,0.1); padding-top:10px; font-size:10px; color:#94a3b8; text-align:center;">' +
      '<strong>GO EC AUTO TECH PVT LTD</strong> &mdash; Operations & Quality Control Division | Confidential Engineering Record' +
    '</div>' +

    '</body></html>';
}


/**
 * Test function to manually trigger Commissioning PDF Email & authorize MailApp / GmailApp permissions
 */
function testCommissioningEmailTriggerV2() {
  var mockPayload = {
    engineer: "Test Engineer",
    locationName: "GOEC Test Station",
    visitDate: "2026-08-08",
    chargers: [
      { cpId: "GOEC-TEST-001", oem: "Exicom", capacity: "60kW DC", serialNo: "EX12345678" }
    ],
    oem: "Exicom",
    capacity: "60kW DC",
    serialNo: "EX12345678",
    cpId: "GOEC-TEST-001",
    brandingStickerStatus: "Installed",
    instructionBoardStatus: "Installed",
    canopyBackdropStatus: "Completed",
    externalLightBoardStatus: "working",
    syntaxBoxSmps: "Yes",
    canopySquareLightStatus: "working",
    canopyBrandingLightStatus: "working",
    sdCardStatus: "Installed",
    cctvStatus: "working",
    fireExtinguisherStatus: "Installed",
    modemStatus: "working",
    bollardStatus: "Installed",
    transformerCapacity: "100 kVA",
    cableSizeTransformerToLt: "150 sqmm",
    cableSizeLtToCharger: "95 sqmm",
    timerContactorStatus: "working",
    canopyHoleDamage: "No",
    ltPanelCoatingCondition: "Good",
    mfmSpdElrWorking: "Yes",
    spdRating: "Type 2",
    lightningConcealedConduit: "Yes",
    civilStructureCondition: "Good",
    parkingPaintingStatus: "Completed",
    interlockStatus: "Completed",
    sims: ["8991234567890"],
    simNumber: "8991234567890",
    remarks: "Manual authorization test email.",
    timestamp: new Date().toISOString()
  };

  sendCommissioningEmailWithPdfV2(mockPayload);
}


// ============================================================================
// AUTOMATED DATABASE BOOTSTRAP & PROVISIONING (setupPortal)
// ============================================================================

/**
 * One-time setup function: creates the database spreadsheet (if not already existing),
 * builds all 13 sheet tabs with complete column schemas, formats headers,
 * seeds the system roles, and sets up an initial bootstrap administrator.
 *
 * Run this function ONCE from the Apps Script editor after deployment.
 */
function setupPortal() {
  Logger.log("==================================================================");
  Logger.log("Starting EV Station Service & Maintenance Portal Database Setup...");
  Logger.log("==================================================================");

  var props = PropertiesService.getScriptProperties();
  var ssId = props.getProperty('SPREADSHEET_ID');
  var ss = null;

  if (ssId && ssId.trim() !== '') {
    try {
      ss = SpreadsheetApp.openById(ssId.trim());
      Logger.log("Found existing spreadsheet configured in Script Properties: " + ss.getUrl());
    } catch (e) {
      Logger.log("Configured spreadsheet ID inaccessible (" + e.message + "). A new one will be created.");
      ss = null;
    }
  }

  if (!ss) {
    try {
      ss = SpreadsheetApp.getActiveSpreadsheet();
      if (ss) {
        Logger.log("Using active container spreadsheet: " + ss.getUrl());
        props.setProperty('SPREADSHEET_ID', ss.getId());
      }
    } catch (eActive) {
      ss = null;
    }
  }

  if (!ss) {
    ss = SpreadsheetApp.create("EV Station Service & Maintenance Portal DB");
    props.setProperty('SPREADSHEET_ID', ss.getId());
    Logger.log("Created brand new database spreadsheet: " + ss.getUrl());
  }

  var HEADER_BG = '#0F172A'; // Slate 900
  var HEADER_FG = '#F8FAFC'; // Slate 50

  function ensureSheetWithHeaders(sheetName, headers) {
    var sheet = ss.getSheetByName(sheetName);
    if (!sheet) {
      sheet = ss.insertSheet(sheetName);
      Logger.log("Created sheet tab: " + sheetName);
    }
    if (sheet.getLastRow() === 0) {
      sheet.appendRow(headers);
      var headerRange = sheet.getRange(1, 1, 1, headers.length);
      headerRange.setBackground(HEADER_BG)
                 .setFontColor(HEADER_FG)
                 .setFontWeight('bold')
                 .setFontFamily('Segoe UI')
                 .setWrap(true);
      sheet.setFrozenRows(1);
      Logger.log("Initialized headers for: " + sheetName);
    }
    return sheet;
  }

  // 1. Commissioning Log
  ensureSheetWithHeaders(CONFIG_V2.SHEET_COMMISSIONING || 'Commissioning Log', [
    "Timestamp", "ENGINEER", "Location Name", "Visit date", "Charger OEM", "charger Capacity",
    "Charger Serial no.", "Branding Sticker Status", "Instruction Board Status", "Canopy Backdrop Status",
    "External Light Board Status", "Syntax Box SMPS", "Canopy Square Light Status", "Canopy Branding Light Status",
    "SD Card Status", "CCTV Status", "Fire Extinguisher Status", "Modem Status", "Bollard Status",
    "Transformer Capacity", "Transformer to LT Cable Size", "LT to Charger Cable Size", "Timer & Contactor Status",
    "Canopy Hole Damage", "LT Panel Coating Condition", "MFM SPD ELR Working", "SPD Rating",
    "Lightning Concealed Conduit", "Civil Structure Condition", "Parking Slot Painting Status",
    "Interlock Work Status", "SIM No.", "Remarks", "Full Station Image (App)", "Panel Photo (Tech Support)",
    "Placement of Panel", "MCB to Charger Mapping", "Payload JSON", "RecordID", "SubmissionID"
  ]);

  // 2. PM Electrical & Civil
  ensureSheetWithHeaders(CONFIG_V2.SHEET_PM_CIVIL || 'PM_ElectricalCivil_Log', [
    "Timestamp", "ENGINEER", "EVCS Location Name", "PM Date", "Transformer Type (Public/Private)",
    "Before PM Media", "Panel Maintenance", "Panel Voltages (L-L & L-N)", "Earth Pit Voltage (V)",
    "SPD Status", "ELR Tripping Status", "MFM Meter Status", "Unauthorized Load Check",
    "Canopy Structural Integrity", "Modem & CCTV Status", "Canopy Lighting", "External Branding Board",
    "Instruction & Do's/Don'ts Signage", "Fire Extinguisher Status", "Fire Extinguisher Photo",
    "Civil Bay & Bollards", "After PM Media", "Remarks", "Payload JSON", "RecordID"
  ]);

  // 3. PM Charger
  ensureSheetWithHeaders(CONFIG_V2.SHEET_PM_CHARGER || 'PM_Charger_Log', [
    "Timestamp", "ENGINEER", "EVCS Location Name", "PM Date", "CP ID", "Charger Serial No.",
    "Capacity & Type", "Before PM Media", "Alarms Status", "Cleaning Status", "Filter Replacement",
    "Cables Tightness", "Guns & Sockets", "Rodent Proofing", "Display & Touch Status", "Doors & Locks",
    "Power Module Status", "Input Voltages (V)", "Neutral-Earth Voltage (V)", "Emergency Stop Test",
    "Internet Status", "MCB/RCCB/SMPS Status", "Vehicle Charging Test", "RFID Status", "After PM Media",
    "Remarks", "Payload JSON", "Verified Status", "Verified By", "Verified Date", "RecordID"
  ]);

  // 4. Daily Work Report
  ensureSheetWithHeaders(CONFIG_V2.SHEET_DAILY_WORK || 'Daily_Work_Report', [
    "Timestamp", "ENGINEER", "ROLE", "REPORT TYPE", "WORK DATE",
    "LOCATION / STATION", "CP ID / CATEGORY", "ISSUE / DESCRIPTION",
    "CORRECTIVE ACTION", "SPARE PARTS USED", "WORK STATUS", "REMARKS",
    "ATTACHMENT URL", "Payload JSON", "RecordID", "Work Hours"
  ]);

  // 5. HOD Override Log
  ensureSheetWithHeaders(CONFIG_V2.SHEET_HOD_OVERRIDE || 'HOD_Override_Log', [
    "Timestamp", "HOD Name", "Action", "Target Sheet", "Record ID", "Original Status", "New Status", "Remarks"
  ]);

  // 6. TADA Log
  ensureSheetWithHeaders(CONFIG_V2.SHEET_TADA || 'TADA_Log', [
    "Timestamp", "ENGINEER", "ROLE", "Claim Date",
    "Travel Total (\u20b9)", "Food Total (\u20b9)", "Accommodation Total (\u20b9)", "Consumables Total (\u20b9)", "Grand Total (\u20b9)",
    "Travel Details", "Food Details", "Accommodation Details", "Consumables Details",
    "Payload JSON", "RecordID"
  ]);

  // 7. Users
  var userSheet = ensureSheetWithHeaders(CONFIG_V2.SHEET_USERS || 'Users', [
    "Username", "Password", "FullName", "Role"
  ]);

  // 8. Charger Inventory
  ensureSheetWithHeaders(CONFIG_V2.SHEET_INVENTORY || 'Charger Inventory', [
    "Location Name", "CP ID", "Charger Serial No", "OEM", "Connector Type", "Power Rating", "Service Engineer", "PM Due Date"
  ]);

  // 9. Sim Inventory
  ensureSheetWithHeaders(CONFIG_V2.SHEET_SIM || 'Sim Inventory', [
    "SIM Number", "Operator", "Location", "Status"
  ]);

  // 10. Weekly Pending Issues Log
  ensureSheetWithHeaders(CONFIG_V2.SHEET_WEEKLY_PENDING || 'Weekly_Pending_Issues_Log', [
    "Issue ID", "Timestamp", "ENGINEER", "Station Name", "Report Date", "Issue Title", "Issue Description", "Status", "HOD Remarks", "Issue Type"
  ]);

  // 11. Roles
  var rolesSheet = ensureSheetWithHeaders(CONFIG_V2.SHEET_ROLES || 'Roles', [
    "RoleName", "AllowedPages", "IsSystemRole"
  ]);

  // 12. Stations
  ensureSheetWithHeaders(CONFIG_V2.SHEET_STATIONS || 'Stations', [
    "StationName", "InvestorName", "InvestorEmails", "AssignedEngineer"
  ]);

  // 13. Audit Log
  ensureSheetWithHeaders(CONFIG_V2.SHEET_AUDIT || 'Audit_Log', [
    "Timestamp", "ActorUsername", "ActorFullName", "Action", "SheetKey", "RecordID", "FieldChanged", "OldValue", "NewValue"
  ]);

  // Seed default system roles
  if (rolesSheet.getLastRow() <= 1) {
    rolesSheet.appendRow(['Admin', 'ALL', true]);
    rolesSheet.appendRow(['HOD', 'dashboard,commissioning,pm_civil,pm_charger,daily_work,weekly_pending,tada,sim_inventory,pm_report,hod_comm,hod_weekly,hod_tada,hod_work_monitor,stations', true]);
    rolesSheet.appendRow(['Engineer', 'dashboard,commissioning,pm_civil,pm_charger,daily_work,weekly_pending,tada,sim_inventory,pm_report', true]);
    Logger.log("Seeded system roles: Admin, HOD, Engineer");
  }

  // Seed default administrator if empty
  var adminUsername = 'admin';
  var adminInitialPass = 'Admin@12345';
  if (userSheet.getLastRow() <= 1) {
    userSheet.appendRow([
      adminUsername,
      hashPasswordV2(adminInitialPass),
      'System Administrator',
      'Admin'
    ]);
    Logger.log("------------------------------------------------------------------");
    Logger.log("INITIAL ADMIN ACCOUNT CREATED:");
    Logger.log("  Username: " + adminUsername);
    Logger.log("  Password: " + adminInitialPass);
    Logger.log("  (Please change this password immediately upon first login)");
    Logger.log("------------------------------------------------------------------");
  }

  // Remove default 'Sheet1' if it exists and other sheets were created
  try {
    var defaultSheet = ss.getSheetByName('Sheet1');
    if (defaultSheet && ss.getSheets().length > 1) {
      ss.deleteSheet(defaultSheet);
    }
  } catch (eSheet1) {}

  // Ensure upload folder exists in Drive
  var folderName = 'EV Station Service Portal Uploads';
  var folders = DriveApp.getFoldersByName(folderName);
  var targetFolder = folders.hasNext() ? folders.next() : DriveApp.createFolder(folderName);
  Logger.log("Drive Upload Folder: " + targetFolder.getName() + " (ID: " + targetFolder.getId() + ")");

  Logger.log("==================================================================");
  Logger.log("SETUP COMPLETE! Database Spreadsheet URL:");
  Logger.log(ss.getUrl());
  Logger.log("==================================================================");

  return {
    success: true,
    spreadsheetUrl: ss.getUrl(),
    adminUsername: adminUsername,
    adminInitialPassword: adminInitialPass
  };
}
