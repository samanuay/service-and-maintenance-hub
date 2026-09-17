# EV Station Service & Maintenance Portal

> **Enterprise Operations, Commissioning & Preventive Maintenance Suite for Electric Vehicle (EV) Charging Infrastructure.**

A production-grade, standalone Google Apps Script Single-Page Web Application (SPA) designed for EV charging point operators (CPOs), operations heads, and field service engineers to manage the entire lifecycle of EV charging stations.

---

## Key Features

### 1. Station Commissioning Wizard
- **Comprehensive 36-Point Inspection**: Full validation of transformers, LT panels, cable sizes, civil foundations, earthing, canopies, lighting, CCTV, and switchgear.
- **Charger & Hardware Verification**: Multi-gun DC fast charger and AC charger validation (OEM, serial numbers, power ratings, and connector configurations).
- **Auto-Sync to Inventory**: Commissioned stations automatically register in the central **Charger Inventory** and schedule upcoming Preventive Maintenance (PM) due dates.

### 2. Preventive Maintenance (PM) Engine
- **Electrical & Civil PM**: Transformer checks, earth pit voltage tests, SPD/ELR tripping status, MFM meter readings, and canopy integrity.
- **Charger PM Protocol**: Power module health, air filter replacement schedules, gun/cable tightness, neutral-to-earth voltages, and live charging validation.
- **Photo Evidence Pipeline**: Mandatory before-and-after photographic records with direct upload to Google Drive.
- **Verification Workflow**: Multi-tier review allowing HODs to verify, approve, or flag discrepancies in PM submissions.

### 3. Management & Supervisory Oversight (HOD Hub)
- **HOD Work Monitor**: Real-time tracking of field engineers' daily activities, route progress, and pending task queues.
- **Commissioning Audits**: Detailed verification of commissioning submissions with PDF generation for management sign-off.
- **Override Logs & Audit Trails**: Tamper-proof append-only audit log capturing all role edits, status changes, and database modifications.

### 4. Operations, Logistics & Expenses
- **Daily Work Reports (DWR)**: Corrective Maintenance (CM), Preventive Maintenance (PM), and Site Survey activity logging with work-hours tracking.
- **Weekly Pending Issues**: Action tracker for unresolved site breakdowns and hardware replacements with HOD resolution remarks.
- **SIM & Connectivity Inventory**: Tracking telecom SIMs, data numbers, network operators, and active station associations.
- **TA/DA Expense Claims**: Travel and Daily Allowance claim filing with receipt image uploads and automatic reimbursement tabulation.

### 5. Security & Access Governance
- **Role-Based Access Control (RBAC)**: Configurable roles (`Admin`, `HOD`, `Engineer`) with granular page-level permissions.
- **Server-Side Session Management**: 12-hour sliding window UUID session tokens stored in Script Properties—never trusting client-supplied roles.
- **Password Security**: Salted SHA-256 password hashing with self-service password updates and administrator reset capabilities.

---

## System Architecture

```
                               ┌───────────────────────────┐
                               │  Client Browser (SPA)     │
                               │  Glassmorphic UI / HTML5  │
                               └─────────────┬─────────────┘
                                             │ google.script.run (async)
                                             ▼
                               ┌───────────────────────────┐
                               │  Server Controller        │
                               │  (Code.js)                │
                               │  - Session Validator      │
                               │  - RBAC Engine            │
                               │  - Schema Normalizer      │
                               └───────┬───────────┬───────┘
                                       │           │
                     ┌─────────────────┴─┐       ┌─┴─────────────────┐
                     ▼                   ▼       ▼                   ▼
           ┌───────────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
           │ Google Sheets DB  │ │ Google Drive│ │ PDF Engine  │ │ Gmail API   │
           │ (13 Sheet Tabs)   │ │ Photo/Media │ │ Reports     │ │ Notifications│
           └───────────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
```

---

## File Structure

| File | Purpose |
| :--- | :--- |
| `Code.js` | Server-side controller, session validation, database CRUD, and self-bootstrapping `setupPortal()` |
| `Home.html` | Core SPA shell with glassmorphic navigation, login interface, and dynamic sub-template loader |
| `Index.html` | Station Commissioning form wizard |
| `PM_ElectricalCivil.html` | Electrical & Civil Infrastructure PM wizard |
| `PM_Charger.html` | EV Charger Preventive Maintenance wizard |
| `PMReport.html` | PM Report verification, review queue, and PDF generator |
| `DailyWorkReport.html` | Field engineer daily task and corrective maintenance logger |
| `WeeklyPending.html` | Weekly open defect tracker and resolution management |
| `TADA.html` | Field travel & daily allowance expense claim system |
| `SimInventory.html` | Telecom SIM inventory and station assignment manager |
| `Stations.html` | Charging station master directory and investor email mapping |
| `Roles.html` | Dynamic Role-Based Access Control configuration |
| `UserManagement.html` | User provisioning, password management, and role assignment |
| `AuditLog.html` | Append-only system change and event audit log |
| `HODCommAudit.html` | Supervisory commissioning audit and verification tool |
| `HODWorkMonitor.html` | Engineer daily work review and monitoring hub |
| `HODTada.html` | HOD expense claim approval interface |
| `appsscript.json` | Google Apps Script project manifest (V8 runtime, Web App configuration) |

---

## Database Model (13 Sheets)

The portal automatically structures and maintains 13 sheets within a Google Spreadsheet:

1. **`Commissioning Log`**: 38+ inspection parameters per station commissioning event.
2. **`PM_ElectricalCivil_Log`**: Transformer, panel voltage, earth pit, SPD, and civil inspection records.
3. **`PM_Charger_Log`**: Charger module, filter replacement, voltage, and charging test logs.
4. **`Daily_Work_Report`**: Daily field engineer activity logs with work hours.
5. **`Weekly_Pending_Issues_Log`**: Open issues, replacement part requests, and HOD resolution remarks.
6. **`TADA_Log`**: Financial expense claims across travel, food, accommodation, and consumables.
7. **`Users`**: User accounts, salted password hashes, full names, and assigned roles.
8. **`Roles`**: System and custom roles with page-level permission mapping (`AllowedPages`).
9. **`Charger Inventory`**: Master list of deployed chargers, CPIDs, OEMs, serials, and PM due dates.
10. **`Sim Inventory`**: SIM card numbers, operators, locations, and connectivity statuses.
11. **`Stations`**: Station names, investor details, notification emails, and designated engineers.
12. **`HOD_Override_Log`**: Audit record of supervisory approvals and status overrides.
13. **`Audit_Log`**: Field-level historical audit trail of all record modifications.

---

## One-Time Setup & Deployment

### Method 1: Using Google Apps Script Editor (No CLI required)

1. Go to [script.google.com](https://script.google.com) and create a **New Project**.
2. Name the project (e.g. `EV Station Service Portal`).
3. Under **Project Settings**, check **Show "appsscript.json" manifest file in editor**.
4. Copy the contents of `appsscript.json` from this repository into the project's `appsscript.json`.
5. Create each file matching the names in this repository:
   - Paste `Code.js` into `Code.gs`.
   - Create HTML files for each `.html` file (e.g., `Home`, `Index`, `PM_Charger`, etc.) and paste their respective contents.
6. **Run `setupPortal()`**:
   - In the function dropdown, select **`setupPortal`** and click **Run**.
   - Review and grant the required Google permissions (Google Sheets, Drive, Gmail).
   - Check the **Execution Log**: it will output your new Google Spreadsheet URL, Google Drive folder, and initial administrator credentials.
7. **Deploy the Web App**:
   - Click **Deploy** → **New deployment**.
   - Select **Web app** as the type.
   - Set **Execute as**: `Me (your Google account)`.
   - Set **Who has access**: `Anyone within your organization` (or `Anyone` if desired).
   - Click **Deploy** and open the resulting Web App URL!

---

### Method 2: Using Clasp CLI

```bash
# 1. Install clasp globally
npm install -g @google/clasp

# 2. Log in to your Google Account
clasp login

# 3. Create a new Apps Script Web App
clasp create --type webapp --title "EV Station Service Portal"

# 4. Push code to Apps Script
clasp push

# 5. Open in editor to run setupPortal() once
clasp open
```

---

## First-Time Login

When `setupPortal()` runs, it provisions an initial bootstrap administrator:

* **Username**: `admin`
* **Default Password**: `Admin@12345`

> **Note**: Log in immediately and change the default password via the portal interface or user settings.

---

## Optional Configuration

In Google Apps Script under **Project Settings** → **Script Properties**, you can optionally customize:

| Property | Description | Example |
| :--- | :--- | :--- |
| `SPREADSHEET_ID` | Explicit Google Spreadsheet ID to bind to | `1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms` |
| `NOTIFICATION_EMAILS` | Comma-separated emails to receive commissioning PDF alerts | `ops@example.com, management@example.com` |

---

## License

This project is open source and available under the [MIT License](LICENSE).
