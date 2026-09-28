/*
 * sysinfo.c - preflight
 *
 * Two jobs:
 *   1. Tell the operator whether this Windows build is a good place to sweep.
 *      Driver packages on Windows Update are targeted at specific OS versions
 *      and architectures, so an exact VID/PID match can still yield nothing if
 *      the vendor never certified the package for the build you are on.
 *   2. Catch the environmental reasons a sweep silently returns zero hits:
 *      WSUS management, driver-search policy, metered links, dead services.
 *      Without these checks every empty run would look identical.
 */

#include "pnpfuzz.h"
#include <objbase.h>

/* --- INetworkCostManager, declared by hand so no extra SDK header/lib ----- */

static const GUID PF_CLSID_NetworkListManager =
    { 0xDCB00C01, 0x570F, 0x4A9B, { 0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B } };
static const GUID PF_IID_INetworkCostManager =
    { 0xDCB00008, 0x570F, 0x4A9B, { 0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B } };

typedef struct PF_INetworkCostManager PF_INetworkCostManager;
typedef struct PF_INetworkCostManagerVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(PF_INetworkCostManager *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(PF_INetworkCostManager *);
    ULONG   (STDMETHODCALLTYPE *Release)(PF_INetworkCostManager *);
    HRESULT (STDMETHODCALLTYPE *GetCost)(PF_INetworkCostManager *, DWORD *, void *);
    HRESULT (STDMETHODCALLTYPE *GetDataPlanStatus)(PF_INetworkCostManager *, void *, void *);
    HRESULT (STDMETHODCALLTYPE *SetDestinationAddresses)(PF_INetworkCostManager *, UINT32, void *, VARIANT_BOOL);
} PF_INetworkCostManagerVtbl;
struct PF_INetworkCostManager { const PF_INetworkCostManagerVtbl *lpVtbl; };

#define PF_NLM_COST_UNRESTRICTED 0x1
#define PF_NLM_COST_UNKNOWN      0x0

/* ------------------------------------------------------------ registry --- */

static int reg_dword(HKEY root, const char *sub, const char *val, int *out)
{
    HKEY k;
    DWORD type = 0, data = 0, cb = sizeof(data);
    LONG r;

    *out = -1;
    if (RegOpenKeyExA(root, sub, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS)
        return 0;
    r = RegQueryValueExA(k, val, NULL, &type, (LPBYTE)&data, &cb);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS || type != REG_DWORD) return 0;
    *out = (int)data;
    return 1;
}

static int reg_str(HKEY root, const char *sub, const char *val, char *out, size_t cap)
{
    HKEY k;
    DWORD type = 0, cb = (DWORD)cap;
    LONG r;

    out[0] = '\0';
    if (RegOpenKeyExA(root, sub, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS)
        return 0;
    r = RegQueryValueExA(k, val, NULL, &type, (LPBYTE)out, &cb);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        out[0] = '\0';
        return 0;
    }
    out[cap - 1] = '\0';
    return 1;
}

static int reg_key_exists(HKEY root, const char *sub)
{
    HKEY k;
    if (RegOpenKeyExA(root, sub, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS)
        return 0;
    RegCloseKey(k);
    return 1;
}

/* ------------------------------------------------------------ services --- */

/* Reports "<state>/<start type>", e.g. "stopped/manual". Both wuauserv and the
 * install services are demand-start, so "stopped" on its own means nothing;
 * "disabled" is the state that actually blocks a sweep. Sets *disabled when
 * the start type is SERVICE_DISABLED. */
static void svc_state(const char *name, char *out, size_t cap, int *disabled)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS_PROCESS ssp;
    BYTE  cfgbuf[8192];
    LPQUERY_SERVICE_CONFIGA cfg = (LPQUERY_SERVICE_CONFIGA)cfgbuf;
    DWORD need = 0;
    const char *st = "unknown";
    const char *start = "?";

    if (disabled) *disabled = 0;
    strncpy(out, "unavailable", cap - 1);
    out[cap - 1] = '\0';

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return;
    svc = OpenServiceA(scm, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!svc) { CloseServiceHandle(scm); return; }

    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &need)) {
        switch (ssp.dwCurrentState) {
        case SERVICE_STOPPED:          st = "stopped"; break;
        case SERVICE_START_PENDING:    st = "starting"; break;
        case SERVICE_STOP_PENDING:     st = "stopping"; break;
        case SERVICE_RUNNING:          st = "running"; break;
        case SERVICE_PAUSED:           st = "paused"; break;
        default:                       st = "unknown"; break;
        }
    }

    if (QueryServiceConfigA(svc, cfg, sizeof(cfgbuf), &need)) {
        switch (cfg->dwStartType) {
        case SERVICE_AUTO_START:   start = "auto";     break;
        case SERVICE_DEMAND_START: start = "manual";   break;
        case SERVICE_DISABLED:     start = "disabled";
                                   if (disabled) *disabled = 1; break;
        case SERVICE_BOOT_START:   start = "boot";     break;
        case SERVICE_SYSTEM_START: start = "system";   break;
        default: break;
        }
    }

    _snprintf(out, cap, "%s/%s", st, start);
    out[cap - 1] = '\0';

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

/* ---------------------------------------------------------- elevation ---- */

int pf_is_elevated(void)
{
    HANDLE tok = NULL;
    TOKEN_ELEVATION e;
    DWORD n = 0;
    int elevated = 0;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &n))
            elevated = e.TokenIsElevated ? 1 : 0;
        CloseHandle(tok);
    }
    return elevated;
}

/* ------------------------------------------------------------- version --- */

typedef struct {
    DWORD       build;
    const char *client;
    const char *server;
    int         recommended;
    const char *note;
} build_row;

/* The "recommended" flag marks builds where PnP/WU driver acquisition is
 * historically most productive for this kind of sweep: the two original
 * Threshold releases (huge legacy driver catalogue still offered, very
 * permissive matching), the Server 2016 LTSC line, and the two current
 * Windows 11 releases (largest live catalogue). */
static const build_row g_builds[] = {
    { 10240, "Windows 10 1507 (TH1)",  "Windows Server 2016 TP (TH1)", 1,
      "Threshold 1: very large legacy driver catalogue, permissive matching" },
    { 10586, "Windows 10 1511 (TH2)",  "Windows Server 2016 TP4 (TH2)", 1,
      "Threshold 2: same catalogue behaviour as 1507" },
    { 14393, "Windows 10 1607",        "Windows Server 2016",           1,
      "Server 2016 LTSC: long-tail vendor packages still published here" },
    { 15063, "Windows 10 1703",        "Windows Server 1703",           0, NULL },
    { 16299, "Windows 10 1709",        "Windows Server 1709",           0, NULL },
    { 17134, "Windows 10 1803",        "Windows Server 1803",           0, NULL },
    { 17763, "Windows 10 1809",        "Windows Server 2019",           0, NULL },
    { 18362, "Windows 10 1903",        "Windows Server 1903",           0, NULL },
    { 18363, "Windows 10 1909",        "Windows Server 1909",           0, NULL },
    { 19041, "Windows 10 2004",        "Windows Server 2004",           0, NULL },
    { 19042, "Windows 10 20H2",        "Windows Server 20H2",           0, NULL },
    { 19043, "Windows 10 21H1",        NULL,                            0, NULL },
    { 19044, "Windows 10 21H2",        NULL,                            0, NULL },
    { 19045, "Windows 10 22H2",        NULL,                            0, NULL },
    { 20348, NULL,                     "Windows Server 2022",           0, NULL },
    { 22000, "Windows 11 21H2",        NULL,                            0, NULL },
    { 22621, "Windows 11 22H2",        NULL,                            0, NULL },
    { 22631, "Windows 11 23H2",        NULL,                            0, NULL },
    { 25398, NULL,                     "Windows Server 23H2",           0, NULL },
    { 26100, "Windows 11 24H2",        "Windows Server 2025",           1,
      "Current servicing branch: largest live Windows Update driver catalogue" },
    { 26200, "Windows 11 25H2",        NULL,                            1,
      "Current servicing branch: largest live Windows Update driver catalogue" },
    { 0, NULL, NULL, 0, NULL }
};

typedef LONG (WINAPI *RtlGetVersion_t)(PRTL_OSVERSIONINFOEXW);

static void get_real_version(sysinfo_t *si)
{
    HMODULE nt;
    RtlGetVersion_t fn;
    RTL_OSVERSIONINFOEXW vi;

    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);

    nt = GetModuleHandleW(L"ntdll.dll");
    fn = nt ? (RtlGetVersion_t)GetProcAddress(nt, "RtlGetVersion") : NULL;
    if (fn && fn(&vi) == 0) {
        si->major     = vi.dwMajorVersion;
        si->minor     = vi.dwMinorVersion;
        si->build     = vi.dwBuildNumber;
        si->is_server = (vi.wProductType != VER_NT_WORKSTATION);
    }
}

static void get_arch(sysinfo_t *si)
{
    SYSTEM_INFO sinf;
    GetNativeSystemInfo(&sinf);
    switch (sinf.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: strcpy(si->arch, "AMD64"); break;
    case PROCESSOR_ARCHITECTURE_INTEL: strcpy(si->arch, "x86");   break;
    case 12 /* ARM64 */:               strcpy(si->arch, "ARM64"); break;
    case PROCESSOR_ARCHITECTURE_ARM:   strcpy(si->arch, "ARM");   break;
    default:                           strcpy(si->arch, "?");     break;
    }
}

static int check_metered(void)
{
    PF_INetworkCostManager *ncm = NULL;
    DWORD cost = 0;
    HRESULT hr;
    int result = -1;

    hr = CoCreateInstance(&PF_CLSID_NetworkListManager, NULL, CLSCTX_ALL,
                          &PF_IID_INetworkCostManager, (void **)&ncm);
    if (FAILED(hr) || !ncm) return -1;

    if (SUCCEEDED(ncm->lpVtbl->GetCost(ncm, &cost, NULL))) {
        if (cost == PF_NLM_COST_UNKNOWN)              result = -1;
        else if (cost & PF_NLM_COST_UNRESTRICTED)     result = 0;
        else                                          result = 1;
    }
    ncm->lpVtbl->Release(ncm);
    return result;
}

/* ------------------------------------------------------------- collect --- */

void sysinfo_collect(sysinfo_t *si)
{
    const build_row *row;
    int i, tmp;
    char disp[64] = {0};
    char product[128] = {0};

    memset(si, 0, sizeof(*si));
    si->search_order_config = -1;
    si->exclude_wu_drivers  = -1;
    si->prevent_metadata    = -1;
    si->dual_scan_disabled  = -1;
    si->metered             = -1;

    get_real_version(si);
    get_arch(si);
    si->elevated = pf_is_elevated();

    reg_dword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
              "UBR", &tmp);
    si->ubr = (tmp > 0) ? (DWORD)tmp : 0;

    reg_str(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "DisplayVersion", disp, sizeof(disp));
    reg_str(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "ProductName", product, sizeof(product));
    reg_str(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "EditionID", si->edition, sizeof(si->edition));

    /* Friendly name: prefer the build table (it knows 24H2 vs 25H2 exactly),
     * fall back to the registry strings. */
    si->friendly[0] = '\0';
    for (i = 0; g_builds[i].build; i++) {
        row = &g_builds[i];
        if (row->build != si->build) continue;
        {
            const char *name = si->is_server ? row->server : row->client;
            if (!name) name = si->is_server ? row->client : row->server;
            if (name) {
                strncpy(si->friendly, name, sizeof(si->friendly) - 1);
                si->friendly[sizeof(si->friendly) - 1] = '\0';
            }
        }
        si->recommended = row->recommended;
        if (row->recommended && row->note) {
            _snprintf(si->suitability, sizeof(si->suitability),
                      "RECOMMENDED - %s", row->note);
        }
        break;
    }
    if (!si->friendly[0]) {
        if (product[0] && disp[0])
            _snprintf(si->friendly, sizeof(si->friendly), "%s %s", product, disp);
        else if (product[0])
            _snprintf(si->friendly, sizeof(si->friendly), "%s", product);
        else
            _snprintf(si->friendly, sizeof(si->friendly), "Windows %lu.%lu build %lu",
                      (unsigned long)si->major, (unsigned long)si->minor,
                      (unsigned long)si->build);
    }
    si->friendly[sizeof(si->friendly) - 1] = '\0';

    if (!si->suitability[0]) {
        _snprintf(si->suitability, sizeof(si->suitability),
                  "NOT on the high-yield list - expect fewer Windows Update hits "
                  "than on 1507/1511, Server 2016, or Windows 11 24H2/25H2");
    }
    si->suitability[sizeof(si->suitability) - 1] = '\0';

    svc_state("wuauserv",      si->wuauserv,    sizeof(si->wuauserv), &si->wu_disabled);
    svc_state("DeviceInstall", si->dsmsvc,      sizeof(si->dsmsvc),      NULL);
    svc_state("DsmSvc",        si->devsetupmgr, sizeof(si->devsetupmgr), NULL);

    reg_dword(HKEY_LOCAL_MACHINE,
              "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching",
              "SearchOrderConfig", &si->search_order_config);
    reg_dword(HKEY_LOCAL_MACHINE,
              "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
              "ExcludeWUDriversInQualityUpdate", &si->exclude_wu_drivers);
    reg_dword(HKEY_LOCAL_MACHINE,
              "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Device Metadata",
              "PreventDeviceMetadataFromNetwork", &si->prevent_metadata);
    reg_dword(HKEY_LOCAL_MACHINE,
              "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
              "DisableDualScan", &si->dual_scan_disabled);
    reg_str(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
            "WUServer", si->wsus_server, sizeof(si->wsus_server));

    si->device_install_restricted = reg_key_exists(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions");

    /* A policy that outright forbids the WU driver search. */
    {
        int dont = -1;
        reg_dword(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Policies\\Microsoft\\Windows\\DriverSearching",
                  "DontSearchWindowsUpdate", &dont);
        if (dont == 1 && si->search_order_config != 0)
            si->search_order_config = 0;
    }

    si->metered = check_metered();

    si->blockers = 0;
    if (si->wsus_server[0])            si->blockers++;
    if (si->search_order_config == 0)  si->blockers++;
    if (si->exclude_wu_drivers == 1)   si->blockers++;
    if (si->wu_disabled)               si->blockers++;
}

/* -------------------------------------------------------------- report --- */

void sysinfo_report(const sysinfo_t *si, int no_wu)
{
    log_console(PF_INFO, "OS          : %s (%lu.%lu.%lu.%lu) %s %s",
                si->friendly,
                (unsigned long)si->major, (unsigned long)si->minor,
                (unsigned long)si->build, (unsigned long)si->ubr,
                si->arch, si->is_server ? "Server" : "Client");
    if (si->edition[0])
        log_console(PF_INFO, "Edition     : %s", si->edition);

    log_console(si->recommended ? PF_GOOD : PF_WARN, "Suitability : %s", si->suitability);
    if (!si->recommended) {
        log_console(PF_WARN, "              A driver package is published per OS version and "
                             "architecture.");
        log_console(PF_WARN, "              An exact VID/PID match can still return nothing here "
                             "if the vendor");
        log_console(PF_WARN, "              certified it for a different build. Highest yield: "
                             "Win10 1507/1511 x64,");
        log_console(PF_WARN, "              Windows Server 2016 x64, Win11 24H2, Win11 25H2.");
    }
    if (strcmp(si->arch, "AMD64") != 0)
        log_console(PF_WARN, "Arch        : %s - most vendor packages target x64 only; "
                             "expect far fewer matches", si->arch);

    log_console(si->elevated ? PF_INFO : PF_ERR, "Elevation   : %s",
                si->elevated ? "Administrator" : "NOT ELEVATED (device creation will fail)");

    log_console(si->wu_disabled ? PF_ERR : PF_INFO, "wuauserv    : %s%s",
                si->wuauserv,
                si->wu_disabled ? "  <- DISABLED, no Windows Update search is possible" : "");
    /* Both are demand-start and normally sit stopped; they are what actually
     * performs the install after CM_Setup_DevNode, so record their state. */
    log_console(PF_INFO, "DeviceInstall: %s   DsmSvc: %s (both demand-start; "
                         "stopped is normal)", si->dsmsvc, si->devsetupmgr);

    if (si->search_order_config == 0)
        log_console(PF_ERR, "DriverSearching\\SearchOrderConfig = 0 -> Windows will NEVER "
                            "pull drivers from Windows Update on this host");
    else if (si->search_order_config > 0)
        log_console(PF_INFO, "SearchOrderConfig : %d (WU driver search permitted)",
                    si->search_order_config);
    else
        log_console(PF_INFO, "SearchOrderConfig : not set (default: WU driver search permitted)");

    if (si->exclude_wu_drivers == 1)
        log_console(PF_ERR, "Policy ExcludeWUDriversInQualityUpdate = 1 -> WU driver offers "
                            "are suppressed");

    if (si->wsus_server[0])
        log_console(PF_ERR, "WSUS managed: %s -> the WU driver search will query WSUS, "
                            "not Microsoft Update. Expect zero hits.", si->wsus_server);

    if (si->prevent_metadata == 1)
        log_console(PF_WARN, "PreventDeviceMetadataFromNetwork = 1 (metadata only; driver "
                             "search itself is unaffected)");

    if (si->device_install_restricted)
        log_console(PF_WARN, "Device installation restriction policies are present "
                             "(HKLM\\...\\DeviceInstall\\Restrictions) - some hardware IDs "
                             "may be blocked outright");

    if (si->metered == 1)
        log_console(PF_WARN, "Network     : METERED - Windows suppresses driver downloads on "
                             "metered links");
    else if (si->metered == 0)
        log_console(PF_INFO, "Network     : unrestricted");

    if (no_wu) {
        log_console(PF_INFO, "Windows Update query disabled (--no-wu): local DriverStore only");
    } else if (si->blockers) {
        log_console(PF_ERR, "%d environmental blocker(s) found. A zero-hit sweep here proves "
                            "nothing about the hardware IDs.", si->blockers);
    } else {
        log_console(PF_GOOD, "No environmental blockers detected");
    }
}

void sysinfo_json(const sysinfo_t *si, jb_t *b)
{
    char ver[64];
    _snprintf(ver, sizeof(ver), "%lu.%lu.%lu.%lu",
              (unsigned long)si->major, (unsigned long)si->minor,
              (unsigned long)si->build, (unsigned long)si->ubr);
    ver[sizeof(ver) - 1] = '\0';

    jb_str(b, "os_name", si->friendly);
    jb_str(b, "os_version", ver);
    jb_u64(b, "os_build", si->build);
    jb_u64(b, "os_ubr", si->ubr);
    jb_str(b, "os_edition", si->edition);
    jb_str(b, "arch", si->arch);
    jb_bool(b, "is_server", si->is_server);
    jb_bool(b, "build_recommended", si->recommended);
    jb_str(b, "suitability", si->suitability);
    jb_bool(b, "elevated", si->elevated);
    jb_str(b, "svc_wuauserv", si->wuauserv);
    jb_bool(b, "wuauserv_disabled", si->wu_disabled);
    jb_str(b, "svc_deviceinstall", si->dsmsvc);
    jb_str(b, "svc_dsmsvc", si->devsetupmgr);
    jb_num(b, "search_order_config", si->search_order_config);
    jb_num(b, "exclude_wu_drivers", si->exclude_wu_drivers);
    jb_num(b, "prevent_device_metadata", si->prevent_metadata);
    jb_num(b, "disable_dual_scan", si->dual_scan_disabled);
    jb_str(b, "wsus_server", si->wsus_server);
    jb_bool(b, "device_install_restrictions", si->device_install_restricted);
    jb_num(b, "metered", si->metered);
    jb_num(b, "environment_blockers", si->blockers);
}
