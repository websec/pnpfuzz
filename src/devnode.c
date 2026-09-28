/*
 * devnode.c - synthetic PnP device nodes
 *
 * Technique from pnp_simulate.c (DEF CON 34, "Plug and Pwn"): create a
 * ROOT-enumerated devnode carrying a chosen USB hardware ID and let the PnP
 * manager react to it exactly as it would to a real enumerated PDO.
 *
 * Two differences from the published PoC:
 *
 *  1. The DriverStore probe is non-destructive. The PoC calls DiInstallDevice
 *     to find out whether a local driver matches, which actually installs it.
 *     Here SetupDiBuildDriverInfoList(SPDIT_COMPATDRIVER) asks the same
 *     question and installs nothing, which also yields the INF path, the
 *     driver rank, and exactly which of our IDs matched.
 *
 *  2. One node carries many hardware IDs. SPDRP_HARDWAREID is a REG_MULTI_SZ
 *     and Windows matches against every entry, so a batch of candidate IDs can
 *     be probed with one node and one Windows Update round trip. Attribution
 *     survives because both the SetupAPI driver detail and the WU update carry
 *     the specific ID that matched.
 *
 * Every node is created as ROOT\PNPFUZZ\<nnnn>, so orphan cleanup is an exact
 * prefix test rather than product-string guessing.
 */

#include "pnpfuzz.h"
#include <newdev.h>

/* CM_SETUP_DEVNODE_READY comes from cfgmgr32.h (via pnpfuzz.h). Deliberately
 * no #ifndef fallback here: the value in the published PoC's fallback is
 * CM_SETUP_DOWNLOAD, so a fallback that ever fired would silently perform the
 * wrong operation instead of failing to build. */

static const GUID PF_GUID_NULL = { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };

/* {4D36E97E-E325-11CE-BFC1-08002BE10318} - GUID_DEVCLASS_UNKNOWN, declared
 * here rather than pulling in devguid.h + uuid.lib. Used only as a fallback if
 * a null class GUID is rejected. */
static const GUID PF_GUID_DEVCLASS_UNKNOWN =
    { 0x4D36E97E, 0xE325, 0x11CE, { 0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18 } };

/* ------------------------------------------------------------- pf_strset ---- */

struct pf_strset {
    char **slot;
    int    cap;
    int    n;
};

static uint32_t fnv1a(const char *s)
{
    uint32_t h = 2166136261u;
    for (; *s; s++) {
        h ^= (uint32_t)(unsigned char)(*s >= 'a' && *s <= 'z' ? *s - 32 : *s);
        h *= 16777619u;
    }
    return h;
}

pf_strset *pf_strset_new(void)
{
    pf_strset *s = (pf_strset *)calloc(1, sizeof(pf_strset));
    if (!s) return NULL;
    s->cap  = 1024;
    s->slot = (char **)calloc((size_t)s->cap, sizeof(char *));
    if (!s->slot) { free(s); return NULL; }
    return s;
}

void pf_strset_free(pf_strset *s)
{
    int i;
    if (!s) return;
    for (i = 0; i < s->cap; i++) free(s->slot[i]);
    free(s->slot);
    free(s);
}

static int pf_strset_grow(pf_strset *s);

int pf_strset_add(pf_strset *s, const char *v)
{
    uint32_t h;
    int i;

    if (!s || !v || !*v) return 0;
    if (s->n * 4 >= s->cap * 3 && pf_strset_grow(s) != 0) return -1;

    h = fnv1a(v);
    for (i = 0; i < s->cap; i++) {
        int k = (int)((h + (uint32_t)i) % (uint32_t)s->cap);
        if (!s->slot[k]) {
            s->slot[k] = _strdup(v);
            if (!s->slot[k]) return -1;
            s->n++;
            return 1;
        }
        if (_stricmp(s->slot[k], v) == 0) return 0;
    }
    return -1;
}

static int pf_strset_grow(pf_strset *s)
{
    char **old = s->slot;
    int    oldcap = s->cap, i;

    s->cap *= 2;
    s->slot = (char **)calloc((size_t)s->cap, sizeof(char *));
    if (!s->slot) { s->slot = old; s->cap = oldcap; return -1; }
    s->n = 0;
    for (i = 0; i < oldcap; i++) {
        if (!old[i]) continue;
        {
            uint32_t h = fnv1a(old[i]);
            int j;
            for (j = 0; j < s->cap; j++) {
                int k = (int)((h + (uint32_t)j) % (uint32_t)s->cap);
                if (!s->slot[k]) { s->slot[k] = old[i]; s->n++; break; }
            }
        }
    }
    free(old);
    return 0;
}

int pf_strset_has(pf_strset *s, const char *v)
{
    uint32_t h;
    int i;
    if (!s || !v) return 0;
    h = fnv1a(v);
    for (i = 0; i < s->cap; i++) {
        int k = (int)((h + (uint32_t)i) % (uint32_t)s->cap);
        if (!s->slot[k]) return 0;
        if (_stricmp(s->slot[k], v) == 0) return 1;
    }
    return 0;
}

int pf_strset_count(pf_strset *s) { return s ? s->n : 0; }

/* ------------------------------------------------------------ helpers ---- */

static void w2a(const wchar_t *w, char *buf, int cap)
{
    if (!w || WideCharToMultiByte(CP_UTF8, 0, w, -1, buf, cap, NULL, NULL) <= 0)
        buf[0] = '\0';
    buf[cap - 1] = '\0';
}

/* Build a double-null-terminated wide REG_MULTI_SZ from UTF-8 ids.
 * Returns byte size including both terminators, 0 on failure. */
static DWORD build_multisz(char ids[][PF_MAX_ID], int n, wchar_t *out, int out_chars)
{
    wchar_t *p = out;
    int i;

    if (out_chars < 2) return 0;
    for (i = 0; i < n; i++) {
        int room = (int)((out + out_chars - 1) - p);
        int len;
        if (room <= 1) return 0;
        len = MultiByteToWideChar(CP_UTF8, 0, ids[i], -1, p, room);
        if (len <= 0) return 0;
        p += len;                     /* len includes the NUL */
    }
    *p = L'\0';
    return (DWORD)((p - out + 1) * sizeof(wchar_t));
}

static void fmt_version(DWORDLONG v, char *buf, size_t cap)
{
    _snprintf(buf, cap, "%u.%u.%u.%u",
              (unsigned)((v >> 48) & 0xFFFF), (unsigned)((v >> 32) & 0xFFFF),
              (unsigned)((v >> 16) & 0xFFFF), (unsigned)(v & 0xFFFF));
    buf[cap - 1] = '\0';
}

static void fmt_date(FILETIME ft, char *buf, size_t cap)
{
    SYSTEMTIME st;
    buf[0] = '\0';
    if (!ft.dwLowDateTime && !ft.dwHighDateTime) return;
    if (FileTimeToSystemTime(&ft, &st)) {
        _snprintf(buf, cap, "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
        buf[cap - 1] = '\0';
    }
}

/* Iterate a REG_MULTI_SZ of wide strings. */
#define FOR_MULTISZ(p, start) for ((p) = (start); *(p); (p) += wcslen(p) + 1)

/* -------------------------------------------------------- node lifetime -- */

static int node_copy_ids(node_t *n, char ids[][PF_MAX_ID], int n_ids,
                         char compat[][PF_MAX_ID], int n_compat)
{
    int i;

    n->ids = (char (*)[PF_MAX_ID])calloc((size_t)(n_ids > 0 ? n_ids : 1), PF_MAX_ID);
    if (!n->ids) return -1;
    for (i = 0; i < n_ids; i++) {
        strncpy(n->ids[i], ids[i], PF_MAX_ID - 1);
        n->ids[i][PF_MAX_ID - 1] = '\0';
    }
    n->n_ids = n_ids;

    if (n_compat > 0) {
        n->compat = (char (*)[PF_MAX_ID])calloc((size_t)n_compat, PF_MAX_ID);
        if (!n->compat) return -1;
        for (i = 0; i < n_compat; i++) {
            strncpy(n->compat[i], compat[i], PF_MAX_ID - 1);
            n->compat[i][PF_MAX_ID - 1] = '\0';
        }
    }
    n->n_compat = n_compat;
    return 0;
}

int node_create(node_t *n, char ids[][PF_MAX_ID], int n_ids,
                char compat[][PF_MAX_ID], int n_compat, const wchar_t *desc)
{
    wchar_t *hw_multi = NULL, *c_multi = NULL;
    DWORD    hw_size = 0, c_size = 0;
    DWORD    err;
    char     msg[256];
    jb_t     jb;
    int      rc = -1;

    memset(n, 0, sizeof(*n));
    n->set = INVALID_HANDLE_VALUE;

    if (n_ids <= 0 || n_ids > PF_MAX_BATCH) return -1;
    if (node_copy_ids(n, ids, n_ids, compat, n_compat) != 0) goto done;

    hw_multi = (wchar_t *)calloc((size_t)n_ids * PF_MAX_ID + 2, sizeof(wchar_t));
    if (!hw_multi) goto done;
    hw_size = build_multisz(ids, n_ids, hw_multi, n_ids * PF_MAX_ID + 2);
    if (!hw_size) goto done;

    if (n_compat > 0) {
        c_multi = (wchar_t *)calloc((size_t)n_compat * PF_MAX_ID + 2, sizeof(wchar_t));
        if (!c_multi) goto done;
        c_size = build_multisz(compat, n_compat, c_multi, n_compat * PF_MAX_ID + 2);
    }

    n->set = SetupDiCreateDeviceInfoList(NULL, NULL);
    if (n->set == INVALID_HANDLE_VALUE) {
        err = GetLastError();
        jb_init(&jb);
        jb_str(&jb, "api", "SetupDiCreateDeviceInfoList");
        jb_u64(&jb, "error", err);
        jb_str(&jb, "error_text", pf_win32_msg(err, msg, sizeof(msg)));
        log_event(PF_ERR, "devnode_create_failed", jb_get(&jb));
        jb_free(&jb);
        goto done;
    }

    n->data.cbSize = sizeof(n->data);
    if (!SetupDiCreateDeviceInfoW(n->set, PF_NODE_ROOT, &PF_GUID_NULL, desc, NULL,
                                  DICD_GENERATE_ID, &n->data)) {
        err = GetLastError();
        /* A null class GUID is the pattern the published PoC uses and it works
         * on the builds it was demonstrated on, but the parameter is not
         * documented as optional. Fall back to the Unknown setup class rather
         * than failing the whole run. */
        n->data.cbSize = sizeof(n->data);
        if (!SetupDiCreateDeviceInfoW(n->set, PF_NODE_ROOT, &PF_GUID_DEVCLASS_UNKNOWN,
                                      desc, NULL, DICD_GENERATE_ID, &n->data)) {
            DWORD err2 = GetLastError();
            jb_init(&jb);
            jb_str(&jb, "api", "SetupDiCreateDeviceInfoW");
            jb_u64(&jb, "error", err);
            jb_str(&jb, "error_text", pf_win32_msg(err, msg, sizeof(msg)));
            jb_u64(&jb, "fallback_error", err2);
            jb_str(&jb, "fallback_error_text", pf_win32_msg(err2, msg, sizeof(msg)));
            log_event(PF_ERR, "devnode_create_failed", jb_get(&jb));
            jb_free(&jb);
            goto done;
        }
        jb_init(&jb);
        jb_u64(&jb, "null_class_guid_error", err);
        log_event(PF_WARN, "devnode_class_guid_fallback", jb_get(&jb));
        jb_free(&jb);
    }

    if (!SetupDiSetDeviceRegistryPropertyW(n->set, &n->data, SPDRP_HARDWAREID,
                                           (const BYTE *)hw_multi, hw_size)) {
        err = GetLastError();
        jb_init(&jb);
        jb_str(&jb, "api", "SetupDiSetDeviceRegistryProperty(HARDWAREID)");
        jb_u64(&jb, "error", err);
        jb_str(&jb, "error_text", pf_win32_msg(err, msg, sizeof(msg)));
        jb_num(&jb, "id_count", n_ids);
        log_event(PF_ERR, "devnode_create_failed", jb_get(&jb));
        jb_free(&jb);
        goto done;
    }

    if (c_size) {
        if (!SetupDiSetDeviceRegistryPropertyW(n->set, &n->data, SPDRP_COMPATIBLEIDS,
                                               (const BYTE *)c_multi, c_size)) {
            err = GetLastError();
            jb_init(&jb);
            jb_str(&jb, "api", "SetupDiSetDeviceRegistryProperty(COMPATIBLEIDS)");
            jb_u64(&jb, "error", err);
            jb_str(&jb, "error_text", pf_win32_msg(err, msg, sizeof(msg)));
            log_event(PF_WARN, "devnode_compatids_failed", jb_get(&jb));
            jb_free(&jb);
        }
    }

    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, n->set, &n->data)) {
        err = GetLastError();
        jb_init(&jb);
        jb_str(&jb, "api", "SetupDiCallClassInstaller(DIF_REGISTERDEVICE)");
        jb_u64(&jb, "error", err);
        jb_str(&jb, "error_text", pf_win32_msg(err, msg, sizeof(msg)));
        log_event(PF_ERR, "devnode_create_failed", jb_get(&jb));
        jb_free(&jb);
        goto done;
    }
    n->created = 1;

    if (SetupDiGetDeviceInstanceIdW(n->set, &n->data, n->instance_id,
                                    MAX_DEVICE_ID_LEN, NULL)) {
        w2a(n->instance_id, n->instance_id_a, sizeof(n->instance_id_a));
    }

    jb_init(&jb);
    jb_str(&jb, "instance_id", n->instance_id_a);
    jb_num(&jb, "hardware_id_count", n_ids);
    jb_num(&jb, "compatible_id_count", n_compat);
    jb_str(&jb, "first_hardware_id", ids[0]);
    jb_str(&jb, "last_hardware_id", ids[n_ids - 1]);
    log_event(PF_INFO, "devnode_created", jb_get(&jb));
    jb_free(&jb);

    rc = 0;

done:
    free(hw_multi);
    free(c_multi);
    if (rc != 0) node_destroy(n);
    return rc;
}

/* Remove the node from the system and release the handle. */
void node_destroy(node_t *n)
{
    if (!n) return;

    if (n->created && n->set != INVALID_HANDLE_VALUE) {
        SP_REMOVEDEVICE_PARAMS rp;
        BOOL ok = FALSE;

        memset(&rp, 0, sizeof(rp));
        rp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        rp.ClassInstallHeader.InstallFunction = DIF_REMOVE;
        rp.Scope = DI_REMOVEDEVICE_GLOBAL;

        if (SetupDiSetClassInstallParamsW(n->set, &n->data, &rp.ClassInstallHeader,
                                          sizeof(rp)))
            ok = SetupDiCallClassInstaller(DIF_REMOVE, n->set, &n->data);

        if (!ok && n->instance_id[0]) {
            /* Fall back to a devnode-level uninstall, including the phantom
             * case where SetupAPI can no longer act on the element. */
            DEVINST inst = 0;
            if (CM_Locate_DevNodeW(&inst, n->instance_id, CM_LOCATE_DEVNODE_PHANTOM)
                == CR_SUCCESS)
                ok = (CM_Uninstall_DevNode(inst, 0) == CR_SUCCESS);
        }

        {
            jb_t jb;
            jb_init(&jb);
            jb_str(&jb, "instance_id", n->instance_id_a);
            jb_bool(&jb, "removed", ok ? 1 : 0);
            if (!ok) {
                char msg[256];
                DWORD err = GetLastError();
                jb_u64(&jb, "error", err);
                jb_str(&jb, "error_text", pf_win32_msg(err, msg, sizeof(msg)));
            }
            log_event(ok ? PF_INFO : PF_WARN, "devnode_removed", jb_get(&jb));
            jb_free(&jb);
        }
        n->created = 0;
    }

    if (n->set != INVALID_HANDLE_VALUE && n->set != NULL) {
        SetupDiDestroyDeviceInfoList(n->set);
        n->set = INVALID_HANDLE_VALUE;
    }
    free(n->ids);
    free(n->compat);
    n->ids = NULL;
    n->compat = NULL;
    n->n_ids = n->n_compat = 0;
}

/* ------------------------------------------------- DriverStore probing --- */

/* Which of our IDs does `driver_id` correspond to? Returns 1 for a hardware-ID
 * match, 2 for a compatible-ID match, 0 for neither. */
static int attribute_id(const node_t *n, const char *driver_id, char *out)
{
    int i;
    for (i = 0; i < n->n_ids; i++) {
        if (_stricmp(n->ids[i], driver_id) == 0) {
            strncpy(out, n->ids[i], PF_MAX_ID - 1);
            out[PF_MAX_ID - 1] = '\0';
            return 1;
        }
    }
    for (i = 0; i < n->n_compat; i++) {
        if (_stricmp(n->compat[i], driver_id) == 0) {
            strncpy(out, n->compat[i], PF_MAX_ID - 1);
            out[PF_MAX_ID - 1] = '\0';
            return 2;
        }
    }
    return 0;
}

static void inf_class_name(const wchar_t *inf, char *out, size_t cap)
{
    GUID    g;
    wchar_t cls[64] = {0};
    DWORD   req = 0;

    out[0] = '\0';
    if (!inf || !*inf) return;
    if (SetupDiGetINFClassW(inf, &g, cls, 64, &req))
        w2a(cls, out, (int)cap);
}

int node_probe_driverstore(node_t *n, drvmatch_t *out, int cap)
{
    SP_DEVINSTALL_PARAMS_W dip;
    SP_DRVINFO_DATA_V2_W   drv;
    DWORD i;
    int   found = 0;
    DWORD t0 = GetTickCount();

    if (!n->created || n->set == INVALID_HANDLE_VALUE) return -1;

    memset(&dip, 0, sizeof(dip));
    dip.cbSize = sizeof(dip);
    if (SetupDiGetDeviceInstallParamsW(n->set, &n->data, &dip)) {
        dip.Flags   |= DI_QUIETINSTALL;
        dip.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS;   /* include ExcludeFromSelect */
        dip.DriverPath[0] = L'\0';                     /* default INF search path   */
        SetupDiSetDeviceInstallParamsW(n->set, &n->data, &dip);
    }

    if (!SetupDiBuildDriverInfoList(n->set, &n->data, SPDIT_COMPATDRIVER)) {
        DWORD err = GetLastError();
        char  msg[256];
        jb_t  jb;
        jb_init(&jb);
        jb_str(&jb, "api", "SetupDiBuildDriverInfoList");
        jb_u64(&jb, "error", err);
        jb_str(&jb, "error_text", pf_win32_msg(err, msg, sizeof(msg)));
        jb_str(&jb, "instance_id", n->instance_id_a);
        log_event(PF_ERR, "driverstore_probe_failed", jb_get(&jb));
        jb_free(&jb);
        return -1;
    }

    memset(&drv, 0, sizeof(drv));
    drv.cbSize = sizeof(drv);

    for (i = 0; found < cap &&
         SetupDiEnumDriverInfoW(n->set, &n->data, SPDIT_COMPATDRIVER, i,
                                (PSP_DRVINFO_DATA_W)&drv); i++) {
        BYTE  detbuf[16384];
        PSP_DRVINFO_DETAIL_DATA_W det = (PSP_DRVINFO_DETAIL_DATA_W)detbuf;
        DWORD req = 0;
        BOOL  got;
        wchar_t *p;
        drvmatch_t m;
        int kind = 0;

        memset(detbuf, 0, sizeof(detbuf));
        det->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA_W);
        got = SetupDiGetDriverInfoDetailW(n->set, &n->data, (PSP_DRVINFO_DATA_W)&drv,
                                          det, sizeof(detbuf), &req);
        if (!got) {
            /* On ERROR_INSUFFICIENT_BUFFER only the fixed part is guaranteed;
             * the ID region is not guaranteed to be double-NUL terminated, so
             * walking it could run off the buffer. Record the truncation
             * instead of parsing a buffer we know is incomplete. */
            DWORD e = GetLastError();
            jb_t tj;
            jb_init(&tj);
            jb_str(&tj, "instance_id", n->instance_id_a);
            jb_u64(&tj, "error", e);
            jb_u64(&tj, "required_bytes", req);
            log_event(PF_WARN, "driverstore_detail_unavailable", jb_get(&tj));
            jb_free(&tj);
            memset(&drv, 0, sizeof(drv));
            drv.cbSize = sizeof(drv);
            continue;
        }

        memset(&m, 0, sizeof(m));

        /* SP_DRVINFO_DETAIL_DATA_W.HardwareID holds the driver node's single
         * hardware ID, then the compatible-ID MULTI_SZ at CompatIDsOffset. A
         * class-only INF section (exactly what USB\Class_xx compatible IDs are
         * meant to find) has no hardware ID at all, so both regions must be
         * checked separately. */
        if (det->CompatIDsOffset > 1) {
            char idbuf[PF_MAX_ID];
            w2a(det->HardwareID, idbuf, sizeof(idbuf));
            kind = attribute_id(n, idbuf, m.hwid);
        }
        if (!kind && det->CompatIDsLength) {
            for (p = det->HardwareID + det->CompatIDsOffset; *p; p += wcslen(p) + 1) {
                char idbuf[PF_MAX_ID];
                w2a(p, idbuf, sizeof(idbuf));
                kind = attribute_id(n, idbuf, m.hwid);
                if (kind) break;
            }
        }
        if (!kind) {
            /* Compatible on some ID we did not set. Record it rather than
             * silently dropping the match. */
            w2a(det->CompatIDsOffset > 1 ? det->HardwareID
                                         : det->HardwareID + det->CompatIDsOffset,
                m.hwid, sizeof(m.hwid));
            m.compat_only = 1;
        } else {
            m.compat_only = (kind == 2);
        }

        w2a(det->InfFileName, m.inf, sizeof(m.inf));
        w2a(det->SectionName, m.section, sizeof(m.section));
        w2a(drv.Description, m.desc, sizeof(m.desc));
        w2a(drv.MfgName, m.mfg, sizeof(m.mfg));
        w2a(drv.ProviderName, m.provider, sizeof(m.provider));
        fmt_version(drv.DriverVersion, m.version, sizeof(m.version));
        fmt_date(drv.DriverDate, m.date, sizeof(m.date));
        inf_class_name(det->InfFileName, m.cls, sizeof(m.cls));

        {
            SP_DRVINSTALL_PARAMS dp;
            memset(&dp, 0, sizeof(dp));
            dp.cbSize = sizeof(dp);
            if (SetupDiGetDriverInstallParamsW(n->set, &n->data,
                                               (PSP_DRVINFO_DATA_W)&drv, &dp))
                m.rank = dp.Rank;
            else
                m.rank = 0xFFFFFFFFu;
        }

        out[found++] = m;

        memset(&drv, 0, sizeof(drv));
        drv.cbSize = sizeof(drv);
    }

    SetupDiDestroyDriverInfoList(n->set, &n->data, SPDIT_COMPATDRIVER);

    {
        jb_t jb;
        jb_init(&jb);
        jb_str(&jb, "instance_id", n->instance_id_a);
        jb_num(&jb, "candidate_ids", n->n_ids);
        jb_num(&jb, "matches", found);
        jb_u64(&jb, "elapsed_ms", GetTickCount() - t0);
        log_event(found ? PF_GOOD : PF_DEBUG, "driverstore_probe", jb_get(&jb));
        jb_free(&jb);
    }
    return found;
}

/* ------------------------------------------------------- bound driver ---- */

static int read_reg_sz(HKEY k, const wchar_t *name, char *out, size_t cap)
{
    wchar_t buf[1024];
    DWORD   type = 0, cb = sizeof(buf);

    out[0] = '\0';
    if (RegQueryValueExW(k, name, NULL, &type, (LPBYTE)buf, &cb) != ERROR_SUCCESS)
        return 0;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return 0;
    buf[(cb / sizeof(wchar_t)) < 1024 ? (cb / sizeof(wchar_t)) : 1023] = L'\0';
    w2a(buf, out, (int)cap);
    return out[0] != '\0';
}

/* Reads the driver actually bound to an instance (after an install). */
static int read_bound_driver(const wchar_t *instance_id, drvmatch_t *out, ULONG *problem)
{
    HDEVINFO        set;
    SP_DEVINFO_DATA data;
    HKEY            k;
    int             have = 0;

    memset(out, 0, sizeof(*out));
    if (problem) *problem = 0;

    set = SetupDiCreateDeviceInfoList(NULL, NULL);
    if (set == INVALID_HANDLE_VALUE) return 0;

    memset(&data, 0, sizeof(data));
    data.cbSize = sizeof(data);
    if (!SetupDiOpenDeviceInfoW(set, instance_id, NULL, 0, &data)) {
        SetupDiDestroyDeviceInfoList(set);
        return 0;
    }

    if (problem) {
        ULONG status = 0;
        if (CM_Get_DevNode_Status(&status, problem, data.DevInst, 0) != CR_SUCCESS)
            *problem = 0;
    }

    k = SetupDiOpenDevRegKey(set, &data, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ);
    if (k != INVALID_HANDLE_VALUE) {
        have |= read_reg_sz(k, L"MatchingDeviceId", out->hwid, sizeof(out->hwid));
        read_reg_sz(k, L"DriverDesc",   out->desc,     sizeof(out->desc));
        read_reg_sz(k, L"ProviderName", out->provider, sizeof(out->provider));
        read_reg_sz(k, L"DriverVersion", out->version, sizeof(out->version));
        read_reg_sz(k, L"DriverDate",   out->date,     sizeof(out->date));
        read_reg_sz(k, L"InfPath",      out->inf,      sizeof(out->inf));
        read_reg_sz(k, L"InfSection",   out->section,  sizeof(out->section));
        read_reg_sz(k, L"MfgName",      out->mfg,      sizeof(out->mfg));
        RegCloseKey(k);
        have = 1;
    }

    {
        wchar_t cls[128] = {0};
        DWORD   type = 0, cb = sizeof(cls);
        if (SetupDiGetDeviceRegistryPropertyW(set, &data, SPDRP_CLASS, &type,
                                              (PBYTE)cls, cb, NULL))
            w2a(cls, out->cls, sizeof(out->cls));
    }

    SetupDiDestroyDeviceInfoList(set);
    return have;
}

int node_install_local(node_t *n, int *reboot_needed, drvmatch_t *out)
{
    BOOL  reboot = FALSE;
    BOOL  ok;
    DWORD err = 0;
    char  msg[256];
    jb_t  jb;

    if (reboot_needed) *reboot_needed = 0;
    if (out) memset(out, 0, sizeof(*out));
    if (!n->created) return -1;

    ok = DiInstallDevice(NULL, n->set, &n->data, NULL, 0, &reboot);
    if (!ok) err = GetLastError();

    jb_init(&jb);
    jb_str(&jb, "instance_id", n->instance_id_a);
    jb_bool(&jb, "installed", ok ? 1 : 0);
    jb_bool(&jb, "reboot_required", reboot ? 1 : 0);
    if (!ok) {
        jb_u64(&jb, "error", err);
        jb_str(&jb, "error_text", pf_win32_msg(err, msg, sizeof(msg)));
    }
    if (ok && out) {
        ULONG problem = 0;
        read_bound_driver(n->instance_id, out, &problem);
        jb_str(&jb, "matched_hardware_id", out->hwid);
        jb_str(&jb, "driver_desc", out->desc);
        jb_str(&jb, "driver_provider", out->provider);
        jb_str(&jb, "inf", out->inf);
        jb_u64(&jb, "devnode_problem", problem);
    }
    log_event(ok ? PF_GOOD : PF_DEBUG, "driverstore_install", jb_get(&jb));
    jb_free(&jb);

    if (reboot_needed) *reboot_needed = reboot ? 1 : 0;
    return ok ? 0 : -1;
}

int node_trigger_pnp_install(node_t *n)
{
    DEVINST   inst = 0;
    CONFIGRET cr;
    char      msg[256];
    jb_t      jb;

    if (!n->created || !n->instance_id[0]) return -1;

    cr = CM_Locate_DevNodeW(&inst, n->instance_id, CM_LOCATE_DEVNODE_NORMAL);
    if (cr != CR_SUCCESS) {
        jb_init(&jb);
        jb_str(&jb, "api", "CM_Locate_DevNode");
        jb_str(&jb, "instance_id", n->instance_id_a);
        jb_str(&jb, "error_text", pf_cr_msg(cr, msg, sizeof(msg)));
        log_event(PF_ERR, "pnp_install_failed", jb_get(&jb));
        jb_free(&jb);
        return -1;
    }

    cr = CM_Setup_DevNode(inst, CM_SETUP_DEVNODE_READY);

    jb_init(&jb);
    jb_str(&jb, "instance_id", n->instance_id_a);
    jb_bool(&jb, "queued", cr == CR_SUCCESS);
    jb_str(&jb, "result", pf_cr_msg(cr, msg, sizeof(msg)));
    log_event(cr == CR_SUCCESS ? PF_INFO : PF_ERR,
              cr == CR_SUCCESS ? "pnp_install_queued" : "pnp_install_failed", jb_get(&jb));
    jb_free(&jb);

    return (cr == CR_SUCCESS) ? 0 : -1;
}

int node_wait_installed(node_t *n, int timeout_s, volatile int *abort_flag,
                        drvmatch_t *out)
{
    DWORD t0 = GetTickCount();
    ULONG problem = 0;
    int   got = 0;

    if (out) memset(out, 0, sizeof(*out));
    if (!n->instance_id[0]) return -1;

    while ((int)((GetTickCount() - t0) / 1000) < timeout_s) {
        drvmatch_t m;
        if (abort_flag && *abort_flag) break;

        if (read_bound_driver(n->instance_id, &m, &problem) && m.desc[0]) {
            if (out) *out = m;
            got = 1;
            break;
        }
        Sleep(1000);
    }

    {
        jb_t jb;
        jb_init(&jb);
        jb_str(&jb, "instance_id", n->instance_id_a);
        jb_bool(&jb, "driver_bound", got);
        jb_u64(&jb, "waited_ms", GetTickCount() - t0);
        jb_u64(&jb, "devnode_problem", problem);
        if (got && out) {
            jb_str(&jb, "matched_hardware_id", out->hwid);
            jb_str(&jb, "driver_desc", out->desc);
            jb_str(&jb, "driver_provider", out->provider);
            jb_str(&jb, "driver_version", out->version);
            jb_str(&jb, "inf", out->inf);
            jb_str(&jb, "class", out->cls);
        }
        log_event(got ? PF_GOOD : PF_INFO, "pnp_install_result", jb_get(&jb));
        jb_free(&jb);
    }
    return got ? 0 : -1;
}

/* ------------------------------------------------------------- cleanup --- */

static int uninstall_instance(const wchar_t *instance_id)
{
    HDEVINFO        set;
    SP_DEVINFO_DATA data;
    int             removed = 0;

    set = SetupDiCreateDeviceInfoList(NULL, NULL);
    if (set == INVALID_HANDLE_VALUE) return 0;

    memset(&data, 0, sizeof(data));
    data.cbSize = sizeof(data);

    if (SetupDiOpenDeviceInfoW(set, instance_id, NULL, 0, &data)) {
        ULONG status = 0, problem = 0;
        int present = (CM_Get_DevNode_Status(&status, &problem, data.DevInst, 0) == CR_SUCCESS);

        if (present) {
            BOOL need = FALSE;
            if (DiUninstallDevice(NULL, set, &data, 0, &need)) {
                removed = 1;
            } else {
                SP_REMOVEDEVICE_PARAMS rp;
                memset(&rp, 0, sizeof(rp));
                rp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
                rp.ClassInstallHeader.InstallFunction = DIF_REMOVE;
                rp.Scope = DI_REMOVEDEVICE_GLOBAL;
                if (SetupDiSetClassInstallParamsW(set, &data, &rp.ClassInstallHeader,
                                                  sizeof(rp)) &&
                    SetupDiCallClassInstaller(DIF_REMOVE, set, &data))
                    removed = 1;
            }
            CM_Uninstall_DevNode(data.DevInst, 0);   /* purge whatever is left */
        } else {
            removed = (CM_Uninstall_DevNode(data.DevInst, 0) == CR_SUCCESS);
        }
    } else {
        DEVINST inst = 0;
        if (CM_Locate_DevNodeW(&inst, (DEVINSTID_W)instance_id,
                               CM_LOCATE_DEVNODE_PHANTOM) == CR_SUCCESS)
            removed = (CM_Uninstall_DevNode(inst, 0) == CR_SUCCESS);
    }

    SetupDiDestroyDeviceInfoList(set);
    return removed;
}

int pf_cleanup_orphans(int dry_run, int *found_out, int *removed_out)
{
    HDEVINFO        set;
    SP_DEVINFO_DATA data;
    DWORD           idx;
    int             found = 0, removed = 0;
    int             pass;

    if (found_out)   *found_out = 0;
    if (removed_out) *removed_out = 0;

    /* Two passes: uninstalling a parent can turn children into removable
     * phantoms that only the second pass can reach. */
    for (pass = 0; pass < 2; pass++) {
        int pass_found = 0;

        /* No DIGCF_PRESENT, so non-present ("ghost") nodes are included. */
        set = SetupDiGetClassDevsW(NULL, L"ROOT", NULL, DIGCF_ALLCLASSES);
        if (set == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            char  msg[256];
            jb_t  jb;
            jb_init(&jb);
            jb_str(&jb, "api", "SetupDiGetClassDevs(ROOT)");
            jb_u64(&jb, "error", err);
            jb_str(&jb, "error_text", pf_win32_msg(err, msg, sizeof(msg)));
            log_event(PF_ERR, "cleanup_failed", jb_get(&jb));
            jb_free(&jb);
            return -1;
        }

        memset(&data, 0, sizeof(data));
        data.cbSize = sizeof(data);

        for (idx = 0; SetupDiEnumDeviceInfo(set, idx, &data); idx++) {
            wchar_t id[MAX_DEVICE_ID_LEN] = {0};
            char    id_a[MAX_DEVICE_ID_LEN];

            if (!SetupDiGetDeviceInstanceIdW(set, &data, id, MAX_DEVICE_ID_LEN, NULL))
                continue;
            if (_wcsnicmp(id, PF_NODE_PREFIX, wcslen(PF_NODE_PREFIX)) != 0)
                continue;

            w2a(id, id_a, sizeof(id_a));
            pass_found++;
            /* Count every node seen on any pass. Pass 1 exists to reach nodes
             * pass 0 could not see, so counting only pass 0 could report more
             * removed than found. */
            found++;

            if (dry_run) {
                jb_t jb;
                log_console(PF_INFO, "would remove: %s", id_a);
                jb_init(&jb);
                jb_str(&jb, "instance_id", id_a);
                log_event(PF_INFO, "cleanup_candidate", jb_get(&jb));
                jb_free(&jb);
                continue;
            }

            if (uninstall_instance(id)) {
                jb_t jb;
                removed++;
                jb_init(&jb);
                jb_str(&jb, "instance_id", id_a);
                log_event(PF_INFO, "cleanup_removed", jb_get(&jb));
                jb_free(&jb);
            } else {
                jb_t jb;
                char msg[256];
                DWORD err = GetLastError();
                jb_init(&jb);
                jb_str(&jb, "instance_id", id_a);
                jb_u64(&jb, "error", err);
                jb_str(&jb, "error_text", pf_win32_msg(err, msg, sizeof(msg)));
                log_event(PF_WARN, "cleanup_remove_failed", jb_get(&jb));
                jb_free(&jb);
            }

            memset(&data, 0, sizeof(data));
            data.cbSize = sizeof(data);
        }

        SetupDiDestroyDeviceInfoList(set);

        if (dry_run || pass_found == 0) break;
    }

    if (found_out)   *found_out = found;
    if (removed_out) *removed_out = removed;

    {
        jb_t jb;
        jb_init(&jb);
        jb_bool(&jb, "dry_run", dry_run);
        jb_num(&jb, "found", found);
        jb_num(&jb, "removed", removed);
        log_event(PF_INFO, "cleanup_done", jb_get(&jb));
        jb_free(&jb);
    }
    return 0;
}

/* --------------------------------------------------- present-ID harvest -- */

int collect_present_bus_ids(pf_strset *s, const char *enumerator)
{
    HDEVINFO        set;
    SP_DEVINFO_DATA data;
    DWORD           idx;
    int             n = 0;
    wchar_t         wenum[32];
    int             i;

    /* The enumerator name is an internal constant ("USB" / "PCI"), so a plain
     * widening is sufficient and avoids pulling a converter in here. */
    if (!enumerator || !*enumerator) enumerator = "USB";
    for (i = 0; enumerator[i] && i < (int)(sizeof(wenum)/sizeof(wenum[0])) - 1; i++)
        wenum[i] = (wchar_t)(unsigned char)enumerator[i];
    wenum[i] = L'\0';

    set = SetupDiGetClassDevsW(NULL, wenum, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) return -1;

    memset(&data, 0, sizeof(data));
    data.cbSize = sizeof(data);

    for (idx = 0; SetupDiEnumDeviceInfo(set, idx, &data); idx++) {
        BYTE     buf[4096];
        DWORD    type = 0, cb = 0;
        wchar_t *p;

        memset(buf, 0, sizeof(buf));
        if (SetupDiGetDeviceRegistryPropertyW(set, &data, SPDRP_HARDWAREID, &type,
                                              buf, sizeof(buf) - 2 * sizeof(wchar_t), &cb)) {
            FOR_MULTISZ(p, (wchar_t *)buf) {
                char id[PF_MAX_ID];
                w2a(p, id, sizeof(id));
                if (id[0] && pf_strset_add(s, id) == 1) n++;
            }
        }
        memset(&data, 0, sizeof(data));
        data.cbSize = sizeof(data);
    }

    SetupDiDestroyDeviceInfoList(set);
    return n;
}
