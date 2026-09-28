/*
 * pnpfuzz - PnP driver-acquisition fuzzer for Windows
 *
 * Author: Joel Aviad Ossi, WebSec B.V.
 *
 * Hardware-free driver acquisition, done entirely in software. The tool
 * sweeps a user-defined
 * VID/PID(/REV/MI/class/subclass/protocol) space by synthesising USB device
 * identities directly in the Windows PnP manager and asking Windows which
 * driver it would fetch for each one, from the local DriverStore and from
 * Windows Update.
 *
 * The underlying single-device auto-install primitive - create a synthetic
 * device node so the PnP manager and Windows Update react as if the hardware
 * were physically plugged in - was published at DEF CON 34 (2026) in
 * "Plug and Pwn: Weaponizing Windows PnP Auto-Install" by Alejandro Hernando
 * and Borja Martinez (pnp_simulate.c). That research is the primitive this
 * builds on. pnpfuzz is a distinct, original tool: a batched, resumable,
 * coverage-checked fuzzer over the identity space, not a single-device PoC.
 *
 * For authorised security research only. Requires Administrator.
 */

#ifndef PNPFUZZ_H
#define PNPFUZZ_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <setupapi.h>    /* HDEVINFO, SP_DEVINFO_DATA                        */
#include <cfgmgr32.h>    /* MAX_DEVICE_ID_LEN, CONFIGRET, CM_NOTIFY_*        */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define PF_VERSION          "2.12.1"
#define PF_AUTHOR           "Joel Aviad Ossi, WebSec B.V."

/* Device-instance tagging. Every node we create is ROOT\PNPFUZZ\<nnnn>, which
 * makes orphan cleanup an exact prefix test instead of a heuristic. */
#define PF_NODE_ROOT        L"PNPFUZZ"
#define PF_NODE_PREFIX      L"ROOT\\PNPFUZZ\\"
#define PF_NODE_PREFIX_A    "ROOT\\PNPFUZZ\\"

#define PF_MAX_ID           192     /* chars in one hardware/compatible ID   */
#define PF_MAX_BATCH        8192    /* hardware IDs on a single probe node    */
#define PF_MAX_COMPAT       8
#define PF_MAX_AXIS_VALUES  0x10000

/* Auto batch-tuning defaults. Calibration probes upward to the largest batch
 * width Windows Update still answers losslessly on this host. */
#define PF_AUTO_BATCH_MAX   4096    /* ceiling calibration will probe to      */
#define PF_AUTO_BATCH_FLOOR 16      /* width halving will never drop below    */
/* Starting width in auto mode when there is no reference to calibrate against
 * yet. Without a reference no canary can be injected, so this width is
 * UNVERIFIED either way - running it at the halving floor bought no safety and
 * cost an order of magnitude in speed. */
#define PF_AUTO_BATCH_START 512

/* Canary sanity floor. A VALID canary is seen at some workable width; if the
 * width has been halved below this and the canary has STILL never come back, the
 * canary is not a valid detector for this search space (typically a different
 * vendor than the sweep, so it is crowded out of every populated batch). Rather
 * than ratchet on to width 1 and grind one ID per search for hours, the sweep
 * gives up on that canary, resets to a healthy width and continues without
 * truncation detection (loudly warned). */
#define PF_CANARY_GIVEUP_WIDTH  64

/* Smallest width the tool will TRUST from a cache or checkpoint without
 * re-measuring it. A width this low is almost never a real Windows Update
 * limit - it is the residue of a runtime collapse (a bad canary, or a WU
 * outage that made every batch look truncated). Riding it would silently
 * inherit a previous run's damage and crawl for hours, so a width below this,
 * or any width that was produced by halving rather than by a full calibration,
 * is re-measured from scratch on the next run and the cache repaired. */
#define PF_WIDTH_TRUST_MIN      64

/* Bounded retries for a Windows Update search that does not complete (timeout or
 * BUSY). A transient WU stall on a long run should not kill the whole sweep, but
 * an endlessly wedged WU must not spin forever either. */
#define PF_WU_RETRY_MAX         3

/* ------------------------------------------------------------------ log --- */

typedef enum {
    PF_DEBUG = 0,
    PF_INFO,
    PF_GOOD,
    PF_WARN,
    PF_ERR
} pf_level;

/* Console + JSONL event stream + CSV hit table. Every JSONL record carries an
 * ISO-8601 timestamp, a monotonic offset, the event name and its detail, so a
 * run can be reconstructed exactly after the fact. */
int         log_open(const char *dir, const char *run_id);
void        log_close(void);
const char *log_dir_path(void);
const char *log_run_id(void);

void log_console(pf_level lvl, const char *fmt, ...);

/* Structured event. `fields` is raw JSON (no braces) appended to the record,
 * or NULL. Use jb_* below to build it. */
void log_event(pf_level lvl, const char *event, const char *fields);

void log_hit_csv(const char *hwid, const char *source, const char *match_kind,
                 const char *provider, const char *desc, const char *cls,
                 const char *version, const char *inf, const char *extra);

/* Small append-only JSON field builder. */
typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} jb_t;

void        jb_init(jb_t *b);
void        jb_free(jb_t *b);
void        jb_str(jb_t *b, const char *key, const char *val);
void        jb_wstr(jb_t *b, const char *key, const wchar_t *val);
void        jb_num(jb_t *b, const char *key, double v);
void        jb_u64(jb_t *b, const char *key, unsigned long long v);
void        jb_bool(jb_t *b, const char *key, int v);
void        jb_raw(jb_t *b, const char *key, const char *raw_json);
const char *jb_get(jb_t *b);

/* Decode a Win32 error / HRESULT / CONFIGRET into readable text. Returns buf. */
char *pf_win32_msg(DWORD code, char *buf, size_t cap);
char *pf_cr_msg(DWORD cr, char *buf, size_t cap);

/* ------------------------------------------------------------- sysinfo --- */

typedef struct {
    DWORD major, minor, build, ubr;
    int   is_server;
    char  arch[16];             /* AMD64 / ARM64 / x86                       */
    char  friendly[96];         /* "Windows 11 24H2"                         */
    char  edition[64];
    int   recommended;          /* on the high-yield build list              */
    char  suitability[256];

    /* Everything below answers "why did my sweep return zero hits?" */
    int   elevated;
    char  wuauserv[32];
    char  dsmsvc[32];           /* DeviceInstall - the Device Install Service */
    char  devsetupmgr[32];      /* DsmSvc        - Device Setup Manager       */
    int   wu_disabled;          /* wuauserv start type is SERVICE_DISABLED    */
    int   search_order_config;      /* -1 unset. 0 = never use WU            */
    int   exclude_wu_drivers;       /* -1 unset. 1 = WU drivers suppressed   */
    int   prevent_metadata;         /* -1 unset                              */
    char  wsus_server[256];         /* non-empty => WU driver search is dead  */
    int   dual_scan_disabled;       /* -1 unset                              */
    int   device_install_restricted;
    int   metered;                  /* -1 unknown                            */
    int   blockers;                 /* count of hard blockers found          */
} sysinfo_t;

void sysinfo_collect(sysinfo_t *si);
void sysinfo_report(const sysinfo_t *si, int no_wu);
void sysinfo_json(const sysinfo_t *si, jb_t *b);
int  pf_is_elevated(void);

/* ---------------------------------------------------------------- hwid --- */

typedef struct {
    uint32_t *v;
    int       n;
    int       given;            /* axis was supplied on the command line     */
} axis_t;

/* Which bus the synthesised identity belongs to. The PnP primitive itself is
 * bus-agnostic: a hardware ID is just a string the PnP manager matches against
 * INF models sections, so the only thing that changes between buses is the
 * shape of that string. PCI enumerates on VEN/DEV exactly as USB does on
 * VID/PID, with SUBSYS and a CC class code in place of USB's interface and
 * class triplet. */
typedef enum {
    PF_BUS_USB = 0,
    PF_BUS_PCI
} pf_bus;

typedef struct {
    axis_t   vid, pid, rev, mi, cls, sub, prot;
    axis_t   subsys;            /* PCI only: SUBSYS_ssssssss (32-bit)        */
    pf_bus   bus;
    int      with_plain;        /* also emit the bare VID&PID / VEN&DEV form */
    uint64_t total;
} space_t;

const char *pf_bus_name(pf_bus b);      /* "USB" / "PCI"                     */
const char *pf_bus_enumerator(pf_bus b);/* SetupAPI enumerator filter        */

/* One point in the search space, expanded to concrete IDs. */
typedef struct {
    uint64_t index;
    unsigned vid, pid, rev, mi, cls, sub, prot;
    unsigned subsys;                /* PCI SUBSYS_ssssssss                   */
    char     ids[4][PF_MAX_ID];     /* hardware IDs for this combination     */
    int      n_ids;
    char     compat[PF_MAX_COMPAT][PF_MAX_ID];
    int      n_compat;
    char     label[PF_MAX_ID];      /* primary ID, used for reporting        */
} combo_t;

/* Parse "046D", "0x046D", "0000-FFFF", "1,2,A-F", "*". Values are HEX always,
 * so `10` is 0x10 and never decimal. Returns 0
 * on success, -1 on a malformed spec. */
int  axis_parse(axis_t *a, const char *spec, uint32_t max, const char *name);
void axis_single(axis_t *a, uint32_t value);
void axis_free(axis_t *a);

int      space_finalise(space_t *sp, char *err, size_t errcap);
uint64_t space_total(const space_t *sp);
void     space_at(const space_t *sp, uint64_t index, combo_t *out);
void     space_free(space_t *sp);

/* ------------------------------------------------------------- devnode --- */

typedef struct {
    char     hwid[PF_MAX_ID];       /* which of our IDs the driver matched   */
    char     inf[MAX_PATH];
    char     section[128];
    char     desc[256];
    char     mfg[128];
    char     provider[128];
    char     version[64];
    char     date[32];
    char     cls[64];
    DWORD    rank;                  /* lower is a better match               */
    int      compat_only;           /* matched a compatible ID, not VID/PID  */
} drvmatch_t;

typedef struct {
    HDEVINFO        set;
    SP_DEVINFO_DATA data;
    wchar_t         instance_id[MAX_DEVICE_ID_LEN];
    char            instance_id_a[MAX_DEVICE_ID_LEN];
    int             created;        /* DIF_REGISTERDEVICE succeeded */
    /* Copies of the IDs this node carries, used to attribute matches. */
    char          (*ids)[PF_MAX_ID];
    int             n_ids;
    char          (*compat)[PF_MAX_ID];
    int             n_compat;
} node_t;

int  node_create(node_t *n, char ids[][PF_MAX_ID], int n_ids,
                 char compat[][PF_MAX_ID], int n_compat, const wchar_t *desc);
void node_destroy(node_t *n);

/* Non-destructive: asks SetupAPI which INFs would match, installs nothing. */
int  node_probe_driverstore(node_t *n, drvmatch_t *out, int cap);

/* Destructive: DiInstallDevice (local DriverStore) */
int  node_install_local(node_t *n, int *reboot_needed, drvmatch_t *out);

/* Destructive: CM_Setup_DevNode(READY) -> Device Install Service -> WU */
int  node_trigger_pnp_install(node_t *n);

/* Poll until the node has a driver bound or the timeout expires. */
int  node_wait_installed(node_t *n, int timeout_s, volatile int *abort_flag,
                         drvmatch_t *out);

int  pf_cleanup_orphans(int dry_run, int *found, int *removed);

/* Present-hardware exclusion set, so we never probe an ID that already exists
 * on this host (a real device, or a node left by an earlier run). */
typedef struct pf_strset pf_strset;
pf_strset *pf_strset_new(void);
void    pf_strset_free(pf_strset *s);
int     pf_strset_add(pf_strset *s, const char *v);
int     pf_strset_has(pf_strset *s, const char *v);
int     pf_strset_count(pf_strset *s);
/* Present-hardware IDs for one bus enumerator ("USB", "PCI"). */
int     collect_present_bus_ids(pf_strset *s, const char *enumerator);

/* --------------------------------------------------------------- watch --- */

typedef struct {
    char  type[48];
    char  instance[MAX_DEVICE_ID_LEN];
    DWORD t_ms;
    int   ours;
} pnpev_t;

int  watch_start(int log_all);
void watch_stop(void);
int  watch_take(pnpev_t *out, int cap);   /* drain, returns count */
void watch_mark(void);                    /* reset the "since" cursor */

/* -------------------------------------------------------------- vendor --- */

/* Recon on the vendor ID itself, before any sweeping: who owns it, are they a
 * Windows hardware publisher, and do they have certified drivers. Answers
 * "is a sweep of this vendor even likely to find anything" up front, and
 * distinguishes a dormant ID from a silicon vendor whose customers publish the
 * drivers under their own name. Public endpoints only, read-only. */
/* One publisher account in the partner directory. A name prefix routinely
 * matches several: "raytheon" returns Raytheon Company, Raytheon Anschuetz GmbH
 * and Raytheon Technologies, which are separate accounts with separate driver
 * catalogues. Guessing one would silently hide the others. */
#define PF_CPL_MAX_ACCOUNTS 12

typedef struct {
    char account_id[32];
    char publisher[256];
    int  score;                     /* name-similarity to the DeviceHunt name */
    int  selected;                  /* enumerated in this run                 */
    int  n_products;                /* submissions found for this account     */
} cpl_account_t;

typedef struct {
    char submission_id[40];
    char account_id[32];            /* which publisher it belongs to          */
    char product_name[256];
    char os_codes[512];
    int  declarative;
    int  universal;
} cpl_product_t;

typedef struct {
    int   dh_found;                 /* the vendor ID resolved to a company    */
    int   from_local;               /* resolved from the built-in USB-IF list */
    char  dh_name[256];             /* company name                           */
    int   cpl_found;                /* partner directory has >=1 publisher    */
    char  cpl_query_used[256];      /* the (possibly shortened) name that hit  */
    cpl_account_t accounts[PF_CPL_MAX_ACCOUNTS];
    int   n_accounts;
    int   n_selected;
    int   truncated_accounts;       /* more matches than we kept              */
    cpl_product_t *products;
    int   n_products, cap_products;
    int   letters_tried, letters_ok;
    char  error[256];
} vendor_info_t;

/* How to resolve an ambiguous publisher match. */
typedef struct {
    int         scan_all;           /* --cpl-all: enumerate every match       */
    const char *pick_account;       /* --cpl-account <id>, or NULL            */
    int         interactive;        /* allowed to prompt on a console         */
} vendor_opts_t;

int  vendor_lookup(const char *bus, unsigned vid, const vendor_opts_t *opt,
                   vendor_info_t *vi);
void vendor_report(const vendor_info_t *vi, const char *bus, unsigned vid);
void vendor_free(vendor_info_t *vi);

/* ------------------------------------------------------------------ wu --- */

typedef struct {
    char hwid[PF_MAX_ID];       /* the DriverHardwareID reported by WU       */
    char matched[PF_MAX_ID];    /* which of our target IDs it matched        */
    char title[512];
    char description[1024];
    char cls[128];
    char manufacturer[128];
    char company[128];
    char version_date[32];
    char update_id[64];
    int  is_downloaded;
} wuhit_t;

typedef struct {
    wuhit_t *hits;
    int      count;
    int      cap;
    long     total_updates;     /* driver updates WU returned, pre-filter    */
    HRESULT  error;
    char     error_msg[256];
    int      completed;
    DWORD    elapsed_ms;
} wures_t;

/* Runs the search on a dedicated STA thread. Filters the returned driver
 * updates against every ID in `targets`, which is what makes batching work. */
int  wu_search(char targets[][PF_MAX_ID], int n_targets, int timeout_s,
               wures_t *out);
void wu_free(wures_t *r);
void wu_set_superseded(int on);

/* When on, every driver update Windows Update returns for a search is logged
 * to the JSONL as a wu_raw_update event, matched or not. Lets an operator
 * confirm with their own eyes that the returned set is scoped to the injected
 * device inventory and is not a catalogue dump. */
void wu_set_dump_raw(int on);

/* ------------------------------------------------------------- globals --- */

extern volatile int g_abort;

#endif /* PNPFUZZ_H */
