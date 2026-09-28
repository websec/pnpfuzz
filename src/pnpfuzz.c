/*
 * pnpfuzz.c - command line, preflight, sweep orchestration
 *
 * How the sweep works:
 *
 *   build a batch of candidate hardware IDs -> one synthetic devnode ->
 *   one SetupAPI driver-match query -> one Windows Update search ->
 *   attribute the results back to individual IDs -> drop the node.
 *   One network round trip per batch, no hardware in the loop.
 */

#include "pnpfuzz.h"
#include <objbase.h>
#include <time.h>
#include <io.h>       /* _commit, _fileno - durable checkpoint flush */

volatile int g_abort = 0;

/* ----------------------------------------------------------------- cfg --- */

typedef enum { MODE_QUERY = 0, MODE_INSTALL, MODE_INSTALL_ALL } run_mode;

typedef struct {
    space_t   space;
    run_mode  mode;
    int       no_wu;
    int       no_driverstore;
    int       batch;
    int       batch_given;     /* --batch was passed explicitly              */
    int       auto_batch;      /* calibrate + ride best width (DEFAULT on)   */
    int       auto_batch_given;/* --auto-batch stated explicitly             */
    int       wu_blockers;    /* preflight hard blockers (WSUS, policy, ...) */
    int       no_recon;       /* --no-recon: skip the vendor-identity lookup */
    int       recon_only;     /* --recon-only: report and exit, no sweeping  */
    int       cpl_all;        /* --cpl-all: enumerate every matching pub.   */
    char      cpl_account[32];/* --cpl-account <id>                         */
    DWORD     os_build;        /* for the per-host width cache               */
    char      os_arch[16];
    int       auto_batch_max;  /* ceiling calibration probes to              */
    char      ref_id[PF_MAX_ID]; /* --ref-id: known-good WU reference        */
    int       dump_raw_wu;
    int       bench_wu;
    int       bench_reps;
    int       wu_timeout;
    int       wu_timeout_given;   /* --wu-timeout was passed explicitly       */
    int       first_wu_timeout;   /* first search of the process (cold sync)  */
    int       install_timeout;
    int       settle_ms;
    uint64_t  start;
    uint64_t  limit;
    int       resume;          /* accepted for back-compat; resume is default */
    int       restart;         /* --restart: ignore any checkpoint, start fresh */
    int       start_given;     /* --start was passed explicitly               */
    /* Resume state seeded from the checkpoint when continuing an interrupted run */
    uint64_t  resume_from;     /* scan start (0 = none)                        */
    int       resume_active;
    int       resume_width;    /* calibrated batch width to restore (0 = none) */
    char      resume_ref[PF_MAX_ID];
    int       no_exclude;
    int       stop_on_first;
    int       keep;
    int       watch_all;
    int       setupapi_slices;
    int       assume_yes;
    int       force;
    char      logdir[MAX_PATH];
    char      sig[512];        /* config signature, guards --resume */
} config;

typedef struct {
    uint64_t probed;
    uint64_t skipped_present;
    uint64_t batches;
    int      ds_hits;
    int      wu_hits;
    int      installs_ok;
    int      installs_failed;
    int      wu_errors;
    DWORD    t0;
} stats;

/* ------------------------------------------------------------- console --- */

static void fmt_duration(double seconds, char *buf, size_t cap)
{
    long s = (long)(seconds < 0 ? 0 : seconds);
    if (s < 60)        _snprintf(buf, cap, "%lds", s);
    else if (s < 3600) _snprintf(buf, cap, "%ldm%02lds", s / 60, s % 60);
    else if (s < 86400)_snprintf(buf, cap, "%ldh%02ldm", s / 3600, (s % 3600) / 60);
    else               _snprintf(buf, cap, "%ldd%02ldh", s / 86400, (s % 86400) / 3600);
    buf[cap - 1] = '\0';
}

static void banner(void)
{
    fprintf(stderr,
"\n"
"  pnpfuzz " PF_VERSION "  -  PnP driver-acquisition fuzzer for Windows\n"
"  by " PF_AUTHOR "\n"
"\n"
"  Synthesises USB device identities in the Windows PnP manager and asks\n"
"  Windows which driver it would fetch for each. No hardware required.\n"
"\n"
"  Built on the PnP auto-install primitive from DEF CON 34 (2026),\n"
"  \"Plug and Pwn\" by Alejandro Hernando & Borja Martinez (pnp_simulate.c).\n"
"  That research is the primitive; this fuzzer is an original tool on top of it.\n"
"\n"
"  Authorised security research only.\n\n");
}

static void usage(void)
{
    banner();
    fprintf(stderr,
"USAGE\n"
"  pnpfuzz --vid <spec> [options]\n"
"\n"
"  The short version: `pnpfuzz --vid 1532` sweeps that vendor's entire PID\n"
"  range and tunes itself. --pid defaults to 0000-FFFF, batch width is\n"
"  self-calibrating, and the canary is discovered automatically from the\n"
"  first Windows Update hit. Nothing else is required.\n"
"\n"
"  A <spec> is always HEXADECIMAL: a comma separated list of values and\n"
"  A-B ranges, or * for the whole range.\n"
"      046D        0x046D        0000-FFFF        1,2,10-1F        *\n"
"\n"
"  Every axis takes such a spec, so several vendors sweep in one run:\n"
"      --vid 1EF9,046D,1532 --pid 0000-FFFF\n"
"  VID is the OUTERMOST axis and PID the innermost, so the sweep walks every\n"
"  PID of the first VID, then advances to the next VID automatically, in the\n"
"  order you listed them. A header is printed as each VID begins, and no batch\n"
"  ever straddles a VID boundary. Resume, coverage and the hit table span the\n"
"  whole multi-VID space as one search.\n"
"\n"
"HOW IT WORKS\n"
"  For each combination the tool registers a synthetic ROOT\\PNPFUZZ device\n"
"  node whose hardware ID is USB\\VID_xxxx&PID_yyyy, which injects that ID\n"
"  into the machine's PnP device inventory as a present, driverless device.\n"
"  It then asks two questions about that injected device:\n"
"    * local DriverStore  - would an installed INF bind to it? (SetupAPI,\n"
"      non-destructive: it matches, it does not install)\n"
"    * Windows Update     - the WU agent uploads the current device inventory\n"
"      (now carrying your ID) and the service resolves, server-side, which\n"
"      driver package it would offer. This is the same code path as physically\n"
"      plugging the device in. It is NOT a walk of the Microsoft Update\n"
"      Catalogue: WU only returns drivers applicable to devices present on the\n"
"      box, which is why an unassigned VID returns nothing. Use --dump-raw-wu\n"
"      to see the exact returned set for yourself.\n"
"  Many candidate IDs ride one node, so ONE WU search covers a whole batch.\n"
"  The node is removed immediately after; nothing is installed unless you ask.\n"
"\n"
"HARDWARE ID SHAPES  (what --bus builds, and what each axis adds)\n"
"  The PnP manager matches a device against INF models sections by STRING, so\n"
"  the only thing that changes between buses is the shape of that string. Both\n"
"  buses take the same axes; they just render differently.\n"
"\n"
"  USB  (--bus usb, the default)          e.g. a Logitech mouse, VID 046D\n"
"    plain            USB\\VID_046D&PID_C52B\n"
"    + --rev 0100     USB\\VID_046D&PID_C52B&REV_0100        (bcdDevice, 4 hex)\n"
"    + --mi 00        USB\\VID_046D&PID_C52B&MI_00           (composite iface)\n"
"    compatible IDs   USB\\Class_03&SubClass_01&Prot_01      (--class/--subclass\n"
"                     USB\\Class_03&SubClass_01               /--protocol)\n"
"                     USB\\Class_03\n"
"\n"
"  PCI / PCIe  (--bus pci, same for both)  e.g. an Intel NIC, VEN 8086\n"
"    plain            PCI\\VEN_8086&DEV_1234\n"
"    +--subsys 11AB5  PCI\\VEN_8086&DEV_1234&SUBSYS_00011AB5  (32-bit subsystem)\n"
"    + --rev 07       PCI\\VEN_8086&DEV_1234&REV_07           (2 hex, not 4)\n"
"    most specific    PCI\\VEN_8086&DEV_1234&SUBSYS_00011AB5&REV_07\n"
"    compatible IDs   PCI\\VEN_8086&CC_020000                 (--class 02\n"
"                     PCI\\CC_020000                           --subclass 00\n"
"                     PCI\\VEN_8086&CC_0200                    --protocol 00)\n"
"                     PCI\\CC_0200\n"
"                     PCI\\VEN_8086\n"
"    Note VEN/DEV are the PCI names for VID/PID; --ven/--dev are accepted too.\n"
"    REV is 2 hex on PCI vs 4 on USB, --mi does not apply, and --class/--subclass\n"
"    /--protocol become the class code CC_ccsspp (class, subclass, prog-IF).\n"
"\n"
"TARGET\n"
"  --bus usb|pci         which bus to synthesise identities on   (default usb)\n"
"                        USB: USB\\VID_xxxx&PID_yyyy\n"
"                        PCI: PCI\\VEN_xxxx&DEV_yyyy  (PCI and PCIe both)\n"
"  --vid, --ven <spec>   vendor ID(s)                            (required)\n"
"                        PCI calls it VEN; both spellings work on either bus\n"
"  --pid, --dev <spec>   product/device ID(s) (default: 0000-FFFF, all of them)\n"
"  --subsys <spec>       PCI only: SUBSYS_ssssssss, the 32-bit subsystem pair\n"
"                        (subsystem vendor + subsystem device). Pin a value;\n"
"                        the 2^32 space is not sweepable and most INFs match\n"
"                        the bare VEN&DEV form anyway.\n"
"  --rev <spec>          bcdDevice revision, adds &REV_xxxx to the hardware ID\n"
"  --mi <spec>           interface number, adds &MI_xx (composite devices)\n"
"  --class <spec>        USB: bDeviceClass -> USB\\Class_xx compatible ID\n"
"                        PCI: class code   -> PCI\\VEN_xxxx&CC_ccsspp / PCI\\CC_*\n"
"  --subclass <spec>     bDeviceSubClass -> USB\\Class_xx&SubClass_yy (needs --class)\n"
"  --protocol <spec>     bDeviceProtocol -> ...&Prot_zz            (needs --subclass)\n"
"  --with-plain          when sweeping REV/MI (USB) or SUBSYS/REV (PCI), also\n"
"                        present the bare VID&PID / VEN&DEV form, the way real\n"
"                        hardware reports both the specific and generic IDs\n"
"\n"
"MODE  (default is query only: nothing downloaded, nothing installed)\n"
"  --install             query first, then install ONLY the IDs that matched,\n"
"                        each on its own node so attribution stays exact.\n"
"                        DOWNLOADS AND RUNS VENDOR CODE AS SYSTEM; the install\n"
"                        is NOT undone by cleanup. Prompts unless --yes.\n"
"  --install-all         fire CM_Setup_DevNode on every batch regardless of the\n"
"                        query result. The Device Install Service resolves\n"
"                        server-side and can occasionally find what the COM\n"
"                        query misses. Much slower, much more invasive.\n"
"  --no-wu               skip the Windows Update search (local DriverStore only)\n"
"  --no-driverstore      skip the local DriverStore match query (WU only)\n"
"  --superseded          include potentially superseded driver packages in WU\n"
"\n"
"THROUGHPUT   (one WU search per batch is the cost; wider batch = fewer searches)\n"
"  --batch N             PIN a fixed width and switch self-tuning off (max %d).\n"
"                        Pass --auto-batch too to keep self-tuning and use this\n"
"                        only as the starting width.\n"
"  --no-auto-batch       disable self-tuning; use the fixed --batch width\n"
"  --auto-batch          ON BY DEFAULT. Calibrate the largest batch width WU still\n"
"                        answers LOSSLESSLY on this host, then ride it, with a\n"
"                        known-good ID as a per-batch canary: if WU ever\n"
"                        silently truncates the ID list the canary goes missing,\n"
"                        so the tool warns, halves the width and re-runs that\n"
"                        range - coverage is never over-claimed. The calibrated\n"
"                        width is cached per host+build, so later runs on the\n"
"                        same machine skip calibration entirely.\n"
"                        Needs Windows Update (ignored with --no-wu).\n"
"                        NOTE: a canary requires a reference. With neither\n"
"                        --ref-id nor a cached value it runs UNVERIFIED at\n"
"                        width %d until it discovers its own Windows Update hit.\n"
"  --auto-batch-max N    ceiling that calibration probes to (default %d, max %d)\n"
"  --ref-id <hwid>       a hardware ID you KNOW Windows Update answers for, used\n"
"                        as the calibration reference and canary. Strongly\n"
"                        recommended: it is what turns an unverified width into\n"
"                        a measured one, from the very first batch.\n"
"                        It must be an ID WINDOWS UPDATE answers for. A local\n"
"                        DriverStore match will not do - such an ID never comes\n"
"                        back from a WU search, so every batch would look\n"
"                        truncated and the width would collapse.\n"
"  --wu-timeout N        seconds per Windows Update search        (default 300)\n"
"  --first-wu-timeout N  seconds for the FIRST search only, which also pays the\n"
"                        one-time WU catalogue sync (default 900, or --wu-timeout\n"
"                        if you set that; the first search is NOT special-cased\n"
"                        past your explicit cap)\n"
"  --bench-wu            find the widest STABLE bulk width and the minimum\n"
"                        timeout for it, on this host. Times a WU scan at widths\n"
"                        64..8192 (decoy IDs, works even if WU returns nothing),\n"
"                        then prints a recommended --batch/--wu-timeout pair.\n"
"                        Respects --wu-timeout as the per-scan cap.\n"
"  --bench-reps N        repeat each width N times so the recommendation clears\n"
"                        the SLOWEST run, not a lucky one (default 1; use 3 for\n"
"                        a stable figure - each rep is a full scan, so it is slow)\n"
"  --install-timeout N   seconds to wait for a driver to bind     (default 300)\n"
"  --settle N            ms to let PnP settle after node creation (default 750)\n"
"\n"
"SCOPE / RESUME\n"
"  Resume is AUTOMATIC. Progress is checkpointed to the log directory after\n"
"  every batch (durably: a crash or Ctrl+C mid-write cannot corrupt it). Just\n"
"  re-run the SAME command and it continues from the last completed batch; an\n"
"  interrupted batch is redone in full, so nothing is skipped. The checkpoint\n"
"  is per search space, so different sweeps in one log directory don't collide.\n"
"  --start N             begin at combination N (decimal index); an explicit\n"
"                        --start overrides auto-resume for that run\n"
"  --limit N             stop after N combinations\n"
"  --restart, --fresh    ignore any saved checkpoint and start this space over\n"
"  --resume              accepted but no longer needed (resume is the default)\n"
"  --stop-on-first       stop at the first confirmed hit\n"
"  --no-recon            skip the vendor-identity lookup (see RECON below)\n"
"  --cpl-all             when several publishers match the vendor name,\n"
"                        enumerate ALL of them instead of asking\n"
"  --cpl-account <id>    enumerate exactly this publisher account id\n"
"  --recon-only          do the vendor lookup, print it, and exit without\n"
"                        sweeping. Cheap way to triage a vendor first.\n"
"  --no-exclude          also probe IDs already present on this host (default\n"
"                        skips them, so a real device is never touched)\n"
"\n"
"OUTPUT\n"
"  --logdir PATH         where run-*.jsonl / hits-*.csv / checkpoint.txt go\n"
"                        (default .\\pnpfuzz-logs)\n"
"  --dump-raw-wu         log EVERY driver update WU returns per search, matched\n"
"                        or not, as wu_raw_update events. Proves the query is\n"
"                        device-scoped, not a catalogue dump. Verbose.\n"
"  --watch-all           record PnP notifications for every device, not just ours\n"
"  --setupapi            save the setupapi.dev.log slice for each hitting batch\n"
"\n"
"RECON  (before each sweep, unless --no-recon)\n"
"  Three public, read-only lookups that say whether the vendor is worth\n"
"  sweeping, and how to read a zero-hit result:\n"
"    0. A built-in USB-IF vendor list (13,756 entries) is consulted first -\n"
"       authoritative for USB, instant, and needs no network.\n"
"    1. devicehunt.com resolves the ID when the local list cannot: always\n"
"       for PCI (a separate PCI-SIG registry), and for newer USB vendors.\n"
"    2. The Microsoft partner hardware directory is searched for that name.\n"
"    3. Its certified submissions are enumerated by querying the product\n"
"       search for each letter a-z and unioning the results (the search\n"
"       matches any substring, so single letters enumerate the catalogue).\n"
"  A name often matches SEVERAL publishers (\"raytheon\" returns Raytheon\n"
"  Company, Raytheon Anschuetz GmbH and Raytheon Technologies). Those are\n"
"  separate accounts with separate catalogues, so the tool lists them and\n"
"  asks which to enumerate; --cpl-all or --cpl-account answers in advance,\n"
"  and a non-interactive run takes the closest name match and says so.\n"
"  A vendor with certified drivers makes a Windows Update package likely.\n"
"  A vendor that resolves but is ABSENT from the directory is usually either\n"
"  dormant, or a silicon vendor whose customers publish under their own name\n"
"  - so the drivers exist, just under a different publisher.\n"
"\n"
"HOUSEKEEPING\n"
"  --verify-batch <id>   one-shot check: prove batching is lossless on this host\n"
"                        before a long sweep. Give a hardware ID you already know\n"
"                        WU answers for; it is searched alone, then buried among\n"
"                        decoys at --batch width. (Auto mode does this for you.)\n"
"  --cleanup             remove leftover ROOT\\PNPFUZZ nodes and exit\n"
"  --cleanup-dry-run     list leftover nodes without removing anything\n"
"  --keep                leave probe nodes registered (debugging only)\n"
"  --yes                 skip the confirmation prompt in install modes\n"
"  --force               continue without Administrator (node creation will fail)\n"
"  --help                this text\n"
"  --version             print version and exit\n"
"\n"
"  Set PNPFUZZ_DEBUG=1 in the environment to also echo debug events to console.\n"
"\n"
"EXAMPLES\n"
"  Full PID sweep of one vendor, query only, auto-tuned for speed:\n"
"    pnpfuzz --vid 046D --pid 0000-FFFF --auto-batch\n"
"\n"
"  Sweep every device ID of a PCI/PCIe vendor (VEN 8086 = Intel):\n"
"    pnpfuzz --bus pci --ven 8086\n"
"\n"
"  PCI sweep narrowed to a class code (02 00 00 = an Ethernet controller):\n"
"    pnpfuzz --bus pci --ven 8086 --class 02 --subclass 00 --protocol 00\n"
"\n"
"  Auto-tune from a known-good reference (fastest start, fully certified):\n"
"    pnpfuzz --vid 06CB --pid * --auto-batch --ref-id \"USB\\VID_06CB&PID_0089\"\n"
"\n"
"  Several vendors. If interrupted, the SAME line resumes automatically:\n"
"    pnpfuzz --vid 06CB,1199,056A --pid * --auto-batch\n"
"\n"
"  Query, then install whatever matched, unattended:\n"
"    pnpfuzz --vid 06CB --pid 0080-00A0 --install --yes\n"
"\n"
"  HID-class compatible IDs alongside the VID/PID sweep:\n"
"    pnpfuzz --vid 046D --pid 0000-0FFF --class 03 --subclass 01 --protocol 01\n"
"\n"
"  Prove the WU query is device-scoped and confirm a 128-wide batch is lossless:\n"
"    pnpfuzz --verify-batch \"USB\\VID_06CB&PID_0089\" --batch 128 --dump-raw-wu\n"
"\n", PF_MAX_BATCH, PF_AUTO_BATCH_START, PF_AUTO_BATCH_MAX, PF_MAX_BATCH);
}

/* --------------------------------------------------------- ctrl handler -- */

static BOOL WINAPI ctrl_handler(DWORD type)
{
    (void)type;
    if (!g_abort) {
        g_abort = 1;
        fprintf(stderr, "\n[!] Interrupt received. Finishing the current batch and "
                        "cleaning up...\n");
        return TRUE;
    }
    return FALSE;   /* second Ctrl+C: let the OS kill us */
}

/* --------------------------------------------------------- oem inf diff -- */

static void snapshot_oem_infs(pf_strset *s)
{
    char            pat[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE          h;
    UINT            n;

    n = GetWindowsDirectoryA(pat, MAX_PATH);
    if (!n || n >= MAX_PATH - 20) return;
    strcat(pat, "\\INF\\oem*.inf");

    h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        pf_strset_add(s, fd.cFileName);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

static void report_new_oem_infs(pf_strset *before)
{
    char            pat[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE          h;
    UINT            n;

    n = GetWindowsDirectoryA(pat, MAX_PATH);
    if (!n || n >= MAX_PATH - 20) return;
    strcat(pat, "\\INF\\oem*.inf");

    h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!pf_strset_has(before, fd.cFileName)) {
            jb_t jb;
            jb_init(&jb);
            jb_str(&jb, "inf", fd.cFileName);
            log_event(PF_GOOD, "driverstore_package_added", jb_get(&jb));
            jb_free(&jb);
            log_console(PF_GOOD, "DriverStore gained %s "
                                 "(devnode removal does NOT undo this)", fd.cFileName);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

/* --------------------------------------------------- setupapi.dev.log ---- */

static long long setupapi_size(void)
{
    char  path[MAX_PATH];
    WIN32_FILE_ATTRIBUTE_DATA fad;
    UINT  n = GetWindowsDirectoryA(path, MAX_PATH);

    if (!n || n >= MAX_PATH - 24) return -1;
    strcat(path, "\\INF\\setupapi.dev.log");
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) return -1;
    return ((long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
}

static void setupapi_slice(long long from, long long to, const char *tag)
{
    char  src[MAX_PATH], dst[MAX_PATH];
    HANDLE h;
    FILE  *out;
    LARGE_INTEGER li;
    char  buf[65536];
    long long left;
    UINT  n;

    if (from < 0 || to <= from) return;
    n = GetWindowsDirectoryA(src, MAX_PATH);
    if (!n || n >= MAX_PATH - 24) return;
    strcat(src, "\\INF\\setupapi.dev.log");

    h = CreateFileA(src, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    li.QuadPart = from;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) { CloseHandle(h); return; }

    _snprintf(dst, sizeof(dst), "%s\\setupapi-%s.log", log_dir_path(), tag);
    dst[sizeof(dst) - 1] = '\0';
    out = fopen(dst, "wb");
    if (!out) { CloseHandle(h); return; }

    left = to - from;
    while (left > 0) {
        DWORD want = (DWORD)(left > (long long)sizeof(buf) ? (long long)sizeof(buf) : left);
        DWORD got = 0;
        if (!ReadFile(h, buf, want, &got, NULL) || got == 0) break;
        fwrite(buf, 1, got, out);
        left -= got;
    }
    fclose(out);
    CloseHandle(h);

    {
        jb_t jb;
        jb_init(&jb);
        jb_str(&jb, "file", dst);
        jb_u64(&jb, "bytes", (unsigned long long)(to - from));
        log_event(PF_INFO, "setupapi_slice_saved", jb_get(&jb));
        jb_free(&jb);
    }
}

/* ---------------------------------------------------------- checkpoint --- */

/* The checkpoint records progress through a search space so an interrupted run
 * can be continued by simply re-running the same command. It is:
 *   - named per search space (checkpoint-<sighash>.txt), so distinct sweeps in
 *     one log directory never clobber each other;
 *   - written atomically and flushed to disk after every batch, so a kill or
 *     crash mid-write cannot corrupt it (write temp, _commit, rename over).
 */

static unsigned sig_hash(const char *s)
{
    unsigned h = 2166136261u;
    for (; s && *s; s++) { h ^= (unsigned char)*s; h *= 16777619u; }
    return h;
}

static void checkpoint_path(const config *cfg, char *out, size_t cap)
{
    _snprintf(out, cap, "%s\\checkpoint-%08x.txt", cfg->logdir, sig_hash(cfg->sig));
    out[cap - 1] = '\0';
}

static void checkpoint_write(const config *cfg, uint64_t index, int width, const char *ref)
{
    char  path[MAX_PATH], tmp[MAX_PATH + 8];   /* headroom so tmp can't alias path */
    FILE *f;

    checkpoint_path(cfg, path, sizeof(path));
    _snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    tmp[sizeof(tmp) - 1] = '\0';

    f = fopen(tmp, "wb");
    if (!f) return;
    fprintf(f, "version=%s\nsignature=%s\nindex=%llu\nwidth=%d\nref=%s\n",
            PF_VERSION, cfg->sig, (unsigned long long)index,
            width, (ref && ref[0]) ? ref : "");
    fflush(f);
    _commit(_fileno(f));                     /* force to disk before rename */
    fclose(f);

    /* Atomic replace: readers see either the old file or the new, never a torn
     * half-written one. */
    if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING))
        DeleteFileA(tmp);
}

/* Parse one checkpoint file. Returns 0 and fills the outputs on success, -1 if
 * the file is missing or has no index. Tolerant of a missing width/ref (older
 * checkpoints). Does not validate the signature; the caller does that. */
static int checkpoint_parse(const char *path, char *sig_out, size_t sig_cap,
                            uint64_t *index, int *width, char *ref_out, size_t ref_cap)
{
    char  line[1024];
    FILE *f;
    int   have_idx = 0;

    if (sig_out) sig_out[0] = '\0';
    if (width)   *width = 0;
    if (ref_out) ref_out[0] = '\0';

    f = fopen(path, "rb");
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        if (strncmp(line, "signature=", 10) == 0) {
            if (sig_out) { strncpy(sig_out, line + 10, sig_cap - 1); sig_out[sig_cap - 1] = '\0'; }
        } else if (strncmp(line, "index=", 6) == 0) {
            *index = _strtoui64(line + 6, NULL, 10);
            have_idx = 1;
        } else if (strncmp(line, "width=", 6) == 0) {
            if (width) *width = atoi(line + 6);
        } else if (strncmp(line, "ref=", 4) == 0) {
            if (ref_out) { strncpy(ref_out, line + 4, ref_cap - 1); ref_out[ref_cap - 1] = '\0'; }
        }
    }
    fclose(f);
    return have_idx ? 0 : -1;
}

/* Locate and validate this search space's checkpoint. Returns 0 with the
 * resume point on success, -1 if none applies. */
static int checkpoint_read(const config *cfg, uint64_t *index, int *width, char *ref_out, size_t ref_cap)
{
    char path[MAX_PATH], legacy[MAX_PATH];
    char sig[512];

    checkpoint_path(cfg, path, sizeof(path));
    if (checkpoint_parse(path, sig, sizeof(sig), index, width, ref_out, ref_cap) == 0) {
        if (strcmp(sig, cfg->sig) == 0) return 0;
        return -1;      /* hash collision (astronomically unlikely) -> ignore */
    }

    /* Fall back to a pre-hashed-name unhashed checkpoint.txt so an in-progress sweep
     * survives the upgrade, but only if its signature matches this space. */
    _snprintf(legacy, sizeof(legacy), "%s\\checkpoint.txt", cfg->logdir);
    legacy[sizeof(legacy) - 1] = '\0';
    if (checkpoint_parse(legacy, sig, sizeof(sig), index, width, ref_out, ref_cap) == 0 &&
        strcmp(sig, cfg->sig) == 0)
        return 0;

    return -1;
}

/* --------------------------------------------------------- verify batch -- */

/* Batching only helps if a hardware ID buried among decoys is still reported.
 * Rather than assume that, prove it on the host before a multi-hour sweep. */
static int verify_batch(const char *known_id, int batch, int wu_timeout)
{
    char (*ids)[PF_MAX_ID];
    node_t node;
    wures_t r;
    int i, alone_found = 0, batched_found = 0, rc = 1;
    wchar_t desc[128];

    if (batch < 2) batch = 2;
    if (batch > PF_MAX_BATCH) batch = PF_MAX_BATCH;

    ids = (char (*)[PF_MAX_ID])calloc((size_t)batch, PF_MAX_ID);
    if (!ids) return 1;

    log_console(PF_INFO, "Batch verification: does '%s' still surface inside a "
                         "batch of %d?", known_id, batch);

    /* Pass 1: the control. Just the known ID. */
    strncpy(ids[0], known_id, PF_MAX_ID - 1);
    _snwprintf(desc, 128, L"pnpfuzz batch verification (control)");
    if (node_create(&node, ids, 1, NULL, 0, desc) != 0) {
        log_console(PF_ERR, "cannot create the probe node - are you elevated?");
        free(ids);
        return 1;
    }
    Sleep(1000);
    memset(&r, 0, sizeof(r));
    if (wu_search(ids, 1, wu_timeout, &r) == 0) alone_found = r.count;
    else log_console(PF_ERR, "control search failed: %s", r.error_msg);
    wu_free(&r);
    node_destroy(&node);

    log_console(alone_found ? PF_GOOD : PF_WARN,
                "control (batch of 1): %d Windows Update match(es)", alone_found);
    if (!alone_found) {
        log_console(PF_ERR, "The control found nothing, so this ID is not a usable "
                            "reference on this host.");
        log_console(PF_ERR, "Pick a hardware ID you have already confirmed, or check "
                            "the preflight warnings above.");
        free(ids);
        return 1;
    }

    /* Pass 2: same ID, buried among decoys under an unassigned vendor ID.
     * Placed LAST, matching calibration and the sweep's canary: if Windows
     * Update honours only the first N entries, the tail is the first casualty.
     * A reference in the middle would survive whenever N > batch/2 and report
     * roughly twice the usable width. */
    memset(ids, 0, (size_t)batch * PF_MAX_ID);
    for (i = 0; i < batch; i++)
        _snprintf(ids[i], PF_MAX_ID, "USB\\VID_FFFF&PID_%04X", (unsigned)i);
    strncpy(ids[batch - 1], known_id, PF_MAX_ID - 1);
    ids[batch - 1][PF_MAX_ID - 1] = '\0';
    _snwprintf(desc, 128, L"pnpfuzz batch verification (batch of %d)", batch);
    if (node_create(&node, ids, batch, NULL, 0, desc) != 0) {
        log_console(PF_ERR, "cannot create the batched probe node");
        free(ids);
        return 1;
    }
    Sleep(1000);
    memset(&r, 0, sizeof(r));
    if (wu_search(ids, batch, wu_timeout, &r) == 0) {
        for (i = 0; i < r.count; i++)
            if (_stricmp(r.hits[i].matched, known_id) == 0) batched_found++;
    } else {
        log_console(PF_ERR, "batched search failed: %s", r.error_msg);
    }
    wu_free(&r);
    node_destroy(&node);

    log_console(batched_found ? PF_GOOD : PF_ERR,
                "batched (batch of %d): %d match(es) for the known ID", batch, batched_found);

    if (batched_found) {
        log_console(PF_GOOD, "Batching is lossless at %d on this host. Sweep with "
                             "--batch %d.", batch, batch);
        rc = 0;
    } else {
        log_console(PF_ERR, "The known ID disappeared when batched. Halve --batch and "
                            "verify again;");
        log_console(PF_ERR, "if even small batches lose it, sweep with --batch 1 "
                            "(slow but exact).");
    }

    {
        jb_t jb;
        jb_init(&jb);
        jb_str(&jb, "known_id", known_id);
        jb_num(&jb, "batch", batch);
        jb_num(&jb, "control_matches", alone_found);
        jb_num(&jb, "batched_matches", batched_found);
        jb_bool(&jb, "lossless", batched_found > 0);
        log_event(batched_found ? PF_GOOD : PF_ERR, "batch_verification", jb_get(&jb));
        jb_free(&jb);
    }
    free(ids);
    return rc;
}

/* -------------------------------------------------------------- report --- */

static void report_ds_match(const drvmatch_t *m, stats *st)
{
    jb_t jb;

    st->ds_hits++;
    log_console(PF_GOOD, "DRIVERSTORE  %s  ->  %s / %s  [%s %s rank %lu]",
                m->hwid, m->provider[0] ? m->provider : "?",
                m->desc[0] ? m->desc : "?", m->cls, m->version,
                (unsigned long)m->rank);

    jb_init(&jb);
    jb_str(&jb, "hardware_id", m->hwid);
    jb_bool(&jb, "compatible_id_match", m->compat_only);
    jb_str(&jb, "inf", m->inf);
    jb_str(&jb, "section", m->section);
    jb_str(&jb, "description", m->desc);
    jb_str(&jb, "manufacturer", m->mfg);
    jb_str(&jb, "provider", m->provider);
    jb_str(&jb, "version", m->version);
    jb_str(&jb, "date", m->date);
    jb_str(&jb, "class", m->cls);
    jb_u64(&jb, "rank", m->rank);
    log_event(PF_GOOD, "driverstore_match", jb_get(&jb));
    jb_free(&jb);

    {
        char extra[128];
        _snprintf(extra, sizeof(extra), "rank=%lu%s", (unsigned long)m->rank,
                  m->compat_only ? " compatible-id" : "");
        extra[sizeof(extra) - 1] = '\0';
        log_hit_csv(m->hwid, "driverstore",
                    m->compat_only ? "compatible" : "hardware",
                    m->provider, m->desc, m->cls, m->version, m->inf, extra);
    }
}

static void report_wu_hit(const wuhit_t *h, stats *st)
{
    jb_t jb;

    st->wu_hits++;
    log_console(PF_GOOD, "WINDOWSUPDATE %s  ->  %s", h->matched, h->title);
    if (h->manufacturer[0] || h->cls[0])
        log_console(PF_GOOD, "              %s / %s / %s",
                    h->manufacturer, h->cls, h->version_date);

    jb_init(&jb);
    jb_str(&jb, "matched_target", h->matched);
    jb_str(&jb, "wu_driver_hardware_id", h->hwid);
    jb_str(&jb, "title", h->title);
    jb_str(&jb, "description", h->description);
    jb_str(&jb, "driver_class", h->cls);
    jb_str(&jb, "driver_manufacturer", h->manufacturer);
    jb_str(&jb, "driver_provider", h->company);
    jb_str(&jb, "driver_date", h->version_date);
    jb_str(&jb, "update_id", h->update_id);
    jb_bool(&jb, "already_downloaded", h->is_downloaded);
    log_event(PF_GOOD, "windows_update_match", jb_get(&jb));
    jb_free(&jb);

    log_hit_csv(h->matched, "windowsupdate", "hardware", h->manufacturer,
                h->title, h->cls, h->version_date, "", h->update_id);
}

static void drain_pnp_events(void)
{
    pnpev_t ev[256];
    int n, i;

    n = watch_take(ev, 256);
    for (i = 0; i < n; i++) {
        jb_t jb;
        jb_init(&jb);
        jb_str(&jb, "action", ev[i].type);
        jb_str(&jb, "instance_id", ev[i].instance);
        jb_bool(&jb, "ours", ev[i].ours);
        jb_u64(&jb, "since_start_ms", ev[i].t_ms);
        log_event(PF_DEBUG, "pnp_event", jb_get(&jb));
        jb_free(&jb);
    }
}

/* --------------------------------------------------------- install pass -- */

static void install_one(const char *hwid, const config *cfg, stats *st,
                        char compat[][PF_MAX_ID], int n_compat)
{
    char    ids[1][PF_MAX_ID];
    node_t  node;
    wchar_t desc[256];
    drvmatch_t bound;
    pf_strset *before;
    long long sa_from, sa_to;
    jb_t    jb;
    int     ok = 0;

    strncpy(ids[0], hwid, PF_MAX_ID - 1);
    ids[0][PF_MAX_ID - 1] = '\0';
    _snwprintf(desc, 256, L"pnpfuzz install probe (%hs)", ids[0]);
    desc[255] = L'\0';

    log_console(PF_WARN, "INSTALL %s - Windows will download and run vendor code as "
                         "SYSTEM", hwid);

    jb_init(&jb);
    jb_str(&jb, "hardware_id", hwid);
    log_event(PF_WARN, "install_start", jb_get(&jb));
    jb_free(&jb);

    before = pf_strset_new();
    if (before) snapshot_oem_infs(before);
    sa_from = setupapi_size();

    if (node_create(&node, ids, 1, compat, n_compat, desc) != 0) {
        st->installs_failed++;
        if (before) pf_strset_free(before);
        return;
    }

    watch_mark();
    Sleep((DWORD)cfg->settle_ms);

    /* Local DriverStore first, exactly what the PnP manager tries first. A
     * success here counts even if the Device Install Service path then fails:
     * a package really did get installed, and the audit trail has to say so. */
    if (node_install_local(&node, NULL, &bound) == 0 && bound.desc[0]) ok = 1;

    /* Then the real thing: hand the node to the Device Install Service. */
    if (node_trigger_pnp_install(&node) == 0) {
        drvmatch_t via_dis;
        if (node_wait_installed(&node, cfg->install_timeout, &g_abort, &via_dis) == 0) {
            bound = via_dis;
            ok = 1;
        }
    }

    drain_pnp_events();
    sa_to = setupapi_size();

    if (ok) {
        st->installs_ok++;
        log_console(PF_GOOD, "INSTALLED %s -> %s / %s (%s) inf=%s",
                    hwid, bound.provider[0] ? bound.provider : "?",
                    bound.desc[0] ? bound.desc : "?", bound.cls, bound.inf);
        log_hit_csv(hwid, "installed", "hardware", bound.provider, bound.desc,
                    bound.cls, bound.version, bound.inf, bound.hwid);
    } else {
        st->installs_failed++;
        log_console(PF_WARN, "install did not bind a driver for %s within %d s",
                    hwid, cfg->install_timeout);
    }

    if (before) {
        report_new_oem_infs(before);
        pf_strset_free(before);
    }

    if (cfg->setupapi_slices && sa_from >= 0 && sa_to > sa_from) {
        char tag[128];
        int  k;
        _snprintf(tag, sizeof(tag), "install-%s", hwid);
        tag[sizeof(tag) - 1] = '\0';
        for (k = 0; tag[k]; k++)
            if (tag[k] == '\\' || tag[k] == '&' || tag[k] == ':' || tag[k] == '/')
                tag[k] = '_';
        setupapi_slice(sa_from, sa_to, tag);
    }

    jb_init(&jb);
    jb_str(&jb, "hardware_id", hwid);
    jb_bool(&jb, "driver_bound", ok);
    log_event(ok ? PF_GOOD : PF_WARN, "install_end", jb_get(&jb));
    jb_free(&jb);

    if (!cfg->keep) {
        node_destroy(&node);
    } else {
        log_console(PF_WARN, "--keep: %s left registered", node.instance_id_a);
        node.created = 0;      /* keep the devnode, still release our handles */
        node_destroy(&node);
    }
}

/* ----------------------------------------------------- width cache (host) -- */

/* Calibration is a property of the host and its Windows build, not of the
 * search space, so the result is cached per machine. Without this every new
 * sweep on the same VM re-pays a dozen Windows Update searches to rediscover
 * the same number. Stored under %LOCALAPPDATA%\pnpfuzz\, falling back to the
 * log directory when that is unavailable. */

/* How a cached width was arrived at. A width MEASURED by a full binary-search
 * calibration is trustworthy at any value. A width reached by runtime HALVING is
 * only ever a lower bound reacting to a missing canary, and a bad canary or a WU
 * outage drives it down for reasons that have nothing to do with this host's real
 * limit - so a halved width is never trusted blindly on a later run. */
#define PF_ORIGIN_CALIBRATED "calibrated"
#define PF_ORIGIN_HALVED     "halved"

/* The calibrated width and its canary are only meaningful for the vendor they
 * were measured against: a canary is a real Windows-Update-answered ID of that
 * vendor, and it is crowded out of batches belonging to a different one. Key the
 * cache on the first VID being swept so each vendor keeps its own entry and a
 * repeat run on that vendor starts instantly instead of recalibrating. */
static unsigned cache_vid_key(const config *cfg)
{
    if (cfg->space.vid.n > 0 && cfg->space.vid.v)
        return (unsigned)(cfg->space.vid.v[0] & 0xFFFF);
    return 0xFFFFu;
}

static void width_cache_path(const config *cfg, char *out, size_t cap)
{
    char  base[MAX_PATH];
    char  arch[16];
    DWORD n;
    int   i;

    /* get_arch() yields "?" for an unrecognised architecture, which is an
     * illegal Win32 filename character and would make the cache silently
     * never work. Reduce to filename-safe characters. */
    strncpy(arch, cfg->os_arch[0] ? cfg->os_arch : "x", sizeof(arch) - 1);
    arch[sizeof(arch) - 1] = '\0';
    for (i = 0; arch[i]; i++)
        if (!((arch[i] >= 'A' && arch[i] <= 'Z') || (arch[i] >= 'a' && arch[i] <= 'z') ||
              (arch[i] >= '0' && arch[i] <= '9')))
            arch[i] = '_';

    n = GetEnvironmentVariableA("LOCALAPPDATA", base, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        char dir[MAX_PATH];
        _snprintf(dir, sizeof(dir), "%s\\pnpfuzz", base);
        dir[sizeof(dir) - 1] = '\0';
        CreateDirectoryA(dir, NULL);          /* ok if it already exists */
        _snprintf(out, cap, "%s\\wu-width-%lu-%s-%s-v%04X.txt", dir,
                  (unsigned long)cfg->os_build, arch,
                  pf_bus_name(cfg->space.bus), cache_vid_key(cfg));
    } else {
        _snprintf(out, cap, "%s\\wu-width-%lu-%s-%s-v%04X.txt", cfg->logdir,
                  (unsigned long)cfg->os_build, arch,
                  pf_bus_name(cfg->space.bus), cache_vid_key(cfg));
    }
    out[cap - 1] = '\0';
}

static int width_cache_read(const config *cfg, int *width, char *ref, size_t ref_cap,
                            char *origin, size_t origin_cap)
{
    char  path[MAX_PATH], line[1024];
    FILE *f;
    int   have = 0;

    *width = 0;
    if (ref) ref[0] = '\0';
    /* An entry written before origins existed is treated as halved, i.e. not
     * trusted below the floor - the safe reading of an unknown provenance. */
    if (origin && origin_cap) {
        strncpy(origin, PF_ORIGIN_HALVED, origin_cap - 1);
        origin[origin_cap - 1] = '\0';
    }

    width_cache_path(cfg, path, sizeof(path));
    f = fopen(path, "rb");
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        if (strncmp(line, "width=", 6) == 0) { *width = atoi(line + 6); have = 1; }
        else if (strncmp(line, "ref=", 4) == 0 && ref) {
            strncpy(ref, line + 4, ref_cap - 1);
            ref[ref_cap - 1] = '\0';
        }
        else if (strncmp(line, "origin=", 7) == 0 && origin && origin_cap) {
            strncpy(origin, line + 7, origin_cap - 1);
            origin[origin_cap - 1] = '\0';
        }
    }
    fclose(f);
    return (have && *width > 0) ? 0 : -1;
}

static void width_cache_write(const config *cfg, int width, const char *ref,
                              const char *origin)
{
    char  path[MAX_PATH];
    FILE *f;

    if (width <= 0) return;

    /* Never persist a degraded width. Writing one would hand the next run this
     * run's damage, which is exactly how a single bad canary turned into hours
     * of one-ID-per-search. Below the trust floor there is nothing worth
     * remembering: the next run re-measures instead. */
    if (width < PF_WIDTH_TRUST_MIN && origin && strcmp(origin, PF_ORIGIN_HALVED) == 0)
        return;

    width_cache_path(cfg, path, sizeof(path));
    f = fopen(path, "wb");
    if (!f) return;
    fprintf(f, "build=%lu\narch=%s\nwidth=%d\nref=%s\norigin=%s\n",
            (unsigned long)cfg->os_build, cfg->os_arch,
            width, (ref && ref[0]) ? ref : "",
            origin ? origin : PF_ORIGIN_HALVED);
    fclose(f);

    {
        jb_t jb;
        jb_init(&jb);
        jb_str(&jb, "file", path);
        jb_num(&jb, "width", width);
        jb_str(&jb, "reference", (ref && ref[0]) ? ref : "");
        jb_str(&jb, "origin", origin ? origin : PF_ORIGIN_HALVED);
        log_event(PF_INFO, "width_cache_saved", jb_get(&jb));
        jb_free(&jb);
    }
}

/* Does a hardware ID's vendor fall inside the VID axis being swept? A canary
 * from a different vendor than the sweep is crowded out of every populated batch
 * (Windows Update fills the node's reply with the swept vendor's real matches),
 * so it reads as perpetual truncation and collapses the width. Detect that up
 * front rather than chase it down to width 1. Returns 1 if the ref's VID is one
 * being swept, 0 otherwise (including when no VID_ token is present). */
static int ref_vid_in_space(const space_t *sp, const char *hwid)
{
    unsigned    vid = 0;
    const char *p;
    int         i, digits = 0;

    if (!hwid || !hwid[0]) return 0;
    /* USB spells the vendor VID_, PCI spells it VEN_. Accept either, so a
     * canary is matched against the sweep on whichever bus it came from. */
    p = strstr(hwid, "VID_");
    if (!p) p = strstr(hwid, "vid_");
    if (!p) p = strstr(hwid, "VEN_");
    if (!p) p = strstr(hwid, "ven_");
    if (!p) return 0;
    p += 4;
    for (i = 0; i < 4 && p[i]; i++) {
        char c = p[i];
        int  d;
        if      (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        vid = (vid << 4) | (unsigned)d;
        digits++;
    }
    if (digits == 0) return 0;
    for (i = 0; i < sp->vid.n; i++)
        if (sp->vid.v[i] == vid) return 1;
    return 0;
}

/* ------------------------------------------------------------ auto-batch -- */

/* Does a known-good reference ID still surface from Windows Update when it is
 * buried inside a batch of `width` hardware IDs? Returns 1 yes, 0 no (WU
 * truncated the list), -1 on a search error we should not read as truncation.
 *
 * The decoys use vendor ID FFFF (unassigned), so WU has nothing to resolve for
 * them and the only possible hit is the reference itself.
 */
static int autobatch_test_width(const char *ref, int width, int wu_timeout)
{
    char   (*ids)[PF_MAX_ID];
    node_t   node;
    wures_t  r;
    wchar_t  desc[128];
    int      i, seen = 0, rc = -1;

    if (width < 1) width = 1;
    if (width > PF_MAX_BATCH) width = PF_MAX_BATCH;

    ids = (char (*)[PF_MAX_ID])calloc((size_t)width, PF_MAX_ID);
    if (!ids) return -1;

    /* Reference LAST, decoys before it. Placement decides what this can detect:
     * if Windows Update honours only the first N entries, a reference in the
     * middle survives whenever N > width/2, so the measured ceiling comes out
     * about twice the truth. At the tail it is the first casualty of any
     * truncation, which is both correct and consistent with the sweep's own
     * canary (also appended last). */
    for (i = 0; i < width; i++)
        _snprintf(ids[i], PF_MAX_ID, "USB\\VID_FFFF&PID_%04X", (unsigned)(i & 0xFFFF));
    strncpy(ids[width - 1], ref, PF_MAX_ID - 1);
    ids[width - 1][PF_MAX_ID - 1] = '\0';

    _snwprintf(desc, 128, L"pnpfuzz calibration (width %d)", width);
    desc[127] = L'\0';

    if (node_create(&node, ids, width, NULL, 0, desc) != 0) { free(ids); return -1; }
    Sleep(1000);

    memset(&r, 0, sizeof(r));
    if (wu_search(ids, width, wu_timeout, &r) == 0) {
        rc = 0;                 /* search ran; assume no unless we see the ref */
        for (i = 0; i < r.count; i++)
            if (_stricmp(r.hits[i].matched, ref) == 0) { seen = 1; break; }
        rc = seen ? 1 : 0;
    }
    wu_free(&r);
    node_destroy(&node);

    {
        jb_t jb;
        jb_init(&jb);
        jb_str(&jb, "reference", ref);
        jb_num(&jb, "width", width);
        jb_num(&jb, "reference_surfaced", rc);
        log_event(rc == 1 ? PF_GOOD : PF_INFO, "autobatch_probe", jb_get(&jb));
        jb_free(&jb);
    }
    free(ids);
    return rc;
}

/* Find the largest width in [floor, maxw] at which `ref` still surfaces.
 * Tries the ceiling first (best case: one search), else binary-searches the
 * boundary. Returns the width, or -1 if the reference does not even survive at
 * `floor` (a host/WU condition, not something batch width can fix). */
static int autobatch_calibrate(const char *ref, int floor, int maxw, int wu_timeout)
{
    int lo, hi, t;

    if (floor < 1) floor = 1;
    if (maxw < floor) maxw = floor;

    log_console(PF_INFO, "Calibrating batch width against %s (floor %d, ceiling %d)...",
                ref, floor, maxw);

    t = autobatch_test_width(ref, maxw, wu_timeout);
    if (t < 0) return -1;                       /* search error, bail */
    if (t == 1) {
        log_console(PF_GOOD, "Reference survives at the ceiling %d; batching is lossless "
                             "up to there.", maxw);
        return maxw;
    }

    t = autobatch_test_width(ref, floor, wu_timeout);
    if (t < 0) return -1;
    if (t == 0) {
        log_console(PF_WARN, "Reference does not survive even at width %d. Windows Update "
                             "appears to be truncating regardless of batch size on this "
                             "host; not a width problem.", floor);
        return -1;
    }

    /* floor good, ceiling bad: binary search the boundary. */
    lo = floor;
    hi = maxw;
    while (hi - lo > 1 && !g_abort) {
        int mid = lo + (hi - lo) / 2;
        t = autobatch_test_width(ref, mid, wu_timeout);
        if (t < 0) break;                        /* treat error as an upper bound */
        if (t == 1) lo = mid; else hi = mid;
    }
    log_console(PF_GOOD, "Largest lossless batch width on this host: %d", lo);
    {
        jb_t jb;
        jb_init(&jb);
        jb_str(&jb, "reference", ref);
        jb_num(&jb, "chosen_width", lo);
        jb_num(&jb, "floor", floor);
        jb_num(&jb, "ceiling", maxw);
        log_event(PF_GOOD, "autobatch_calibrated", jb_get(&jb));
        jb_free(&jb);
    }
    return lo;
}

/* -------------------------------------------------------------- wu bench -- */

/* Times a Windows Update scan at a series of batch widths, using decoy IDs so
 * it works even on a host where WU returns nothing. Answers the only question
 * that decides throughput: is the ~N-second scan a FIXED cost (so stuff in as
 * many hardware IDs as possible), or does it grow with the ID count (so there
 * is a sweet spot)? Also finds the widest batch that still finishes inside the
 * timeout, and the point where node creation or WU stops accepting the list. */
static int bench_wu(int first_timeout, int wu_timeout, int max_width, int reps)
{
    int widths[] = { 64, 256, 1024, 4096, 8192 };
    int nw = (int)(sizeof(widths) / sizeof(widths[0]));
    int i, j, rep;
    int    best_width = 0;      /* widest that completed ALL reps          */
    double best_worst = 0.0;    /* slowest scan seen at best_width          */
    int    stopped = 0;

    if (reps < 1) reps = 1;

    log_console(PF_INFO, "Windows Update scan-time benchmark (decoy hardware IDs).");
    log_console(PF_INFO, "Per-width timeout: %ds, %d rep(s) each. Reps show run-to-run spread,",
                wu_timeout, reps);
    log_console(PF_INFO, "which is what 'stable' needs - the timeout must clear the SLOWEST run.");

    /* Warm the WU cache once (this pays the one-time sync) so the timed rows
     * below measure per-width cost, not the cold-start hit. */
    {
        char   (*ids)[PF_MAX_ID] = (char (*)[PF_MAX_ID])calloc(1, PF_MAX_ID);
        node_t   node;
        wures_t  r;
        DWORD    t0;
        if (ids) {
            strncpy(ids[0], "USB\\VID_FFFF&PID_0001", PF_MAX_ID - 1);
            log_console(PF_INFO, "Warming the WU cache (1 ID, up to %ds; this is the one-time "
                                 "sync)...", first_timeout);
            if (node_create(&node, ids, 1, NULL, 0, L"pnpfuzz WU benchmark warmup") == 0) {
                Sleep(500);
                t0 = GetTickCount();
                memset(&r, 0, sizeof(r));
                if (wu_search(ids, 1, first_timeout, &r) == 0)
                    log_console(PF_GOOD, "  warmup (1 ID): scan %6.1fs",
                                (double)(GetTickCount() - t0) / 1000.0);
                else
                    log_console(PF_WARN, "  warmup did not finish within %ds (%s). If even one ID "
                                         "cannot complete, the scan itself is the bottleneck, not "
                                         "the batch width.", first_timeout, r.error_msg);
                wu_free(&r);
                node_destroy(&node);
            }
            free(ids);
        }
    }

    log_console(PF_INFO, "----------------------------------------------------------------");

    for (i = 0; i < nw && !stopped; i++) {
        int      width = widths[i];
        char   (*ids)[PF_MAX_ID];
        double   wmin = 1e30, wmax = 0.0;
        int      completed = 0;

        if (width > max_width || width > PF_MAX_BATCH) continue;
        if (g_abort) break;

        ids = (char (*)[PF_MAX_ID])calloc((size_t)width, PF_MAX_ID);
        if (!ids) break;
        for (j = 0; j < width; j++)
            _snprintf(ids[j], PF_MAX_ID, "USB\\VID_FFFF&PID_%04X", (unsigned)(j & 0xFFFF));

        for (rep = 0; rep < reps && !g_abort; rep++) {
            node_t  node;
            wures_t r;
            wchar_t desc[128];
            DWORD   t0;

            _snwprintf(desc, 128, L"pnpfuzz WU benchmark (width %d rep %d)", width, rep);
            desc[127] = L'\0';

            if (node_create(&node, ids, width, NULL, 0, desc) != 0) {
                log_console(PF_WARN, "  width %5d : node creation FAILED - mechanical ceiling for "
                                     "one node on this host", width);
                stopped = 1;
                break;
            }
            Sleep(500);

            t0 = GetTickCount();
            memset(&r, 0, sizeof(r));
            if (wu_search(ids, width, wu_timeout, &r) == 0) {
                double secs = (double)(GetTickCount() - t0) / 1000.0;
                if (secs < wmin) wmin = secs;
                if (secs > wmax) wmax = secs;
                completed++;
                {
                    jb_t jb;
                    jb_init(&jb);
                    jb_num(&jb, "width", width);
                    jb_num(&jb, "rep", rep);
                    jb_num(&jb, "scan_seconds", secs);
                    jb_num(&jb, "driver_updates_returned", (double)r.total_updates);
                    log_event(PF_INFO, "wu_bench", jb_get(&jb));
                    jb_free(&jb);
                }
                wu_free(&r);
                node_destroy(&node);
            } else {
                log_console(PF_WARN, "  width %5d : did NOT finish within %ds (%s)",
                            width, wu_timeout, r.error_msg);
                wu_free(&r);
                node_destroy(&node);
                stopped = 1;            /* wider / more reps only slower */
                break;
            }
        }
        free(ids);

        if (completed > 0) {
            if (completed == reps)
                log_console(PF_GOOD, "  width %5d : %6.1f - %6.1fs over %d rep(s)  [stable]",
                            width, wmin, wmax, completed);
            else
                log_console(PF_WARN, "  width %5d : %6.1f - %6.1fs, only %d/%d rep(s) completed",
                            width, wmin, wmax, completed, reps);
            if (completed == reps) { best_width = width; best_worst = wmax; }
        }
    }

    log_console(PF_INFO, "----------------------------------------------------------------");
    if (best_width > 0) {
        int rec_to = (int)(best_worst * 1.3) + 5;   /* 30% margin over slowest  */
        log_console(PF_GOOD, "Widest fully-stable batch on this host: %d hardware IDs/scan.",
                    best_width);
        log_console(PF_GOOD, "Slowest scan seen at that width: %.1fs -> minimum stable timeout "
                             "~%ds.", best_worst, rec_to);
        log_console(PF_GOOD, "Recommended:  --batch %d  --wu-timeout %d", best_width, rec_to);
        log_console(PF_INFO, "If the seconds barely grew with width, cost is FIXED - a larger "
                             "--batch is free and cuts the number of scans. If they grew, cost "
                             "scales with ID count and %d is your sweet spot.", best_width);
        {
            jb_t jb;
            jb_init(&jb);
            jb_num(&jb, "best_stable_width", best_width);
            jb_num(&jb, "slowest_scan_seconds", best_worst);
            jb_num(&jb, "recommended_wu_timeout", rec_to);
            log_event(PF_GOOD, "wu_bench_result", jb_get(&jb));
            jb_free(&jb);
        }
    } else {
        log_console(PF_ERR, "No width completed within %ds. The bottleneck is the WU scan latency "
                            "itself, not the batch width - a single scan can't finish in your "
                            "budget on this host.", wu_timeout);
        log_console(PF_ERR, "Raise --wu-timeout above the warmup time you saw above, or the WU "
                            "scan on this VM is impaired (it returned in minutes with zero "
                            "drivers earlier). No batch width can fix a slow scan.");
    }
    return (best_width > 0) ? 0 : 1;
}

/* ---------------------------------------------------------------- sweep -- */

#define PF_DS_MAX 512   /* driver matches recorded per batch */

static int run_sweep(config *cfg, stats *st)
{
    uint64_t index, end;
    pf_strset  *present = NULL;
    char   (*ids)[PF_MAX_ID] = NULL;
    char     compat[PF_MAX_COMPAT][PF_MAX_ID];
    drvmatch_t *dsm = NULL;
    int      slots;
    int      rc = 0;

    /* Auto-batch state. eff_width is the current user-ID budget per batch.
     * When have_ref is set, a known-good reference rides every batch as a
     * canary: if a search comes back without it, Windows Update truncated the
     * ID list and the batch's coverage cannot be trusted. */
    int      eff_width;
    int      have_ref = 0;
    int      need_calib = 0;
    char     ref[PF_MAX_ID];
    /* If Windows Update returns literally nothing for search after search, the
     * WU axis is dead on this host and the operator should know rather than
     * burn hours reading it as "no drivers exist for these IDs". */
    int      wu_empty_streak = 0, wu_ever_returned = 0, wu_dead_warned = 0;
    /* The first WU search of the process pays a one-time online sync that can
     * take several minutes on a fresh machine; give it room so it does not trip
     * the timeout and strand the whole run. */
    int      first_wu = 1, wu_fail_streak = 0;
    /* Bounded retries for a search that does not complete (timeout / BUSY): a
     * transient WU stall on a long run retries instead of killing the sweep. */
    int      wu_stall_streak = 0;
    /* Collapse guard. If the canary is never returned even after the width has
     * been halved below the sanity floor, it is not a valid canary for this
     * sweep (usually a foreign vendor) - disable it and continue at a healthy
     * width rather than ratchet down to one ID per search. */
    int      canary_ever_seen = 0;
    /* Coverage bookkeeping for the unverified opening phase. Until a canary
     * exists, batches run at a start width nothing has proven, so if calibration
     * later measures a SMALLER lossless width those ranges may have been
     * truncated. Remember where the unverified region began and the widest batch
     * used in it, so the sweep can re-run exactly that region once it knows the
     * true width. Without this the run would silently under-report the prefix. */
    uint64_t unverified_from = 0;
    uint64_t probed_at_unverified_start = 0;
    uint64_t skipped_at_unverified_start = 0;
    int      unverified_maxw = 0;
    int      resweep_done = 0;
    /* Hits already reported, so a re-swept range does not duplicate rows in the
     * console, the CSV or the counters. Keyed by source + hardware ID. */
    pf_strset *reported = NULL;
    /* VID last announced by the per-VID header. Multi-VID sweeps walk VID as the
     * outermost axis, so this advances exactly once per vendor. Seeded to a value
     * no 16-bit VID can equal, and computed from the axis position (not a running
     * counter) so a resume mid-space still prints the right "VID k of n". */
    long     cur_vid_announced = -1;
    ref[0] = '\0';

    if (cfg->auto_batch && cfg->resume_active && cfg->resume_width > 0) {
        /* Resuming an interrupted auto-batch run: restore the width we had
         * already calibrated rather than paying for calibration again. The
         * canary still guards every batch, so this is safe even if the host
         * has drifted since. */
        eff_width = cfg->resume_width;
        if (eff_width > cfg->auto_batch_max) eff_width = cfg->auto_batch_max;
        if (cfg->resume_ref[0] && ref_vid_in_space(&cfg->space, cfg->resume_ref) &&
            eff_width >= PF_WIDTH_TRUST_MIN) {
            strncpy(ref, cfg->resume_ref, PF_MAX_ID - 1);
            ref[PF_MAX_ID - 1] = '\0';
            have_ref = 1;
            log_console(PF_GOOD, "Auto-batch: resuming at width %d, %s as canary "
                                 "(skipping re-calibration).", eff_width, ref);
        } else if (cfg->resume_ref[0] && ref_vid_in_space(&cfg->space, cfg->resume_ref)) {
            /* The checkpoint carries a collapsed width. Resuming on it would
             * inherit the previous run's damage and crawl exactly as that run
             * did. The canary itself is this vendor's, so re-measure with it and
             * carry on from where the run stopped at a healthy width. */
            int w;
            log_console(PF_WARN, "Auto-batch: the saved checkpoint has a collapsed width (%d). "
                                 "Re-measuring before continuing so this run does not inherit "
                                 "the last one's collapse.", eff_width);
            log_event(PF_WARN, "resume_width_distrusted", "\"action\":\"recalibrating\"");
            w = autobatch_calibrate(cfg->resume_ref, 1, cfg->auto_batch_max, cfg->wu_timeout);
            if (w > 0) {
                eff_width = w;
                strncpy(ref, cfg->resume_ref, PF_MAX_ID - 1);
                ref[PF_MAX_ID - 1] = '\0';
                have_ref = 1;
                width_cache_write(cfg, eff_width, ref, PF_ORIGIN_CALIBRATED);
                log_console(PF_GOOD, "Auto-batch: repaired - resuming at measured width %d, "
                                     "%s as canary.", eff_width, ref);
            } else {
                eff_width  = PF_AUTO_BATCH_START;
                if (eff_width > cfg->auto_batch_max) eff_width = cfg->auto_batch_max;
                need_calib = 1;
                log_console(PF_WARN, "Auto-batch: could not re-measure from the saved canary; "
                                     "continuing unverified at width %d.", eff_width);
            }
        } else {
            need_calib = 1;   /* no usable reference yet; keep looking */
            /* Never resume ON a collapsed width with no canary to justify it. */
            if (eff_width < PF_WIDTH_TRUST_MIN) {
                eff_width = cfg->batch_given ? cfg->batch : PF_AUTO_BATCH_START;
                if (eff_width > cfg->auto_batch_max) eff_width = cfg->auto_batch_max;
                if (eff_width < PF_WIDTH_TRUST_MIN) eff_width = PF_WIDTH_TRUST_MIN;
            }
            if (cfg->resume_ref[0])
                log_console(PF_WARN, "Auto-batch: resume canary %s is a different vendor than "
                                     "this sweep; ignoring it and continuing unverified.",
                            cfg->resume_ref);
            else
                log_console(PF_INFO, "Auto-batch: resuming at floor width %d; will calibrate on "
                                     "the next Windows Update hit.", eff_width);
        }
    } else if (cfg->auto_batch) {
        if (cfg->ref_id[0]) {
            int w;
            strncpy(ref, cfg->ref_id, PF_MAX_ID - 1);
            ref[PF_MAX_ID - 1] = '\0';
            /* Calibrating from 1 also validates the reference: width 1 is the
             * reference alone, so a -1 result means WU does not answer for it. */
            w = autobatch_calibrate(ref, 1, cfg->auto_batch_max, cfg->wu_timeout);
            if (w < 0) {
                eff_width = cfg->batch;
                if (eff_width > cfg->auto_batch_max) eff_width = cfg->auto_batch_max;
                log_console(PF_WARN, "--ref-id %s is not answered by Windows Update on this "
                                     "host, so it cannot anchor auto-tuning. Falling back to "
                                     "unverified width %d (no canary).", ref, eff_width);
                ref[0] = '\0';   /* unusable as a canary */
            } else {
                eff_width = w;
                have_ref  = 1;
                log_console(PF_GOOD, "Auto-batch: riding width %d, %s as canary.", eff_width, ref);
                width_cache_write(cfg, eff_width, ref, PF_ORIGIN_CALIBRATED);
            }
        } else {
            /* No reference yet. Try the per-host cache from a previous run on
             * this machine before falling back to an unverified start width. */
            int   cw = 0;
            char  cref[PF_MAX_ID] = {0};
            char  corigin[32] = {0};
            int   distrust = 0;

            /* Re-validate the cached reference with one search before trusting
             * it as a canary. A stale ref that WU no longer answers for would
             * make every batch look truncated and collapse the width. One
             * search, versus ~12 for a full calibration.
             *
             * First reject a cached canary from a DIFFERENT vendor than this
             * sweep: it validates fine on its own (that is all the re-validation
             * search tests) but is then crowded out of every populated batch,
             * which reads as truncation and collapses the width to 1. This is
             * exactly what bites when a cached ref from an earlier run on vendor
             * A is reused for a sweep of vendor B. */
            if (width_cache_read(cfg, &cw, cref, sizeof(cref),
                                 corigin, sizeof(corigin)) == 0 && cw > 0 && cref[0] &&
                !ref_vid_in_space(&cfg->space, cref)) {
                log_console(PF_WARN, "Auto-batch: cached canary %s is a different vendor than "
                                     "this sweep - it would be crowded out of every batch and "
                                     "collapse the width. Ignoring the cache.", cref);
                log_console(PF_WARN, "            Pass --ref-id with an ID Windows Update answers "
                                     "for THIS vendor to auto-tune with a valid canary; otherwise "
                                     "the sweep runs unverified (or use a fixed --batch).");
                cref[0] = '\0';   /* fall through to the unverified-start path */
            }

            /* A cached width is only ridden if it is plausibly this host's real
             * limit. A width that came from runtime HALVING, or any width under
             * the trust floor, is the residue of an earlier collapse - riding it
             * would inherit the previous run's damage. Re-measure instead, which
             * also repairs the cache entry. */
            if (cref[0] && cw > 0 &&
                (cw < PF_WIDTH_TRUST_MIN || strcmp(corigin, PF_ORIGIN_CALIBRATED) != 0)) {
                distrust = 1;
                log_console(PF_WARN, "Auto-batch: cached width %d for this host looks degraded "
                                     "(%s). That is the residue of an earlier collapse, not a "
                                     "measured limit - re-measuring it now.",
                            cw, cw < PF_WIDTH_TRUST_MIN ? "below the trust floor"
                                                        : "produced by halving, not calibration");
                log_event(PF_WARN, "width_cache_distrusted",
                          "\"action\":\"recalibrating\"");
            }

            if (cref[0] && distrust) {
                /* Full binary search against the cached canary, which is already
                 * vendor-checked above. This both repairs the width and proves
                 * the canary in one pass. */
                int w = autobatch_calibrate(cref, 1, cfg->auto_batch_max, cfg->wu_timeout);
                if (w > 0) {
                    eff_width = w;
                    strncpy(ref, cref, PF_MAX_ID - 1);
                    ref[PF_MAX_ID - 1] = '\0';
                    have_ref = 1;
                    width_cache_write(cfg, eff_width, ref, PF_ORIGIN_CALIBRATED);
                    log_console(PF_GOOD, "Auto-batch: repaired - measured width %d on this host, "
                                         "%s as canary. Cache updated.", eff_width, ref);
                } else {
                    cref[0] = '\0';   /* canary is dead too; fall through */
                    log_console(PF_WARN, "Auto-batch: the cached canary is no longer answered by "
                                         "Windows Update either. Discarding the cache entirely.");
                }
            }

            if (cref[0] && have_ref) {
                /* repaired above; nothing further to do */
            } else if (cref[0] && autobatch_test_width(cref, cw, cfg->wu_timeout) == 1) {
                /* Probe the canary AT the cached width, not at width 1: that
                 * validates the width and the canary in a single search. */
                eff_width = cw > cfg->auto_batch_max ? cfg->auto_batch_max : cw;
                strncpy(ref, cref, PF_MAX_ID - 1);
                ref[PF_MAX_ID - 1] = '\0';
                have_ref = 1;
                log_console(PF_GOOD, "Auto-batch: using cached width %d for this host "
                                     "(build %lu %s), %s as canary (re-validated at that "
                                     "width).",
                            eff_width, (unsigned long)cfg->os_build, cfg->os_arch, ref);
            } else if (cref[0]) {
                /* Canary is good in principle but did not survive the cached
                 * width: the host's limit moved. Re-measure rather than guess. */
                int w = autobatch_calibrate(cref, 1, cfg->auto_batch_max, cfg->wu_timeout);
                if (w > 0) {
                    eff_width = w;
                    strncpy(ref, cref, PF_MAX_ID - 1);
                    ref[PF_MAX_ID - 1] = '\0';
                    have_ref = 1;
                    width_cache_write(cfg, eff_width, ref, PF_ORIGIN_CALIBRATED);
                    log_console(PF_GOOD, "Auto-batch: cached width no longer holds; re-measured "
                                         "to %d. Cache updated.", eff_width);
                }
            }

            if (!have_ref) {
                /* Without a reference no canary can be injected, so this width
                 * is unverified whatever we pick - running at the halving floor
                 * bought no safety and cost an order of magnitude in speed. */
                eff_width  = cfg->batch_given ? cfg->batch : PF_AUTO_BATCH_START;
                if (eff_width > cfg->auto_batch_max) eff_width = cfg->auto_batch_max;
                need_calib = 1;
                log_console(PF_WARN, "Auto-batch: no --ref-id and nothing cached for this host, "
                                     "so there is no canary yet. Running UNVERIFIED at width %d "
                                     "(override with --batch).", eff_width);
                log_console(PF_WARN, "            If Windows Update truncates the ID list above "
                                     "that width, hits past it would be missed silently. Give "
                                     "--ref-id <a hardware ID WU answers for> to get a verified, "
                                     "calibrated width.");
            }
        }
    } else {
        eff_width = cfg->batch;
    }
    if (eff_width < 1) eff_width = 1;
    if (eff_width > cfg->auto_batch_max && cfg->auto_batch) eff_width = cfg->auto_batch_max;

    /* Sized for the widest batch we could ever assemble: the effective width,
     * plus one canary slot, plus up to a full combination's IDs of overshoot
     * on the first combination. eff_width is normally bounded by auto_batch_max
     * in auto mode, and every assignment is clamped to it, but --batch can be
     * larger than auto_batch_max on the command line; size for the max of the
     * two so the sizing holds regardless of clamp ordering. */
    {
        int cap = cfg->auto_batch
                    ? (cfg->auto_batch_max > cfg->batch ? cfg->auto_batch_max : cfg->batch)
                    : cfg->batch;
        slots = cap + 8;
    }
    ids = (char (*)[PF_MAX_ID])calloc((size_t)slots, PF_MAX_ID);
    dsm = (drvmatch_t *)calloc(PF_DS_MAX, sizeof(drvmatch_t));
    if (!ids || !dsm) { rc = 1; goto done; }

    end = space_total(&cfg->space);
    /* Written as a subtraction so a huge --limit cannot wrap start+limit and
     * silently produce an empty sweep that still exits 0. main() has already
     * guaranteed cfg->start < end. */
    if (cfg->limit && cfg->limit < end - cfg->start) end = cfg->start + cfg->limit;

    /* Scan starts at the resume point when continuing an interrupted run, but
     * only if it falls inside this invocation's window. cfg->start stays the
     * window base so progress and ETA are still measured against the whole
     * requested range. */
    index = cfg->start;
    if (cfg->resume_active && cfg->resume_from > cfg->start && cfg->resume_from < end)
        index = cfg->resume_from;

    if (!cfg->no_exclude) {
        present = pf_strset_new();
        if (present) {
            int n = collect_present_bus_ids(present,
                                            pf_bus_enumerator(cfg->space.bus));
            log_console(PF_INFO, "Excluding %d %s hardware ID(s) already present on this "
                                 "host (--no-exclude to disable)",
                        n < 0 ? 0 : n, pf_bus_name(cfg->space.bus));
        }
    }

    /* Pre-scan the requested window for target IDs that are already present /
     * installed on this host, and say so up front. Windows Update only returns
     * drivers that are NOT installed (IsInstalled=0), so such a target yields
     * zero WU hits even when a driver exists - which reads as a false miss. By
     * default these IDs are also skipped outright by the exclusion set. Either
     * way the operator needs to know before they interpret a zero. The scan is
     * bounded so a huge multi-axis space cannot stall preflight; for a partial
     * scan we say how far we looked. */
    if (present && pf_strset_count(present) > 0) {
        const uint64_t PRESCAN_CAP = 100000;
        uint64_t j, scanned = 0, present_hits = 0;
        char sample[3][PF_MAX_ID];
        int n_sample = 0, si;
        for (j = index; j < end && scanned < PRESCAN_CAP; j++, scanned++) {
            combo_t c;
            space_at(&cfg->space, j, &c);
            if (pf_strset_has(present, c.ids[0])) {
                present_hits++;
                if (n_sample < 3) {
                    strncpy(sample[n_sample], c.ids[0], PF_MAX_ID - 1);
                    sample[n_sample][PF_MAX_ID - 1] = '\0';
                    n_sample++;
                }
            }
        }
        if (present_hits > 0) {
            jb_t jb;
            log_console(PF_WARN, "%llu target ID(s) in this run are ALREADY present/installed "
                                 "on this host. By default they are skipped; even with "
                                 "--no-exclude, Windows Update filters not-installed drivers "
                                 "(IsInstalled=0), so they report zero WU hits even when a "
                                 "driver exists (a false miss).",
                                 (unsigned long long)present_hits);
            for (si = 0; si < n_sample; si++)
                log_console(PF_WARN, "    already present: %s", sample[si]);
            log_console(PF_WARN, "    To test WU acquisition for these, remove the local package "
                                 "(pnputil /delete-driver oemNN.inf /uninstall /force) and unplug "
                                 "the real device, or use --install-all (which does not depend on "
                                 "the not-installed filter).");
            if (scanned >= PRESCAN_CAP && (end - index) > PRESCAN_CAP)
                log_console(PF_WARN, "    (checked the first %llu of %llu target IDs; the true "
                                     "count may be higher)",
                                     (unsigned long long)PRESCAN_CAP,
                                     (unsigned long long)(end - index));
            jb_init(&jb);
            jb_u64(&jb, "target_ids_already_present", present_hits);
            jb_bool(&jb, "excluded_by_default", !cfg->no_exclude);
            jb_bool(&jb, "prescan_partial",
                    (scanned >= PRESCAN_CAP && (end - index) > PRESCAN_CAP) ? 1 : 0);
            log_event(PF_WARN, "targets_already_present", jb_get(&jb));
            jb_free(&jb);
        }
    }

    unverified_from = index;    /* where an unverified opening phase would begin */
    probed_at_unverified_start  = st->probed;
    skipped_at_unverified_start = st->skipped_present;
    reported = pf_strset_new();

    while (index < end && !g_abort) {
        int n_user = 0, n_send = 0, n_combo = 0, n_compat = 0;
        int canary_injected = 0;   /* we appended it            */
        int canary_present  = 0;   /* it is in the sent ID list */
        node_t node;
        wchar_t desc[256];
        uint64_t batch_first = index;
        int i, k, ds_found = 0, wu_found = 0;
        int wu_ran_ok = 0, canary_seen = 0, lossy = 0;
        int wu_fatal = 0, wu_incomplete = 0;
        /* VID of this batch, taken from its first combination. A batch never
         * spans a VID change, so this identifies the whole batch. */
        unsigned batch_vid = 0;
        int      batch_vid_set = 0;
        /* The canary occupies one slot OF the measured width. Calibration
         * measures the total list length Windows Update honours (reference at
         * the tail), so if the canary were appended on top of a full eff_width
         * of user IDs it would sit one entry past the proven boundary and trip
         * on the very first batch. */
        int budget = eff_width - (have_ref ? 1 : 0);
        char first_hit[PF_MAX_ID];
        long long sa_from, sa_to;
        DWORD batch_t0 = GetTickCount();
        jb_t jb;
        /* Snapshot the running counters so a canary rollback, which re-runs the
         * same index range, does not double-count it. */
        uint64_t save_probed = st->probed;
        uint64_t save_skipped = st->skipped_present;
        uint64_t save_batches = st->batches;

        first_hit[0] = '\0';
        if (budget < 1) budget = 1;

        /* --- assemble a batch (user IDs bounded by the canary-adjusted width) */
        while (index < end && n_user < budget) {
            combo_t c;
            int skipped = 0;

            space_at(&cfg->space, index, &c);

            /* Keep every batch within a single VID. VID is the outermost axis,
             * so once it changes this vendor is exhausted; ending the batch here
             * makes per-VID progress exact and keeps each probe node's IDs under
             * one vendor. The first combination sets the batch VID and never
             * breaks (or a batch could not advance). */
            if (!batch_vid_set) {
                batch_vid = c.vid;
                batch_vid_set = 1;
            } else if (c.vid != batch_vid) {
                break;
            }

            if (n_combo == 0) {
                n_compat = c.n_compat;
                for (k = 0; k < c.n_compat; k++) {
                    strncpy(compat[k], c.compat[k], PF_MAX_ID - 1);
                    compat[k][PF_MAX_ID - 1] = '\0';
                }
            } else {
                /* Compatible IDs live on the node, not on individual hardware
                 * IDs, so a batch must not span a change in them. PID is the
                 * fastest axis, so this only trips when a slower axis rolls. */
                if (c.n_compat != n_compat) break;
                for (k = 0; k < n_compat; k++)
                    if (_stricmp(compat[k], c.compat[k]) != 0) break;
                if (k < n_compat) break;
            }

            /* Never break on the first combination, or a batch narrower than
             * one combination's ID count would never advance the index. */
            if (n_combo > 0 && n_user + c.n_ids > budget) break;

            if (present && pf_strset_has(present, c.ids[0])) {
                st->skipped_present++;
                skipped = 1;
            }

            if (!skipped) {
                for (k = 0; k < c.n_ids; k++) {
                    strncpy(ids[n_user], c.ids[k], PF_MAX_ID - 1);
                    ids[n_user][PF_MAX_ID - 1] = '\0';
                    n_user++;
                }
                n_combo++;
            }
            index++;
            st->probed++;
        }

        if (n_user == 0) {
            checkpoint_write(cfg, index, eff_width, have_ref ? ref : NULL);
            continue;
        }

        st->batches++;
        n_send = n_user;

        /* --- inject the canary, unless the reference is already in this batch */
        if (have_ref) {
            int already = 0;
            for (k = 0; k < n_user; k++)
                if (_stricmp(ids[k], ref) == 0) { already = 1; break; }
            if (already) {
                canary_present = 1;
            } else if (n_user + 1 <= eff_width) {
                strncpy(ids[n_send], ref, PF_MAX_ID - 1);
                ids[n_send][PF_MAX_ID - 1] = '\0';
                n_send++;
                canary_injected = 1;
                canary_present  = 1;
            }
            /* If it will not fit inside the measured width (degenerate widths,
             * or a first-combination overshoot), send the user IDs alone rather
             * than push one entry past the boundary calibration proved. The
             * batch is simply unverified; a canary sitting outside the proven
             * range would report truncation that is our own doing. */
        }

        /* --- create the probe node -------------------------------------- */
        _snwprintf(desc, 256, L"pnpfuzz probe (%hs .. %hs)", ids[0], ids[n_user - 1]);
        desc[255] = L'\0';

        jb_init(&jb);
        jb_u64(&jb, "first_index", batch_first);
        jb_u64(&jb, "last_index", index - 1);
        jb_num(&jb, "hardware_ids", n_user);
        jb_num(&jb, "combinations", n_combo);
        jb_num(&jb, "batch_width", eff_width);
        jb_bool(&jb, "canary", canary_injected);
        log_event(PF_INFO, "batch_start", jb_get(&jb));
        jb_free(&jb);

        /* Per-VID header, printed the first time each vendor is reached. Only
         * shown when more than one VID is in play; the ordinal is the VID's
         * position in the --vid list, so it is correct even on a resumed run. */
        if (cfg->space.vid.n > 1 && batch_vid_set && (long)batch_vid != cur_vid_announced) {
            int vi, vid_ord = 0;
            for (vi = 0; vi < cfg->space.vid.n; vi++)
                if (cfg->space.vid.v[vi] == batch_vid) { vid_ord = vi + 1; break; }
            cur_vid_announced = (long)batch_vid;
            log_console(PF_GOOD, "==== VID %d/%d: USB\\VID_%04X - sweeping its PID range ====",
                        vid_ord, cfg->space.vid.n, batch_vid);
            {
                jb_t vjb;
                jb_init(&vjb);
                jb_num(&vjb, "vid_ordinal", vid_ord);
                jb_num(&vjb, "vid_count", cfg->space.vid.n);
                jb_u64(&vjb, "vid", batch_vid);
                log_event(PF_INFO, "vid_begin", jb_get(&vjb));
                jb_free(&vjb);
            }
        }

        /* Console heartbeat BEFORE the slow part. A batch spends almost all of
         * its wall time inside one Windows Update search (tens of seconds to the
         * --wu-timeout), during which nothing else printed - which read as a
         * hang. Announce the batch and what it is waiting on. */
        {
            uint64_t span = end - cfg->start;
            double   pct  = span ? (double)(batch_first - cfg->start) * 100.0 / (double)span : 0.0;
            log_console(PF_INFO, "[%llu/%llu %5.2f%%] batch %llu: %s .. %s | %d IDs w=%d%s",
                        (unsigned long long)(batch_first - cfg->start),
                        (unsigned long long)span, pct,
                        (unsigned long long)st->batches,
                        ids[0], ids[n_user - 1], n_user, eff_width,
                        cfg->no_wu ? "" : " | Windows Update search running...");
        }

        /* Widest batch used while no canary was guarding coverage. */
        if (!have_ref && eff_width > unverified_maxw) unverified_maxw = eff_width;

        watch_mark();
        sa_from = setupapi_size();

        if (node_create(&node, ids, n_send, n_compat ? compat : NULL, n_compat, desc) != 0) {
            log_console(PF_ERR, "batch at index %llu: node creation failed, skipping",
                        (unsigned long long)batch_first);
            checkpoint_write(cfg, index, eff_width, have_ref ? ref : NULL);
            continue;
        }

        if (cfg->settle_ms > 0) Sleep((DWORD)cfg->settle_ms);

        /* --- local DriverStore (probe now, report after canary check) --- */
        if (!cfg->no_driverstore)
            ds_found = node_probe_driverstore(&node, dsm, PF_DS_MAX);

        /* --- Windows Update --------------------------------------------- */
        {
            wures_t r;
            memset(&r, 0, sizeof(r));

            if (!cfg->no_wu && !g_abort) {
                int wu_to = cfg->wu_timeout;
                if (first_wu) wu_to = cfg->first_wu_timeout;  /* cold-sync allowance */

                if (wu_search(ids, n_send, wu_to, &r) == 0) {
                    wu_ran_ok = 1;
                    first_wu   = 0;
                    wu_fail_streak = 0;
                    wu_stall_streak = 0;   /* a completed search clears the stall count */
                    if (canary_present) {
                        for (i = 0; i < r.count; i++)
                            if (_stricmp(r.hits[i].matched, ref) == 0) { canary_seen = 1; break; }
                    }
                    if (canary_seen) canary_ever_seen = 1;

                    /* total_updates is the pre-filter count: every driver update
                     * WU offered this machine, ours or not. Zero, repeatedly, is
                     * a broken WU axis rather than a negative result. */
                    if (r.total_updates > 0) { wu_ever_returned = 1; wu_empty_streak = 0; }
                    else                       wu_empty_streak++;

                    /* Zero driver updates returned is AMBIGUOUS on its own. It
                     * means either Windows Update is blocked on this host, or WU
                     * is perfectly healthy and simply has no driver to offer for
                     * any ID tested so far - which for an unassigned or
                     * software-only vendor is the correct answer, not a fault.
                     * The two are indistinguishable without a positive control.
                     *
                     * A canary IS that control: if one has ever come back, WU
                     * demonstrably works and the zeros are real findings, so say
                     * nothing. Otherwise report the ambiguity honestly, and only
                     * call it broken when preflight actually found a blocker. */
                    if (!wu_dead_warned && !wu_ever_returned && !canary_ever_seen &&
                        wu_empty_streak >= 10) {
                        wu_dead_warned = 1;
                        if (cfg->wu_blockers > 0) {
                            log_console(PF_ERR, "Windows Update has returned ZERO driver updates "
                                                "for %d consecutive searches, and preflight found "
                                                "%d blocker(s). WU is not answering on this host, "
                                                "so these zeros are NOT evidence about the "
                                                "hardware IDs.",
                                        wu_empty_streak, cfg->wu_blockers);
                            log_console(PF_ERR, "Re-read the preflight lines above (WSUS, "
                                                "SearchOrderConfig, metered, wuauserv). Until it "
                                                "is fixed, --no-wu drops the per-batch WU search "
                                                "and probes the local DriverStore only, which is "
                                                "dramatically faster.");
                        } else {
                            log_console(PF_WARN, "Windows Update has returned zero driver updates "
                                                 "for %d consecutive searches. Preflight found no "
                                                 "blockers, so this is most likely the real "
                                                 "answer: WU has no driver for any ID tested so "
                                                 "far.", wu_empty_streak);
                            log_console(PF_WARN, "It cannot be proven from zeros alone, though - a "
                                                 "blocked WU looks identical. To settle it, pass "
                                                 "--ref-id with an ID Windows Update DOES answer "
                                                 "for on this host: if that comes back, the zeros "
                                                 "are genuine findings.");
                        }
                        jb_init(&jb);
                        jb_num(&jb, "consecutive_empty_searches", wu_empty_streak);
                        jb_num(&jb, "preflight_blockers", cfg->wu_blockers);
                        jb_bool(&jb, "conclusive", cfg->wu_blockers > 0);
                        log_event(cfg->wu_blockers > 0 ? PF_ERR : PF_WARN,
                                  "wu_returned_nothing", jb_get(&jb));
                        jb_free(&jb);
                    }
                } else if (r.error == (HRESULT)ERROR_TIMEOUT || r.error == (HRESULT)ERROR_BUSY) {
                    /* The search did not complete within the timeout (or a prior
                     * abandoned one is still outstanding). The batch was NOT
                     * searched - advancing past it would mark an unsearched range
                     * as covered. Rather than kill the whole run on one stall,
                     * recover: a wide batch may finish inside the timeout if it is
                     * smaller, so halve and redo the range; once at the floor it is
                     * a transient WU stall, so back off and retry a bounded number
                     * of times before finally halting. Every path preserves the
                     * checkpoint, so nothing is ever skipped. */
                    if (eff_width > PF_AUTO_BATCH_FLOOR) {
                        int nw = eff_width / 2;
                        if (nw < PF_AUTO_BATCH_FLOOR) nw = PF_AUTO_BATCH_FLOOR;
                        log_console(PF_WARN, "Windows Update search did not complete in %ds over "
                                             "%d ID(s) at index %llu. Halving width to %d and "
                                             "retrying this range.",
                                    wu_to, n_send, (unsigned long long)batch_first, nw);
                        eff_width = nw;
                        wu_stall_streak = 0;   /* a size fix, not a repeat stall */
                        wu_incomplete = 1;     /* redo the range at the smaller width */
                    } else if (++wu_stall_streak < PF_WU_RETRY_MAX) {
                        log_console(PF_WARN, "Windows Update search stalled at index %llu "
                                             "(attempt %d/%d). Backing off and retrying.",
                                    (unsigned long long)batch_first, wu_stall_streak,
                                    PF_WU_RETRY_MAX);
                        wu_incomplete = 1;     /* retry the same range after a backoff */
                    } else {
                        wu_fatal = 1;          /* wedged at the floor: give up cleanly */
                    }
                    first_wu = 0;
                } else {
                    st->wu_errors++;
                    /* Do NOT clear first_wu here: a transient COM error on the
                     * first attempt usually means the one-time sync never ran,
                     * so the retry should keep the 900s grace. The 3-strike rule
                     * still caps total attempts. */
                    log_console(PF_ERR, "Windows Update search failed: %s", r.error_msg);
                    /* A batch whose search errored was not searched either. Retry
                     * it a couple of times for a transient blip, then stop rather
                     * than skip over it. */
                    if (++wu_fail_streak >= 3) wu_fatal = 1;
                    else                        wu_incomplete = 1;
                }
            }

            /* --- a search that did not complete: do not advance over it ------ */
            if (wu_fatal || wu_incomplete) {
                index = batch_first;                 /* redo this range next time */
                st->probed = save_probed;
                st->skipped_present = save_skipped;
                st->batches = save_batches;
                wu_free(&r);
                node_destroy(&node);
                checkpoint_write(cfg, index, eff_width, have_ref ? ref : NULL);

                if (wu_fatal) {
                    log_console(PF_ERR, " ");
                    log_console(PF_ERR, "Windows Update searches are not completing on this host.");
                    log_console(PF_ERR, "Searches kept exceeding the timeout even after the batch "
                                        "was halved to the floor and retried %d times. Stopped at "
                                        "combination %llu WITHOUT searching it - nothing is marked "
                                        "done that was not, so re-running resumes from exactly "
                                        "here.",
                                PF_WU_RETRY_MAX, (unsigned long long)batch_first);
                    log_console(PF_ERR, "Windows Update itself is wedged or throttling. Options, "
                                        "then re-run to resume:");
                    log_console(PF_ERR, "  --wu-timeout 1800   give the initial sync room; once it "
                                        "completes, later searches are usually fast");
                    log_console(PF_ERR, "  --no-wu             skip Windows Update entirely, probe "
                                        "the local DriverStore only (seconds, not hours)");
                    log_console(PF_ERR, "  --batch 64          lighter searches if the search stays "
                                        "slow even after the first one completes");
                    log_event(PF_ERR, "wu_search_unrecoverable",
                              "\"action\":\"halted, checkpoint preserved\"");
                    rc = 3;                           /* visible to automation */
                    break;                            /* leave the sweep loop */
                }

                Sleep(2000);                          /* transient: brief backoff, then retry */
                continue;
            }

            /* A search that completed but dropped the canary means WU truncated
             * our ID list: this batch's other IDs were not all considered. */
            lossy = (canary_present && wu_ran_ok && !canary_seen);

            if (lossy && eff_width > PF_AUTO_BATCH_FLOOR && !g_abort) {
                int nw = eff_width / 2;
                if (nw < PF_AUTO_BATCH_FLOOR) nw = PF_AUTO_BATCH_FLOOR;

                /* Collapse guard. If the canary has NEVER been returned and the
                 * width is already halving below the sanity floor, it is not a
                 * valid canary for this sweep - almost always a different vendor
                 * than the IDs being swept, so Windows Update crowds it out of
                 * every populated batch and it reads as perpetual truncation.
                 * Ratcheting on would collapse to one ID per search for hours.
                 * Disable it, reset to a healthy width, and continue unverified
                 * so the sweep actually completes. */
                if (!canary_ever_seen && nw < PF_CANARY_GIVEUP_WIDTH) {
                    int rw = cfg->batch_given ? cfg->batch : PF_AUTO_BATCH_START;
                    if (rw > cfg->auto_batch_max) rw = cfg->auto_batch_max;
                    if (rw < PF_CANARY_GIVEUP_WIDTH) rw = PF_CANARY_GIVEUP_WIDTH;
                    log_console(PF_ERR, "Canary %s was never returned by Windows Update in any "
                                        "batch, down to width %d - it is not a valid canary for "
                                        "this sweep (typically a different vendor than the IDs "
                                        "being swept, so WU crowds it out).", ref, eff_width);
                    log_console(PF_WARN, "Disabling truncation detection and continuing at width "
                                         "%d so the sweep completes instead of collapsing to one "
                                         "ID per search. Coverage is NOT canary-verified.", rw);
                    log_console(PF_WARN, "For verified coverage, re-run with --ref-id set to an ID "
                                         "Windows Update answers for THIS vendor (e.g. a hit found "
                                         "so far), or prove a fixed width with --verify-batch.");
                    log_event(PF_ERR, "canary_abandoned",
                              "\"reason\":\"never_seen\",\"action\":\"disabled,continue_unverified\"");
                    have_ref   = 0;
                    ref[0]     = '\0';
                    need_calib = 0;
                    eff_width  = rw;
                    index = batch_first;          /* redo this range unverified */
                    st->probed = save_probed;
                    st->skipped_present = save_skipped;
                    st->batches = save_batches;
                    wu_free(&r);
                    node_destroy(&node);
                    checkpoint_write(cfg, index, eff_width, NULL);
                    continue;
                }

                log_console(PF_WARN, "Canary %s missing from the result: Windows Update "
                                     "truncated the batch at index %llu (width %d). Halving to "
                                     "%d and re-running this range.",
                            ref, (unsigned long long)batch_first, eff_width, nw);
                jb_init(&jb);
                jb_str(&jb, "reference", ref);
                jb_u64(&jb, "first_index", batch_first);
                jb_num(&jb, "old_width", eff_width);
                jb_num(&jb, "new_width", nw);
                log_event(PF_WARN, "batch_truncated_retry", jb_get(&jb));
                jb_free(&jb);

                eff_width = nw;
                /* Persist the corrected width, but never a collapsed one. A
                 * transient WU outage makes every batch look truncated, and a
                 * cached width below the floor would pin future runs on this host
                 * to tiny searches with no way back. */
                if (nw >= PF_AUTO_BATCH_FLOOR)
                    width_cache_write(cfg, eff_width, ref, PF_ORIGIN_HALVED);
                index = batch_first;          /* redo this range, nothing reported */
                st->probed = save_probed;     /* undo this batch's counters      */
                st->skipped_present = save_skipped;
                st->batches = save_batches;
                wu_free(&r);
                node_destroy(&node);
                checkpoint_write(cfg, index, eff_width, have_ref ? ref : NULL);
                continue;
            }
            if (lossy) {
                /* At the floor and still losing the canary that WAS seen earlier:
                 * genuine truncation at the floor. (A canary never seen at all is
                 * caught by the collapse guard above, so it does not reach here.) */
                log_console(PF_ERR, "Canary %s missing at width %d (floor). Windows Update is "
                                    "truncating regardless of batch size; coverage for this batch "
                                    "is NOT guaranteed. Treat results as partial.",
                            ref, eff_width);
                log_event(PF_ERR, "batch_truncated_unrecoverable", NULL);
            }

            /* --- kept batch: report DriverStore then Windows Update ------ */
            for (i = 0; i < ds_found && i < PF_DS_MAX; i++) {
                char key[PF_MAX_ID + 4];
                if (canary_injected && _stricmp(dsm[i].hwid, ref) == 0) continue;
                /* A re-swept range must not report the same match twice. */
                _snprintf(key, sizeof(key), "D:%s", dsm[i].hwid);
                key[sizeof(key) - 1] = '\0';
                if (reported && pf_strset_add(reported, key) == 0) continue;
                report_ds_match(&dsm[i], st);
            }

            for (i = 0; i < r.count; i++) {
                char key[PF_MAX_ID + 4];
                if (canary_injected && _stricmp(r.hits[i].matched, ref) == 0) continue;
                if (first_hit[0] == '\0') {
                    strncpy(first_hit, r.hits[i].matched, PF_MAX_ID - 1);
                    first_hit[PF_MAX_ID - 1] = '\0';
                }
                _snprintf(key, sizeof(key), "W:%s", r.hits[i].matched);
                key[sizeof(key) - 1] = '\0';
                if (reported && pf_strset_add(reported, key) == 0) { wu_found++; continue; }
                report_wu_hit(&r.hits[i], st);
                wu_found++;
            }

            /* Install pass, gated on what the query actually found. */
            if (cfg->mode == MODE_INSTALL && r.count > 0 && !g_abort) {
                for (i = 0; i < r.count && !g_abort; i++) {
                    if (canary_injected && _stricmp(r.hits[i].matched, ref) == 0) continue;
                    install_one(r.hits[i].matched, cfg, st,
                                n_compat ? compat : NULL, n_compat);
                }
            }
            wu_free(&r);
        }

        /* DriverStore hits are worth installing too, but only when the Windows
         * Update pass found nothing, so the same ID is not installed twice. */
        if (cfg->mode == MODE_INSTALL && ds_found > 0 && wu_found == 0 && !g_abort) {
            for (i = 0; i < ds_found && i < PF_DS_MAX && !g_abort; i++) {
                if (canary_injected && _stricmp(dsm[i].hwid, ref) == 0) continue;
                if (!dsm[i].compat_only)
                    install_one(dsm[i].hwid, cfg, st, n_compat ? compat : NULL, n_compat);
            }
        }

        drain_pnp_events();

        /* --- blind install pass ----------------------------------------- */
        if (cfg->mode == MODE_INSTALL_ALL && !g_abort) {
            if (node_trigger_pnp_install(&node) == 0) {
                drvmatch_t bound;
                if (node_wait_installed(&node, cfg->install_timeout, &g_abort, &bound) == 0) {
                    st->installs_ok++;
                    log_console(PF_GOOD, "INSTALLED (blind) %s -> %s / %s",
                                bound.hwid[0] ? bound.hwid : "?",
                                bound.provider, bound.desc);
                    log_hit_csv(bound.hwid, "installed-blind", "hardware", bound.provider,
                                bound.desc, bound.cls, bound.version, bound.inf, "");
                }
            }
            drain_pnp_events();
        }

        sa_to = setupapi_size();
        if (cfg->setupapi_slices && (ds_found || wu_found) && sa_from >= 0 && sa_to > sa_from) {
            char tag[64];
            _snprintf(tag, sizeof(tag), "batch-%llu", (unsigned long long)batch_first);
            tag[sizeof(tag) - 1] = '\0';
            setupapi_slice(sa_from, sa_to, tag);
        }

        if (!cfg->keep) {
            node_destroy(&node);
        } else {
            log_console(PF_WARN, "--keep: %s left registered", node.instance_id_a);
            node.created = 0;   /* keep the devnode, still release our handles */
            node_destroy(&node);
        }

        jb_init(&jb);
        jb_u64(&jb, "first_index", batch_first);
        jb_num(&jb, "driverstore_matches", ds_found);
        jb_num(&jb, "windows_update_matches", wu_found);
        jb_num(&jb, "batch_width", eff_width);
        jb_u64(&jb, "elapsed_ms", GetTickCount() - batch_t0);
        log_event(PF_INFO, "batch_end", jb_get(&jb));
        jb_free(&jb);

        checkpoint_write(cfg, index, eff_width, have_ref ? ref : NULL);

        /* --- no --ref-id: calibrate from the first hit we discover ------- */
        if (need_calib && wu_found > 0 && first_hit[0] && !g_abort) {
            int w;
            need_calib = 0;
            strncpy(ref, first_hit, PF_MAX_ID - 1);
            ref[PF_MAX_ID - 1] = '\0';
            log_console(PF_INFO, "Discovered a Windows Update reference (%s); calibrating "
                                 "batch width from it.", ref);
            w = autobatch_calibrate(ref, 1, cfg->auto_batch_max, cfg->wu_timeout);
            if (w > 0) {
                eff_width = w;
                have_ref  = 1;
                log_console(PF_GOOD, "Auto-batch: riding width %d for the rest of the sweep, "
                                     "%s as canary.", eff_width, ref);
                width_cache_write(cfg, eff_width, ref, PF_ORIGIN_CALIBRATED);

                /* The opening phase ran before any width was proven. If it used
                 * batches WIDER than the width just measured, Windows Update may
                 * have truncated them and hits in that region could have been
                 * missed. Re-run exactly that region at the verified width, with
                 * the canary now guarding every batch. Done at most once: after
                 * this have_ref stays set, so no new unverified region forms. */
                if (!resweep_done && unverified_maxw > eff_width &&
                    unverified_from < index) {
                    resweep_done = 1;
                    log_console(PF_WARN, "The opening %llu combination(s) were swept at width "
                                         "%d, before any width was proven, and the measured "
                                         "lossless width is only %d. Windows Update may have "
                                         "truncated them.",
                                (unsigned long long)(index - unverified_from),
                                unverified_maxw, eff_width);
                    log_console(PF_GOOD, "Re-running that range at the verified width so "
                                         "coverage is complete. Nothing is reported twice.");
                    jb_init(&jb);
                    jb_u64(&jb, "from_index", unverified_from);
                    jb_u64(&jb, "to_index", index);
                    jb_num(&jb, "unverified_width", unverified_maxw);
                    jb_num(&jb, "verified_width", eff_width);
                    log_event(PF_WARN, "unverified_prefix_resweep", jb_get(&jb));
                    jb_free(&jb);

                    index = unverified_from;
                    st->probed = probed_at_unverified_start;
                    st->skipped_present = skipped_at_unverified_start;
                    checkpoint_write(cfg, index, eff_width, ref);
                    continue;
                }
            } else {
                ref[0] = '\0';          /* unusable as a canary */
                log_console(PF_WARN, "Could not calibrate from %s; continuing unverified at "
                                     "width %d.", first_hit, eff_width);
            }
        }

        /* --- progress --------------------------------------------------- */
        {
            double done_frac;
            double elapsed = (double)(GetTickCount() - st->t0) / 1000.0;
            char   eta[32] = "?";
            uint64_t span = end - cfg->start;

            done_frac = span ? (double)(index - cfg->start) / (double)span : 1.0;
            if (done_frac > 0.0005 && elapsed > 1.0)
                fmt_duration(elapsed / done_frac - elapsed, eta, sizeof(eta));

            log_console((ds_found || wu_found) ? PF_GOOD : PF_INFO,
                        "        -> done in %.1fs | ds=%d wu=%d | %5.2f%% | eta %s",
                        (double)(GetTickCount() - batch_t0) / 1000.0,
                        ds_found, wu_found, done_frac * 100.0, eta);
        }

        if (cfg->stop_on_first && (ds_found || wu_found)) {
            log_console(PF_GOOD, "--stop-on-first: halting at index %llu",
                        (unsigned long long)index);
            break;
        }
    }

    if (cfg->auto_batch && need_calib && !g_abort)
        log_console(PF_WARN, "Auto-batch: no Windows Update hit was found to calibrate from, so "
                             "this sweep ran UNVERIFIED at width %d throughout. Supply --ref-id "
                             "next time to get a measured width and a per-batch canary.",
                    eff_width);

done:
    free(ids);
    free(dsm);
    if (present) pf_strset_free(present);
    if (reported) pf_strset_free(reported);
    return rc;
}

/* ----------------------------------------------------------------- cli --- */

static int need_arg(int i, int argc, const char *opt)
{
    if (i + 1 >= argc) {
        fprintf(stderr, "[-] %s requires a value\n", opt);
        return 0;
    }
    return 1;
}

static void sig_append(char *sig, size_t cap, const char *s)
{
    size_t have = strlen(sig);
    size_t room;

    if (have + 1 >= cap) return;
    room = cap - have - 1;
    strncat(sig, s, room);
    sig[cap - 1] = '\0';
}

static void build_signature(config *cfg, int argc, char **argv)
{
    int i;

    cfg->sig[0] = '\0';
    for (i = 1; i < argc; i++) {
        /* Only the arguments that define the search space belong in the
         * signature; --resume, --logdir and friends must not invalidate it. */
        if (strcmp(argv[i], "--vid") == 0 || strcmp(argv[i], "--pid") == 0 ||
            strcmp(argv[i], "--ven") == 0 || strcmp(argv[i], "--dev") == 0 ||
            strcmp(argv[i], "--bus") == 0 || strcmp(argv[i], "--subsys") == 0 ||
            strcmp(argv[i], "--rev") == 0 || strcmp(argv[i], "--mi") == 0 ||
            strcmp(argv[i], "--class") == 0 || strcmp(argv[i], "--subclass") == 0 ||
            strcmp(argv[i], "--protocol") == 0) {
            if (i + 1 < argc) {
                sig_append(cfg->sig, sizeof(cfg->sig), argv[i] + 2);
                sig_append(cfg->sig, sizeof(cfg->sig), "=");
                sig_append(cfg->sig, sizeof(cfg->sig), argv[i + 1]);
                sig_append(cfg->sig, sizeof(cfg->sig), ";");
            }
        } else if (strcmp(argv[i], "--with-plain") == 0) {
            sig_append(cfg->sig, sizeof(cfg->sig), "with-plain;");
        }
    }
}

static int confirm_install(run_mode mode)
{
    char line[64];
    int  first = 0;

    fprintf(stderr,
"\n"
"  ############################################################\n"
"  #  %s\n"
"  #\n"
"  #  Windows will DOWNLOAD driver packages and execute vendor\n"
"  #  co-installers and services as NT AUTHORITY\\SYSTEM.\n"
"  #\n"
"  #  Removing the synthetic device node afterwards does NOT\n"
"  #  undo any of that: DriverStore packages, installed files,\n"
"  #  services and registry changes all persist.\n"
"  #\n"
"  #  Run this on a disposable VM with a snapshot, never on a\n"
"  #  machine you care about.\n"
"  ############################################################\n"
"\n"
"  Type 'yes' to continue: ",
        mode == MODE_INSTALL_ALL ? "BLIND INSTALL MODE (--install-all)"
                                 : "INSTALL MODE (--install)");
    fflush(stderr);

    if (!fgets(line, sizeof(line), stdin)) return 0;
    while (line[first] == ' ' || line[first] == '\t') first++;
    return (_strnicmp(line + first, "yes", 3) == 0) ? 1 : 0;
}

int main(int argc, char **argv)
{
    config   cfg;
    stats    st;
    sysinfo_t si;
    char     err[256];
    char     run_id[64];
    int      i, rc = 0;
    int      do_cleanup = 0, cleanup_dry = 0;
    const char *verify_id = NULL;
    HRESULT  hr;
    SYSTEMTIME now;

    memset(&cfg, 0, sizeof(cfg));
    memset(&st, 0, sizeof(st));
    cfg.batch           = 64;
    cfg.auto_batch      = 1;    /* self-tuning by default; --batch pins it */
    cfg.wu_timeout      = 300;
    cfg.install_timeout = 300;
    cfg.settle_ms       = 750;
    strcpy(cfg.logdir, ".\\pnpfuzz-logs");

    SetConsoleOutputCP(CP_UTF8);

    if (argc < 2) { usage(); return 2; }

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];

        if      (!strcmp(a, "--help") || !strcmp(a, "-h")) { usage(); return 0; }
        else if (!strcmp(a, "--version")) { printf("pnpfuzz %s\n", PF_VERSION); return 0; }
        else if (!strcmp(a, "--bus"))      { if (!need_arg(i,argc,a)) return 2;
                                             i++;
                                             if (!_stricmp(argv[i], "usb"))      cfg.space.bus = PF_BUS_USB;
                                             else if (!_stricmp(argv[i], "pci") ||
                                                      !_stricmp(argv[i], "pcie")) cfg.space.bus = PF_BUS_PCI;
                                             else { log_console(PF_ERR, "--bus: expected usb or pci"); return 2; } }
        /* PCI names its identifiers VEN/DEV; accept both spellings for either
         * bus so the muscle memory of each works. */
        else if (!strcmp(a, "--vid") || !strcmp(a, "--ven"))
                                           { if (!need_arg(i,argc,a)) return 2; if (axis_parse(&cfg.space.vid,  argv[++i], 0xFFFF, a))  return 2; }
        else if (!strcmp(a, "--pid") || !strcmp(a, "--dev"))
                                           { if (!need_arg(i,argc,a)) return 2; if (axis_parse(&cfg.space.pid,  argv[++i], 0xFFFF, a))  return 2; }
        else if (!strcmp(a, "--no-recon"))  cfg.no_recon = 1;
        else if (!strcmp(a, "--recon-only")) cfg.recon_only = 1;
        else if (!strcmp(a, "--cpl-all"))   cfg.cpl_all = 1;
        else if (!strcmp(a, "--cpl-account")) { if (!need_arg(i,argc,a)) return 2;
                                                strncpy(cfg.cpl_account, argv[++i], sizeof(cfg.cpl_account) - 1);
                                                cfg.cpl_account[sizeof(cfg.cpl_account) - 1] = 0; }
        else if (!strcmp(a, "--subsys"))   { if (!need_arg(i,argc,a)) return 2; if (axis_parse(&cfg.space.subsys, argv[++i], 0xFFFFFFFFu, "--subsys")) return 2; }
        else if (!strcmp(a, "--rev"))      { if (!need_arg(i,argc,a)) return 2; if (axis_parse(&cfg.space.rev,  argv[++i], 0xFFFF, "--rev"))  return 2; }
        else if (!strcmp(a, "--mi"))       { if (!need_arg(i,argc,a)) return 2; if (axis_parse(&cfg.space.mi,   argv[++i], 0xFF,   "--mi"))   return 2; }
        else if (!strcmp(a, "--class"))    { if (!need_arg(i,argc,a)) return 2; if (axis_parse(&cfg.space.cls,  argv[++i], 0xFF,   "--class")) return 2; }
        else if (!strcmp(a, "--subclass")) { if (!need_arg(i,argc,a)) return 2; if (axis_parse(&cfg.space.sub,  argv[++i], 0xFF,   "--subclass")) return 2; }
        else if (!strcmp(a, "--protocol")) { if (!need_arg(i,argc,a)) return 2; if (axis_parse(&cfg.space.prot, argv[++i], 0xFF,   "--protocol")) return 2; }
        else if (!strcmp(a, "--with-plain"))    cfg.space.with_plain = 1;
        else if (!strcmp(a, "--install"))       cfg.mode = MODE_INSTALL;
        else if (!strcmp(a, "--install-all"))   cfg.mode = MODE_INSTALL_ALL;
        else if (!strcmp(a, "--query"))         cfg.mode = MODE_QUERY;
        else if (!strcmp(a, "--no-wu"))         cfg.no_wu = 1;
        else if (!strcmp(a, "--no-driverstore")) cfg.no_driverstore = 1;
        else if (!strcmp(a, "--superseded"))    wu_set_superseded(1);
        else if (!strcmp(a, "--dump-raw-wu"))   { cfg.dump_raw_wu = 1; wu_set_dump_raw(1); }
        else if (!strcmp(a, "--batch"))         { if (!need_arg(i,argc,a)) return 2; cfg.batch = atoi(argv[++i]); cfg.batch_given = 1; }
        else if (!strcmp(a, "--auto-batch"))    { cfg.auto_batch = 1; cfg.auto_batch_given = 1; }
        else if (!strcmp(a, "--no-auto-batch")) { cfg.auto_batch = 0; cfg.auto_batch_given = 1; }
        else if (!strcmp(a, "--auto-batch-max")){ if (!need_arg(i,argc,a)) return 2; cfg.auto_batch_max = atoi(argv[++i]); }
        else if (!strcmp(a, "--ref-id"))        { if (!need_arg(i,argc,a)) return 2;
                                                  strncpy(cfg.ref_id, argv[++i], PF_MAX_ID - 1);
                                                  cfg.ref_id[PF_MAX_ID - 1] = '\0'; }
        else if (!strcmp(a, "--wu-timeout"))    { if (!need_arg(i,argc,a)) return 2; cfg.wu_timeout = atoi(argv[++i]); cfg.wu_timeout_given = 1; }
        else if (!strcmp(a, "--first-wu-timeout")) { if (!need_arg(i,argc,a)) return 2; cfg.first_wu_timeout = atoi(argv[++i]); }
        else if (!strcmp(a, "--bench-wu"))      cfg.bench_wu = 1;
        else if (!strcmp(a, "--bench-reps"))    { if (!need_arg(i,argc,a)) return 2; cfg.bench_reps = atoi(argv[++i]); }
        else if (!strcmp(a, "--install-timeout")) { if (!need_arg(i,argc,a)) return 2; cfg.install_timeout = atoi(argv[++i]); }
        else if (!strcmp(a, "--settle"))        { if (!need_arg(i,argc,a)) return 2; cfg.settle_ms = atoi(argv[++i]); }
        else if (!strcmp(a, "--start"))         { if (!need_arg(i,argc,a)) return 2; cfg.start = _strtoui64(argv[++i], NULL, 10); cfg.start_given = 1; }
        else if (!strcmp(a, "--limit"))         { if (!need_arg(i,argc,a)) return 2; cfg.limit = _strtoui64(argv[++i], NULL, 10); }
        else if (!strcmp(a, "--resume"))        cfg.resume = 1;   /* now the default; accepted for back-compat */
        else if (!strcmp(a, "--restart") || !strcmp(a, "--fresh")) cfg.restart = 1;
        else if (!strcmp(a, "--no-exclude"))    cfg.no_exclude = 1;
        else if (!strcmp(a, "--stop-on-first")) cfg.stop_on_first = 1;
        else if (!strcmp(a, "--keep"))          cfg.keep = 1;
        else if (!strcmp(a, "--watch-all"))     cfg.watch_all = 1;
        else if (!strcmp(a, "--setupapi"))      cfg.setupapi_slices = 1;
        else if (!strcmp(a, "--yes"))           cfg.assume_yes = 1;
        else if (!strcmp(a, "--force"))         cfg.force = 1;
        else if (!strcmp(a, "--cleanup"))       do_cleanup = 1;
        else if (!strcmp(a, "--cleanup-dry-run")) { do_cleanup = 1; cleanup_dry = 1; }
        else if (!strcmp(a, "--verify-batch"))  { if (!need_arg(i,argc,a)) return 2; verify_id = argv[++i]; }
        else if (!strcmp(a, "--logdir"))        { if (!need_arg(i,argc,a)) return 2;
                                                  strncpy(cfg.logdir, argv[++i], MAX_PATH - 1);
                                                  cfg.logdir[MAX_PATH - 1] = '\0'; }
        else {
            fprintf(stderr, "[-] unknown option: %s (try --help)\n", a);
            return 2;
        }
    }

    if (cfg.batch < 1)            cfg.batch = 1;
    if (cfg.batch > PF_MAX_BATCH) cfg.batch = PF_MAX_BATCH;
    if (cfg.settle_ms < 0)        cfg.settle_ms = 0;
    if (cfg.wu_timeout < 10)      cfg.wu_timeout = 10;
    /* First-search timeout: honour an explicit --first-wu-timeout; else if the
     * user set --wu-timeout, respect that cap for the first search too (don't
     * silently override it); else fall back to the 900s cold-sync grace. */
    if (cfg.first_wu_timeout <= 0)
        cfg.first_wu_timeout = cfg.wu_timeout_given ? cfg.wu_timeout : 900;
    if (cfg.first_wu_timeout < 10) cfg.first_wu_timeout = 10;
    if (cfg.install_timeout < 5)  cfg.install_timeout = 5;

    if (cfg.auto_batch_max <= 0)          cfg.auto_batch_max = PF_AUTO_BATCH_MAX;
    if (cfg.auto_batch_max > PF_MAX_BATCH) cfg.auto_batch_max = PF_MAX_BATCH;
    if (cfg.auto_batch_max < PF_AUTO_BATCH_FLOOR) cfg.auto_batch_max = PF_AUTO_BATCH_FLOOR;

    GetLocalTime(&now);
    _snprintf(run_id, sizeof(run_id), "%04d%02d%02d-%02d%02d%02d",
              now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond);
    run_id[sizeof(run_id) - 1] = '\0';

    if (log_open(cfg.logdir, run_id) != 0) return 1;

    banner();
    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);

    sysinfo_collect(&si);
    cfg.wu_blockers = si.blockers;

    if (!si.elevated && !cfg.force) {
        log_console(PF_ERR, "Administrator privileges are required. Re-run from an "
                            "elevated prompt (--force to try anyway).");
        log_close();
        if (SUCCEEDED(hr)) CoUninitialize();
        return 1;
    }

    /* --- housekeeping paths ------------------------------------------- */

    if (do_cleanup) {
        int found = 0, removed = 0;
        log_console(PF_INFO, "Scanning for leftover %s nodes...", PF_NODE_PREFIX_A);
        pf_cleanup_orphans(cleanup_dry, &found, &removed);
        if (cleanup_dry)
            log_console(PF_INFO, "%d leftover node(s) found (dry run, nothing removed)", found);
        else
            log_console(found ? PF_GOOD : PF_INFO, "%d found, %d removed", found, removed);
        log_close();
        if (SUCCEEDED(hr)) CoUninitialize();
        return 0;
    }

    log_console(PF_INFO, "Preflight");
    sysinfo_report(&si, cfg.no_wu);

    /* Calibration is a per-host, per-build property; key its cache on that. */
    cfg.os_build = si.build;
    strncpy(cfg.os_arch, si.arch, sizeof(cfg.os_arch) - 1);
    cfg.os_arch[sizeof(cfg.os_arch) - 1] = '\0';

    {
        jb_t jb;
        jb_init(&jb);
        jb_str(&jb, "tool_version", PF_VERSION);
        jb_str(&jb, "run_id", run_id);
        sysinfo_json(&si, &jb);
        log_event(PF_INFO, "run_start", jb_get(&jb));
        jb_free(&jb);
    }

    if (cfg.bench_wu) {
        watch_start(cfg.watch_all);
        rc = bench_wu(cfg.first_wu_timeout, cfg.wu_timeout, PF_MAX_BATCH,
                      cfg.bench_reps > 0 ? cfg.bench_reps : 1);
        watch_stop();
        drain_pnp_events();
        pf_cleanup_orphans(0, NULL, NULL);
        log_close();
        if (SUCCEEDED(hr)) CoUninitialize();
        return rc;
    }

    if (verify_id) {
        watch_start(cfg.watch_all);
        rc = verify_batch(verify_id, cfg.batch, cfg.wu_timeout);
        watch_stop();
        drain_pnp_events();
        pf_cleanup_orphans(0, NULL, NULL);
        log_close();
        if (SUCCEEDED(hr)) CoUninitialize();
        return rc;
    }

    /* --- search space -------------------------------------------------- */

    /* --pid defaults to the WHOLE product range. Sweeping every PID of a vendor
     * is the overwhelmingly common request ("test this VID"), and requiring the
     * range to be spelled out added a step that never varied. --pid still
     * narrows it when you want a slice. */
    if (cfg.space.vid.n && !cfg.space.pid.n) {
        if (axis_parse(&cfg.space.pid, "*", 0xFFFF, "--pid") != 0) {
            log_console(PF_ERR, "internal: could not build the default PID range");
            log_close();
            if (SUCCEEDED(hr)) CoUninitialize();
            return 2;
        }
        cfg.space.pid.given = 0;    /* defaulted, not user-specified */
        log_console(PF_INFO, "No --%s given: sweeping the full range 0000-FFFF "
                             "(65536 %s IDs).",
                    cfg.space.bus == PF_BUS_PCI ? "dev" : "pid",
                    cfg.space.bus == PF_BUS_PCI ? "device" : "product");
    }

    if (space_finalise(&cfg.space, err, sizeof(err)) != 0) {
        log_console(PF_ERR, "%s", err);
        usage();
        log_close();
        if (SUCCEEDED(hr)) CoUninitialize();
        return 2;
    }
    build_signature(&cfg, argc, argv);

    /* --- vendor recon --------------------------------------------------- */
    /* Runs before the sweep so its verdict frames everything that follows: a
     * vendor with certified submissions makes a zero-hit sweep suspicious, while
     * a vendor absent from the partner directory makes one expected. Reaches two
     * public read-only endpoints; --no-recon skips it entirely (offline hosts,
     * or when no third-party traffic is acceptable). */
    if (!cfg.no_recon) {
        vendor_info_t vi;
        unsigned      first_vid = cfg.space.vid.n ? cfg.space.vid.v[0] : 0;
        const char   *busname = pf_bus_name(cfg.space.bus);

        vendor_opts_t vopt;
        memset(&vopt, 0, sizeof(vopt));
        vopt.scan_all     = cfg.cpl_all;
        vopt.pick_account = cfg.cpl_account[0] ? cfg.cpl_account : NULL;
        /* Prompt whenever a human can actually answer. Deliberately NOT gated on
         * --yes: that flag is consent to install mode running vendor code as
         * SYSTEM, a danger confirmation, and it has no bearing on which
         * publisher to read. Suppressing an unrelated question because someone
         * accepted a different risk is how choices get made silently on their
         * behalf. --cpl-all / --cpl-account are the ways to answer in advance;
         * a redirected stdin is the only thing that genuinely rules out asking. */
        vopt.interactive  = _isatty(_fileno(stdin));

        log_console(PF_INFO, "Resolving vendor identity (devicehunt.com, "
                             "partner.microsoft.com)...");
        vendor_lookup(cfg.space.bus == PF_BUS_PCI ? "pci" : "usb",
                      first_vid, &vopt, &vi);
        vendor_report(&vi, busname, first_vid);
        vendor_free(&vi);

        if (cfg.space.vid.n > 1)
            log_console(PF_INFO, "  (recon covers the first vendor only; %d more in this run)",
                        cfg.space.vid.n - 1);
    }

    if (cfg.recon_only) {
        log_console(PF_INFO, "--recon-only: stopping before the sweep.");
        space_free(&cfg.space);
        watch_stop();
        log_close();
        if (SUCCEEDED(hr)) CoUninitialize();
        return 0;
    }

    /* Resume is automatic: if a checkpoint for this exact search space exists in
     * the log directory, continue from where the last run stopped. --restart
     * forces a fresh start; an explicit --start also takes precedence (the user
     * is saying where to begin). */
    if (cfg.restart) {
        char cp[MAX_PATH];
        checkpoint_path(&cfg, cp, sizeof(cp));
        DeleteFileA(cp);
        log_console(PF_INFO, "--restart: ignoring any saved checkpoint, starting fresh.");
    } else if (cfg.start_given) {
        log_console(PF_INFO, "Starting at combination %llu (explicit --start; auto-resume "
                             "skipped).", (unsigned long long)cfg.start);
    } else {
        uint64_t saved = 0;
        int      saved_w = 0;
        char     saved_ref[PF_MAX_ID] = {0};
        int      r = checkpoint_read(&cfg, &saved, &saved_w, saved_ref, sizeof(saved_ref));
        uint64_t total = space_total(&cfg.space);
        /* Completeness is measured against this invocation's window end, which
         * --limit can pull in below the full space. */
        uint64_t win_end = total;
        if (cfg.limit && cfg.limit < total - cfg.start) win_end = cfg.start + cfg.limit;

        if (r == 0 && saved >= win_end) {
            log_console(PF_GOOD, "This run is already complete (%llu / %llu combinations done). "
                                 "Nothing to do. Pass --restart to run it again.",
                        (unsigned long long)saved, (unsigned long long)win_end);
            log_close();
            if (SUCCEEDED(hr)) CoUninitialize();
            return 0;
        }
        if (r == 0 && saved > cfg.start && saved < win_end) {
            cfg.resume_from   = saved;
            cfg.resume_active = 1;
            cfg.resume_width  = saved_w;
            strncpy(cfg.resume_ref, saved_ref, PF_MAX_ID - 1);
            cfg.resume_ref[PF_MAX_ID - 1] = '\0';
            log_console(PF_GOOD, "Resuming at combination %llu / %llu (a previous run of this "
                                 "command was interrupted). Pass --restart to start over.",
                        (unsigned long long)saved, (unsigned long long)total);
        }
    }

    if (cfg.start >= space_total(&cfg.space)) {
        log_console(PF_GOOD, "Nothing to do: start index %llu is at or past the end "
                             "of the space (%llu combinations)",
                    (unsigned long long)cfg.start,
                    (unsigned long long)space_total(&cfg.space));
        log_close();
        if (SUCCEEDED(hr)) CoUninitialize();
        return 0;
    }

    /* An explicit --batch pins the width: the operator has stated one, so do not
     * silently self-tune away from it. Stating --auto-batch as well keeps
     * auto-tuning, using --batch only as the starting width. */
    if (cfg.batch_given && !cfg.auto_batch_given && cfg.auto_batch) {
        cfg.auto_batch = 0;
        log_console(PF_INFO, "--batch %d given: using that fixed width (add --auto-batch to "
                             "self-tune from it instead).", cfg.batch);
    }

    /* Auto-tuning is a Windows Update property: without WU there is nothing to
     * calibrate against, and DriverStore matching is already lossless. */
    if (cfg.auto_batch && cfg.no_wu) {
        cfg.auto_batch = 0;
        if (cfg.auto_batch_given)
            log_console(PF_WARN, "--auto-batch ignored: it needs Windows Update, but --no-wu "
                                 "is set. Using fixed --batch %d.", cfg.batch);
    }

    if (cfg.auto_batch) {
        char detail[96];
        if (cfg.ref_id[0])
            _snprintf(detail, sizeof(detail), "auto (calibrate from %s, max %d)",
                      cfg.ref_id, cfg.auto_batch_max);
        else
            _snprintf(detail, sizeof(detail), "auto (self-calibrate on first hit, max %d)",
                      cfg.auto_batch_max);
        detail[sizeof(detail) - 1] = '\0';
        log_console(PF_INFO, "Search space: %llu combination(s), batch %s, mode %s",
                    (unsigned long long)space_total(&cfg.space), detail,
                    cfg.mode == MODE_QUERY ? "query (non-destructive)" :
                    cfg.mode == MODE_INSTALL ? "install (gated on query hits)" :
                                               "install-all (blind)");
    } else {
        log_console(PF_INFO, "Search space: %llu combination(s), batch %d (fixed), mode %s",
                    (unsigned long long)space_total(&cfg.space), cfg.batch,
                    cfg.mode == MODE_QUERY ? "query (non-destructive)" :
                    cfg.mode == MODE_INSTALL ? "install (gated on query hits)" :
                                               "install-all (blind)");
    }
    log_console(PF_INFO, "Logs: %s\\run-%s.jsonl and hits-%s.csv",
                cfg.logdir, run_id, run_id);

    {
        jb_t jb;
        jb_init(&jb);
        jb_str(&jb, "signature", cfg.sig);
        jb_u64(&jb, "total_combinations", space_total(&cfg.space));
        jb_u64(&jb, "start_index", cfg.start);
        jb_u64(&jb, "limit", cfg.limit);
        jb_bool(&jb, "resumed", cfg.resume_active);
        if (cfg.resume_active) jb_u64(&jb, "resume_from", cfg.resume_from);
        jb_bool(&jb, "auto_batch", cfg.auto_batch);
        jb_num(&jb, "batch", cfg.batch);
        if (cfg.auto_batch) {
            jb_num(&jb, "auto_batch_max", cfg.auto_batch_max);
            if (cfg.ref_id[0]) jb_str(&jb, "ref_id", cfg.ref_id);
        }
        jb_str(&jb, "mode", cfg.mode == MODE_QUERY ? "query" :
                            cfg.mode == MODE_INSTALL ? "install" : "install-all");
        jb_bool(&jb, "windows_update", !cfg.no_wu);
        jb_bool(&jb, "driverstore", !cfg.no_driverstore);
        jb_bool(&jb, "dump_raw_wu", cfg.dump_raw_wu);
        jb_num(&jb, "wu_timeout_s", cfg.wu_timeout);
        jb_num(&jb, "install_timeout_s", cfg.install_timeout);
        jb_num(&jb, "settle_ms", cfg.settle_ms);
        jb_bool(&jb, "exclude_present", !cfg.no_exclude);
        log_event(PF_INFO, "run_config", jb_get(&jb));
        jb_free(&jb);
    }

    if (cfg.mode != MODE_QUERY && !cfg.assume_yes) {
        if (!confirm_install(cfg.mode)) {
            log_console(PF_INFO, "Aborted at the confirmation prompt.");
            log_close();
            if (SUCCEEDED(hr)) CoUninitialize();
            return 0;
        }
    }
    if (cfg.mode != MODE_QUERY)
        log_console(PF_WARN, "Install mode active. DriverStore packages and anything a "
                             "vendor co-installer does will persist after cleanup.");

    /* --- sweep ---------------------------------------------------------- */

    st.t0 = GetTickCount();
    watch_start(cfg.watch_all);

    rc = run_sweep(&cfg, &st);

    watch_stop();
    drain_pnp_events();

    /* --- always tidy up ------------------------------------------------- */

    if (!cfg.keep) {
        int found = 0, removed = 0;
        pf_cleanup_orphans(0, &found, &removed);
        if (found)
            log_console(PF_INFO, "Cleanup: %d leftover node(s), %d removed", found, removed);
    }

    /* --- summary -------------------------------------------------------- */

    {
        double elapsed = (double)(GetTickCount() - st.t0) / 1000.0;
        char   dur[32];
        jb_t   jb;

        fmt_duration(elapsed, dur, sizeof(dur));

        log_console(PF_INFO, "----------------------------------------------------------");
        log_console(PF_INFO, "Combinations probed   : %llu", (unsigned long long)st.probed);
        log_console(PF_INFO, "Skipped (already here): %llu", (unsigned long long)st.skipped_present);
        log_console(PF_INFO, "Batches               : %llu", (unsigned long long)st.batches);
        log_console(st.ds_hits ? PF_GOOD : PF_INFO,
                    "DriverStore matches   : %d", st.ds_hits);
        log_console(st.wu_hits ? PF_GOOD : PF_INFO,
                    "Windows Update matches: %d", st.wu_hits);
        if (cfg.mode != MODE_QUERY) {
            log_console(st.installs_ok ? PF_GOOD : PF_INFO,
                        "Drivers installed     : %d", st.installs_ok);
            log_console(PF_INFO, "Installs that failed  : %d", st.installs_failed);
        }
        if (st.wu_errors)
            log_console(PF_WARN, "Windows Update errors : %d", st.wu_errors);
        log_console(PF_INFO, "Elapsed               : %s", dur);
        if (st.probed && elapsed > 0)
            log_console(PF_INFO, "Rate                  : %.1f combinations/s",
                        (double)st.probed / elapsed);
        log_console(PF_INFO, "Artifacts             : %s", cfg.logdir);

        if (!st.ds_hits && !st.wu_hits && si.blockers)
            log_console(PF_WARN, "Zero hits, but %d environmental blocker(s) were flagged "
                                 "in the preflight. Fix those before concluding anything "
                                 "about these hardware IDs.", si.blockers);
        if (!st.ds_hits && !st.wu_hits && !si.recommended)
            log_console(PF_WARN, "Zero hits on a build that is not on the high-yield list. "
                                 "The same IDs may well match on Win10 1507/1511, "
                                 "Server 2016, or Win11 24H2/25H2.");

        jb_init(&jb);
        jb_u64(&jb, "probed", st.probed);
        jb_u64(&jb, "skipped_present", st.skipped_present);
        jb_u64(&jb, "batches", st.batches);
        jb_num(&jb, "driverstore_matches", st.ds_hits);
        jb_num(&jb, "windows_update_matches", st.wu_hits);
        jb_num(&jb, "installs_ok", st.installs_ok);
        jb_num(&jb, "installs_failed", st.installs_failed);
        jb_num(&jb, "wu_errors", st.wu_errors);
        jb_num(&jb, "elapsed_s", elapsed);
        jb_bool(&jb, "aborted", g_abort);
        log_event(PF_INFO, "run_end", jb_get(&jb));
        jb_free(&jb);
    }

    space_free(&cfg.space);
    log_close();
    if (SUCCEEDED(hr)) CoUninitialize();
    return rc;
}
