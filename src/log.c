/*
 * log.c - console + JSONL event stream + CSV hit table
 *
 * Design goal: after a run you can answer "what happened, when, did it work,
 * and if not what did Windows actually say" purely from the artifacts, without
 * having watched the console.
 */

#include "pnpfuzz.h"
#include <stdarg.h>
#include <time.h>

static FILE *g_jsonl;
static FILE *g_csv;
static char  g_dir[MAX_PATH];
static char  g_run_id[64];
static DWORD g_t0;
static CRITICAL_SECTION g_lock;
static int   g_lock_init;
static int   g_console_verbose;   /* set via PNPFUZZ_DEBUG */

/* ----------------------------------------------------------- timestamps -- */

static void iso8601(char *buf, size_t cap)
{
    SYSTEMTIME st;
    TIME_ZONE_INFORMATION tz;
    DWORD r;
    long bias;
    char sign;

    GetLocalTime(&st);
    r = GetTimeZoneInformation(&tz);
    bias = tz.Bias + (r == TIME_ZONE_ID_DAYLIGHT ? tz.DaylightBias :
                      r == TIME_ZONE_ID_STANDARD ? tz.StandardBias : 0);
    /* Bias is UTC = local + bias, so the offset shown is -bias. */
    sign = (bias <= 0) ? '+' : '-';
    if (bias < 0) bias = -bias;

    _snprintf(buf, cap, "%04d-%02d-%02dT%02d:%02d:%02d.%03d%c%02ld:%02ld",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
              st.wMilliseconds, sign, bias / 60, bias % 60);
    buf[cap - 1] = '\0';
}

static void hhmmss(char *buf, size_t cap)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    _snprintf(buf, cap, "%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
    buf[cap - 1] = '\0';
}

/* ------------------------------------------------------- error decoding -- */

char *pf_win32_msg(DWORD code, char *buf, size_t cap)
{
    DWORD n;
    char *p;

    buf[0] = '\0';
    n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       buf, (DWORD)cap, NULL);
    if (n == 0) {
        _snprintf(buf, cap, "unknown error 0x%08lX", (unsigned long)code);
        buf[cap - 1] = '\0';
        return buf;
    }
    /* Trim the trailing CRLF FormatMessage adds. */
    for (p = buf + strlen(buf); p > buf && (p[-1] == '\r' || p[-1] == '\n' || p[-1] == ' '); p--)
        p[-1] = '\0';
    return buf;
}

char *pf_cr_msg(DWORD cr, char *buf, size_t cap)
{
    /* CONFIGRET values are not FormatMessage-able; the ones that actually turn
     * up in this tool are worth naming explicitly. */
    const char *s = NULL;
    switch (cr) {
    case 0x00: s = "CR_SUCCESS"; break;
    case 0x02: s = "CR_OUT_OF_MEMORY"; break;
    case 0x03: s = "CR_INVALID_POINTER"; break;
    case 0x04: s = "CR_INVALID_FLAG"; break;
    case 0x05: s = "CR_INVALID_DEVNODE"; break;
    case 0x08: s = "CR_INVALID_DEVICE_ID"; break;
    case 0x0D: s = "CR_INVALID_DATA"; break;
    case 0x0E: s = "CR_INVALID_API"; break;
    case 0x0F: s = "CR_DEVLOADER_NOT_READY"; break;
    case 0x13: s = "CR_NO_SUCH_DEVNODE"; break;
    case 0x1A: s = "CR_NO_SUCH_VALUE"; break;
    case 0x1F: s = "CR_FAILURE"; break;
    case 0x20: s = "CR_NO_SUCH_LOGICAL_DEV"; break;
    case 0x22: s = "CR_NOT_SYSTEM_VM"; break;
    case 0x23: s = "CR_ACCESS_DENIED"; break;
    case 0x24: s = "CR_NOT_DISABLEABLE"; break;
    case 0x25: s = "CR_CANT_SHARE_IRQ"; break;
    case 0x26: s = "CR_NO_DEPENDENT"; break;
    case 0x30: s = "CR_INVALID_PROPERTY"; break;
    case 0x31: s = "CR_DEVICE_INTERFACE_ACTIVE"; break;
    case 0x32: s = "CR_NO_SUCH_DEVICE_INTERFACE"; break;
    case 0x33: s = "CR_INVALID_REFERENCE_STRING"; break;
    default: break;
    }
    if (s) _snprintf(buf, cap, "%s (0x%lX)", s, (unsigned long)cr);
    else   _snprintf(buf, cap, "CONFIGRET 0x%lX", (unsigned long)cr);
    buf[cap - 1] = '\0';
    return buf;
}

/* ------------------------------------------------------- json builder ---- */

void jb_init(jb_t *b)
{
    b->cap = 512;
    b->buf = (char *)malloc(b->cap);
    b->len = 0;
    if (b->buf) b->buf[0] = '\0';
}

void jb_free(jb_t *b)
{
    free(b->buf);
    b->buf = NULL;
    b->len = b->cap = 0;
}

static int jb_reserve(jb_t *b, size_t extra)
{
    size_t want;
    char  *p;

    if (!b->buf) return 0;
    if (b->len + extra + 1 <= b->cap) return 1;

    /* Grow a local, and only commit b->cap once the realloc succeeded. Raising
     * b->cap first would leave the builder claiming capacity it does not have,
     * and the next append would memcpy past the end of the real block. */
    want = b->cap;
    while (b->len + extra + 1 > want) want *= 2;
    p = (char *)realloc(b->buf, want);
    if (!p) return 0;
    b->buf = p;
    b->cap = want;
    return 1;
}

static void jb_put(jb_t *b, const char *s, size_t n)
{
    if (!jb_reserve(b, n)) return;
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    b->buf[b->len] = '\0';
}

static void jb_comma(jb_t *b)
{
    if (b->len) jb_put(b, ",", 1);
}

/* Escape into the builder. Handles control chars and keeps UTF-8 bytes as-is. */
static void jb_escaped(jb_t *b, const char *s)
{
    char tmp[8];
    jb_put(b, "\"", 1);
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  jb_put(b, "\\\"", 2); break;
        case '\\': jb_put(b, "\\\\", 2); break;
        case '\n': jb_put(b, "\\n", 2);  break;
        case '\r': jb_put(b, "\\r", 2);  break;
        case '\t': jb_put(b, "\\t", 2);  break;
        default:
            if (c < 0x20) {
                _snprintf(tmp, sizeof(tmp), "\\u%04x", c);
                jb_put(b, tmp, strlen(tmp));
            } else {
                jb_put(b, (const char *)&c, 1);
            }
        }
    }
    jb_put(b, "\"", 1);
}

void jb_str(jb_t *b, const char *key, const char *val)
{
    if (!val) return;
    jb_comma(b);
    jb_escaped(b, key);
    jb_put(b, ":", 1);
    jb_escaped(b, val);
}

void jb_wstr(jb_t *b, const char *key, const wchar_t *val)
{
    char tmp[1024];
    if (!val) return;
    if (WideCharToMultiByte(CP_UTF8, 0, val, -1, tmp, sizeof(tmp), NULL, NULL) <= 0)
        tmp[0] = '\0';
    jb_str(b, key, tmp);
}

void jb_num(jb_t *b, const char *key, double v)
{
    char tmp[64];
    jb_comma(b);
    jb_escaped(b, key);
    jb_put(b, ":", 1);
    _snprintf(tmp, sizeof(tmp), "%.6g", v);
    jb_put(b, tmp, strlen(tmp));
}

void jb_u64(jb_t *b, const char *key, unsigned long long v)
{
    char tmp[32];
    jb_comma(b);
    jb_escaped(b, key);
    jb_put(b, ":", 1);
    _snprintf(tmp, sizeof(tmp), "%llu", v);
    jb_put(b, tmp, strlen(tmp));
}

void jb_bool(jb_t *b, const char *key, int v)
{
    jb_comma(b);
    jb_escaped(b, key);
    jb_put(b, ":", 1);
    jb_put(b, v ? "true" : "false", v ? 4u : 5u);
}

void jb_raw(jb_t *b, const char *key, const char *raw_json)
{
    if (!raw_json) return;
    jb_comma(b);
    jb_escaped(b, key);
    jb_put(b, ":", 1);
    jb_put(b, raw_json, strlen(raw_json));
}

const char *jb_get(jb_t *b)
{
    return (b->buf && b->len) ? b->buf : "";
}

/* -------------------------------------------------------------- output --- */

static const char *lvl_tag(pf_level l)
{
    switch (l) {
    case PF_DEBUG: return "  ";
    case PF_INFO:  return "*";
    case PF_GOOD:  return "+";
    case PF_WARN:  return "!";
    default:       return "-";
    }
}

static const char *lvl_name(pf_level l)
{
    switch (l) {
    case PF_DEBUG: return "debug";
    case PF_INFO:  return "info";
    case PF_GOOD:  return "good";
    case PF_WARN:  return "warn";
    default:       return "error";
    }
}

static int ensure_dir(const char *path)
{
    if (CreateDirectoryA(path, NULL)) return 1;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

int log_open(const char *dir, const char *run_id)
{
    char path[MAX_PATH];

    if (!g_lock_init) {
        InitializeCriticalSection(&g_lock);
        g_lock_init = 1;
    }
    g_t0 = GetTickCount();
    g_console_verbose = GetEnvironmentVariableA("PNPFUZZ_DEBUG", NULL, 0) > 0;

    strncpy(g_dir, dir, sizeof(g_dir) - 1);
    g_dir[sizeof(g_dir) - 1] = '\0';
    strncpy(g_run_id, run_id, sizeof(g_run_id) - 1);
    g_run_id[sizeof(g_run_id) - 1] = '\0';

    if (!ensure_dir(g_dir)) {
        fprintf(stderr, "[-] cannot create log directory %s\n", g_dir);
        return -1;
    }

    _snprintf(path, sizeof(path), "%s\\run-%s.jsonl", g_dir, g_run_id);
    path[sizeof(path) - 1] = '\0';
    g_jsonl = fopen(path, "wb");
    if (!g_jsonl) {
        fprintf(stderr, "[-] cannot open %s\n", path);
        return -1;
    }

    _snprintf(path, sizeof(path), "%s\\hits-%s.csv", g_dir, g_run_id);
    path[sizeof(path) - 1] = '\0';
    g_csv = fopen(path, "wb");
    if (g_csv) {
        fputs("timestamp,hardware_id,source,match_kind,provider,description,"
              "class,version,inf,extra\r\n", g_csv);
        fflush(g_csv);
    }
    return 0;
}

void log_close(void)
{
    if (g_jsonl) { fflush(g_jsonl); fclose(g_jsonl); g_jsonl = NULL; }
    if (g_csv)   { fflush(g_csv);   fclose(g_csv);   g_csv = NULL; }
}

const char *log_dir_path(void) { return g_dir; }
const char *log_run_id(void)   { return g_run_id; }

void log_console(pf_level lvl, const char *fmt, ...)
{
    va_list ap;
    char ts[16];

    if (lvl == PF_DEBUG && !g_console_verbose) return;

    if (g_lock_init) EnterCriticalSection(&g_lock);
    hhmmss(ts, sizeof(ts));
    fprintf(stderr, "%s [%s] ", ts, lvl_tag(lvl));
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
    if (g_lock_init) LeaveCriticalSection(&g_lock);
}

void log_event(pf_level lvl, const char *event, const char *fields)
{
    char ts[64];

    if (!g_jsonl) return;

    if (g_lock_init) EnterCriticalSection(&g_lock);
    iso8601(ts, sizeof(ts));
    fprintf(g_jsonl, "{\"ts\":\"%s\",\"t_ms\":%lu,\"level\":\"%s\",\"event\":\"%s\"",
            ts, (unsigned long)(GetTickCount() - g_t0), lvl_name(lvl), event);
    if (fields && *fields) {
        fputc(',', g_jsonl);
        fputs(fields, g_jsonl);
    }
    fputs("}\n", g_jsonl);
    fflush(g_jsonl);   /* a sweep can run for days; never lose the tail */
    if (g_lock_init) LeaveCriticalSection(&g_lock);
}

static void csv_field(FILE *f, const char *s)
{
    fputc('"', f);
    for (; s && *s; s++) {
        if (*s == '"') fputc('"', f);
        if (*s == '\r' || *s == '\n') { fputc(' ', f); continue; }
        fputc(*s, f);
    }
    fputc('"', f);
}

void log_hit_csv(const char *hwid, const char *source, const char *match_kind,
                 const char *provider, const char *desc, const char *cls,
                 const char *version, const char *inf, const char *extra)
{
    char ts[64];
    const char *cols[9];
    int i;

    if (!g_csv) return;

    cols[0] = hwid;     cols[1] = source;  cols[2] = match_kind;
    cols[3] = provider; cols[4] = desc;    cols[5] = cls;
    cols[6] = version;  cols[7] = inf;     cols[8] = extra;

    if (g_lock_init) EnterCriticalSection(&g_lock);
    iso8601(ts, sizeof(ts));
    csv_field(g_csv, ts);
    for (i = 0; i < 9; i++) {
        fputc(',', g_csv);
        csv_field(g_csv, cols[i] ? cols[i] : "");
    }
    fputs("\r\n", g_csv);
    fflush(g_csv);
    if (g_lock_init) LeaveCriticalSection(&g_lock);
}
