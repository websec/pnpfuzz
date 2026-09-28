/*
 * wu.c - Windows Update driver query
 *
 * IUpdateSearcher returns every driver update Microsoft Update considers
 * applicable to this machine's current device inventory, then we filter by
 * IWindowsDriverUpdate::get_DriverHardwareID.
 *
 * That filter is why batching works. The search itself is the expensive part
 * (a full online sync, tens of seconds), and it costs the same whether the
 * synthetic node advertises one hardware ID or two hundred. Probing N
 * candidates therefore costs one search, not N, which is where the
 * batching speedup comes from.
 *
 * The search runs on its own apartment-threaded thread: WU's COM objects want
 * an STA, and SetupAPI work on the main thread is happier in an MTA.
 */

#include "pnpfuzz.h"
#include <objbase.h>
#include <wuapi.h>

/* ssWindowsUpdate: force Microsoft Update rather than a configured WSUS
 * server, so the query still returns data on managed hosts. Note that this
 * only affects the query - an actual install still follows machine policy. */
#define PF_SS_WINDOWS_UPDATE 2

typedef struct {
    char        (*targets)[PF_MAX_ID];   /* private copy owned by the context */
    int           n_targets;
    wures_t      *out;
    int           superseded;
    volatile LONG refs;                  /* 2 = caller + worker thread        */
    volatile LONG abandoned;             /* caller gave up waiting            */
    HANDLE        done;
} wu_ctx;

static int           g_superseded;
static int           g_dump_raw;
static volatile LONG g_abandoned_searches;

void wu_set_superseded(int on) { g_superseded = on ? 1 : 0; }
void wu_set_dump_raw(int on)   { g_dump_raw = on ? 1 : 0; }

/* Last reference out frees everything. The worker keeps reading its own copy
 * of the targets after a timeout, so the caller must never own that buffer. */
static void wu_ctx_release(wu_ctx *c)
{
    if (InterlockedDecrement(&c->refs) != 0) return;

    /* Whoever leaves last clears the outstanding-search bookkeeping, so the
     * flag is correct however the timeout and the completion interleave. */
    if (InterlockedCompareExchange(&c->abandoned, 0, 0))
        InterlockedDecrement(&g_abandoned_searches);

    wu_free(c->out);
    free(c->out);
    free(c->targets);
    CloseHandle(c->done);
    free(c);
}

/* ------------------------------------------------------------ matching --- */

static void upper_ascii(char *s)
{
    for (; *s; s++)
        if (*s >= 'a' && *s <= 'z') *s = (char)(*s - 32);
}

/* Component-boundary aware. "USB\VID_046D&PID_0001" must not match
 * "USB\VID_046D&PID_00012", which a plain substring test would accept. */
static int id_related(const char *a, const char *b)
{
    size_t la, lb;

    if (!a || !b || !*a || !*b) return 0;
    if (_stricmp(a, b) == 0) return 1;

    la = strlen(a);
    lb = strlen(b);
    if (la > lb) {
        const char *t = a; a = b; b = t;
        { size_t s = la; la = lb; lb = s; }
    }
    /* a is now the shorter one; b must extend it at a component boundary. */
    if (_strnicmp(a, b, la) != 0) return 0;
    return b[la] == '&';
}

static void wu_add(wures_t *r, const wuhit_t *h)
{
    if (r->count >= r->cap) {
        int nc = r->cap ? r->cap * 2 : 16;
        wuhit_t *p = (wuhit_t *)realloc(r->hits, (size_t)nc * sizeof(*p));
        if (!p) return;
        r->hits = p;
        r->cap  = nc;
    }
    r->hits[r->count++] = *h;
}

static void bstr_a(BSTR b, char *buf, int cap)
{
    buf[0] = '\0';
    if (b) WideCharToMultiByte(CP_UTF8, 0, b, -1, buf, cap, NULL, NULL);
    buf[cap - 1] = '\0';
}

/* --------------------------------------------------------------- search -- */

static void wu_do_search(wu_ctx *c)
{
    IUpdateSession   *session  = NULL;
    IUpdateSearcher  *searcher = NULL;
    ISearchResult    *result   = NULL;
    IUpdateCollection *updates = NULL;
    wures_t *r = c->out;
    HRESULT hr;
    BSTR criteria;
    LONG count = 0, i;
    DWORD t0 = GetTickCount();

    hr = CoCreateInstance(&CLSID_UpdateSession, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IUpdateSession, (void **)&session);
    if (FAILED(hr)) {
        r->error = hr;
        _snprintf(r->error_msg, sizeof(r->error_msg),
                  "CoCreateInstance(UpdateSession) failed: 0x%08lX", (unsigned long)hr);
        goto out;
    }

    hr = session->lpVtbl->CreateUpdateSearcher(session, &searcher);
    if (FAILED(hr)) {
        r->error = hr;
        _snprintf(r->error_msg, sizeof(r->error_msg),
                  "CreateUpdateSearcher failed: 0x%08lX", (unsigned long)hr);
        goto out;
    }

    searcher->lpVtbl->put_ServerSelection(searcher, PF_SS_WINDOWS_UPDATE);
    searcher->lpVtbl->put_Online(searcher, VARIANT_TRUE);
    if (c->superseded)
        searcher->lpVtbl->put_IncludePotentiallySupersededUpdates(searcher, VARIANT_TRUE);

    criteria = SysAllocString(L"IsInstalled=0 AND Type='Driver'");

    /* A wedged WU/COM state can fault inside Search(); do not take the whole
     * sweep down with it. */
    __try {
        hr = searcher->lpVtbl->Search(searcher, criteria, &result);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        r->error = (HRESULT)code;
        _snprintf(r->error_msg, sizeof(r->error_msg),
                  "Search() raised exception 0x%08lX (Windows Update state is wedged; "
                  "try 'net stop wuauserv' then retry)", (unsigned long)code);
        SysFreeString(criteria);
        goto out;
    }
    SysFreeString(criteria);

    if (FAILED(hr)) {
        r->error = hr;
        _snprintf(r->error_msg, sizeof(r->error_msg),
                  "Search failed: 0x%08lX%s", (unsigned long)hr,
                  hr == (HRESULT)0x80240438L ? " (no route to the update service)" :
                  hr == (HRESULT)0x8024402CL ? " (proxy/name resolution failure)" :
                  hr == (HRESULT)0x80072EE2L ? " (network timeout)" : "");
        goto out;
    }

    hr = result->lpVtbl->get_Updates(result, &updates);
    if (FAILED(hr)) {
        r->error = hr;
        _snprintf(r->error_msg, sizeof(r->error_msg),
                  "get_Updates failed: 0x%08lX", (unsigned long)hr);
        goto out;
    }

    updates->lpVtbl->get_Count(updates, &count);
    r->total_updates = count;
    r->completed = 1;

    for (i = 0; i < count; i++) {
        IUpdate *upd = NULL;
        IWindowsDriverUpdate *drv = NULL;
        BSTR drv_hwid = NULL;
        char wuid[PF_MAX_ID];
        int  t, matched = -1;

        if (FAILED(updates->lpVtbl->get_Item(updates, i, &upd)) || !upd) continue;

        if (FAILED(upd->lpVtbl->QueryInterface(upd, &IID_IWindowsDriverUpdate,
                                               (void **)&drv)) || !drv) {
            upd->lpVtbl->Release(upd);
            continue;
        }

        drv->lpVtbl->get_DriverHardwareID(drv, &drv_hwid);
        bstr_a(drv_hwid, wuid, sizeof(wuid));
        if (drv_hwid) SysFreeString(drv_hwid);
        upper_ascii(wuid);

        for (t = 0; t < c->n_targets; t++) {
            if (id_related(wuid, c->targets[t])) { matched = t; break; }
        }

        /* --dump-raw-wu: record the whole returned set, matched or not, so the
         * device-scoped nature of the query can be verified after the fact. */
        if (g_dump_raw) {
            char rtitle[512], rcls[128];
            BSTR rs = NULL;
            jb_t rj;

            rtitle[0] = rcls[0] = '\0';
            upd->lpVtbl->get_Title(upd, &rs);       bstr_a(rs, rtitle, sizeof(rtitle)); if (rs) { SysFreeString(rs); rs = NULL; }
            drv->lpVtbl->get_DriverClass(drv, &rs);  bstr_a(rs, rcls, sizeof(rcls));     if (rs) { SysFreeString(rs); rs = NULL; }

            jb_init(&rj);
            jb_str(&rj, "driver_hardware_id", wuid);
            jb_str(&rj, "title", rtitle);
            jb_str(&rj, "driver_class", rcls);
            jb_bool(&rj, "matched_a_target", matched >= 0);
            if (matched >= 0) jb_str(&rj, "matched_target", c->targets[matched]);
            log_event(PF_DEBUG, "wu_raw_update", jb_get(&rj));
            jb_free(&rj);
        }

        if (matched >= 0) {
            wuhit_t h;
            BSTR s = NULL;
            DATE d = 0;
            VARIANT_BOOL vb = VARIANT_FALSE;
            IUpdateIdentity *ident = NULL;

            memset(&h, 0, sizeof(h));
            strncpy(h.hwid, wuid, sizeof(h.hwid) - 1);
            strncpy(h.matched, c->targets[matched], sizeof(h.matched) - 1);

            upd->lpVtbl->get_Title(upd, &s);        bstr_a(s, h.title, sizeof(h.title));               if (s) { SysFreeString(s); s = NULL; }
            upd->lpVtbl->get_Description(upd, &s);  bstr_a(s, h.description, sizeof(h.description));   if (s) { SysFreeString(s); s = NULL; }
            drv->lpVtbl->get_DriverClass(drv, &s);  bstr_a(s, h.cls, sizeof(h.cls));                   if (s) { SysFreeString(s); s = NULL; }
            drv->lpVtbl->get_DriverManufacturer(drv, &s); bstr_a(s, h.manufacturer, sizeof(h.manufacturer)); if (s) { SysFreeString(s); s = NULL; }
            drv->lpVtbl->get_DriverProvider(drv, &s);     bstr_a(s, h.company, sizeof(h.company));     if (s) { SysFreeString(s); s = NULL; }

            drv->lpVtbl->get_DriverVerDate(drv, &d);
            if (d != 0.0) {
                SYSTEMTIME st;
                if (VariantTimeToSystemTime(d, &st))
                    _snprintf(h.version_date, sizeof(h.version_date), "%04d-%02d-%02d",
                              st.wYear, st.wMonth, st.wDay);
            }

            if (SUCCEEDED(upd->lpVtbl->get_IsDownloaded(upd, &vb)))
                h.is_downloaded = (vb == VARIANT_TRUE);

            if (SUCCEEDED(upd->lpVtbl->get_Identity(upd, &ident)) && ident) {
                ident->lpVtbl->get_UpdateID(ident, &s);
                bstr_a(s, h.update_id, sizeof(h.update_id));
                if (s) { SysFreeString(s); s = NULL; }
                ident->lpVtbl->Release(ident);
            }

            wu_add(r, &h);
        }

        drv->lpVtbl->Release(drv);
        upd->lpVtbl->Release(upd);
    }

out:
    r->elapsed_ms = GetTickCount() - t0;
    if (updates)  updates->lpVtbl->Release(updates);
    if (result)   result->lpVtbl->Release(result);
    if (searcher) searcher->lpVtbl->Release(searcher);
    if (session)  session->lpVtbl->Release(session);
}

static DWORD WINAPI wu_thread(LPVOID param)
{
    wu_ctx *c = (wu_ctx *)param;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    wu_do_search(c);

    /* Signal completion BEFORE CoUninitialize. On an STA that has driven a
     * Windows Update scan, CoUninitialize can block for minutes while WU does
     * background datastore bookkeeping - work the caller does not need to wait
     * for, since the results are already in place. Releasing the caller here
     * turns a batch that would have stalled for minutes into one bounded by the
     * actual search time; the teardown then finishes on this thread in the
     * background. The refcount keeps the context alive until both sides leave. */
    SetEvent(c->done);
    if (SUCCEEDED(hr)) CoUninitialize();

    wu_ctx_release(c);
    return 0;
}

int wu_search(char targets[][PF_MAX_ID], int n_targets, int timeout_s, wures_t *out)
{
    wu_ctx  *c;
    wures_t *scratch;
    HANDLE   th;
    DWORD    wait;
    jb_t     jb;
    int      i;

    memset(out, 0, sizeof(*out));
    if (n_targets <= 0) return -1;

    /* An abandoned search is still talking to Windows Update. Starting more on
     * top of it makes every subsequent search slower, so skip this batch's
     * query instead of piling up concurrent syncs. */
    if (InterlockedCompareExchange(&g_abandoned_searches, 0, 0) > 0) {
        out->error = (HRESULT)ERROR_BUSY;
        _snprintf(out->error_msg, sizeof(out->error_msg),
                  "skipped: a previous Windows Update search is still running after "
                  "its timeout (raise --wu-timeout)");
        out->error_msg[sizeof(out->error_msg) - 1] = '\0';
        log_event(PF_WARN, "wu_search_skipped",
                  "\"reason\":\"previous search still outstanding\"");
        return -1;
    }

    scratch = (wures_t *)calloc(1, sizeof(wures_t));
    c       = (wu_ctx *)calloc(1, sizeof(wu_ctx));
    if (!scratch || !c) { free(scratch); free(c); return -1; }

    c->targets = (char (*)[PF_MAX_ID])calloc((size_t)n_targets, PF_MAX_ID);
    if (!c->targets) { free(scratch); free(c); return -1; }
    for (i = 0; i < n_targets; i++) {
        strncpy(c->targets[i], targets[i], PF_MAX_ID - 1);
        c->targets[i][PF_MAX_ID - 1] = '\0';
        upper_ascii(c->targets[i]);
    }

    c->n_targets  = n_targets;
    c->out        = scratch;
    c->superseded = g_superseded;
    c->refs       = 2;
    c->done       = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!c->done) { free(c->targets); free(scratch); free(c); return -1; }

    {
        jb_init(&jb);
        jb_num(&jb, "target_count", n_targets);
        jb_str(&jb, "first_target", c->targets[0]);
        jb_str(&jb, "last_target", c->targets[n_targets - 1]);
        jb_num(&jb, "timeout_s", timeout_s);
        log_event(PF_INFO, "wu_search_start", jb_get(&jb));
        jb_free(&jb);
    }

    th = CreateThread(NULL, 0, wu_thread, c, 0, NULL);
    if (!th) {
        CloseHandle(c->done);
        free(c->targets);
        free(scratch);
        free(c);
        return -1;
    }

    /* Poll in short slices so the console can show the search is alive. A WU
     * search on a machine that has never synced can genuinely take minutes
     * (the one-time catalogue download), and a silent multi-minute wait reads
     * as a hang. */
    {
        DWORD total   = (DWORD)timeout_s * 1000;
        DWORD waited   = 0;
        DWORD slice    = 15000;                 /* 15s heartbeat */
        DWORD t_start  = GetTickCount();
        wait = WAIT_TIMEOUT;
        for (;;) {
            DWORD chunk = total - waited;
            if (chunk > slice) chunk = slice;
            wait = WaitForSingleObject(c->done, chunk);
            if (wait == WAIT_OBJECT_0) break;   /* search finished */
            waited += chunk;
            if (waited >= total) { wait = WAIT_TIMEOUT; break; }
            log_console(PF_INFO, "    ...Windows Update search still running "
                                 "(%lus elapsed, up to %ds)",
                        (unsigned long)((GetTickCount() - t_start) / 1000), timeout_s);
        }
    }
    if (wait != WAIT_OBJECT_0) {
        /* Never TerminateThread a live COM apartment. Detach instead: the
         * worker holds its own reference and frees everything when it returns.
         * This is why the targets had to be copied. */
        CloseHandle(th);
        InterlockedExchange(&c->abandoned, 1);
        InterlockedIncrement(&g_abandoned_searches);
        out->error = (HRESULT)ERROR_TIMEOUT;
        _snprintf(out->error_msg, sizeof(out->error_msg),
                  "Windows Update search exceeded %d s and was abandoned", timeout_s);
        out->error_msg[sizeof(out->error_msg) - 1] = '\0';
        jb_init(&jb);
        jb_num(&jb, "timeout_s", timeout_s);
        jb_str(&jb, "error", out->error_msg);
        log_event(PF_ERR, "wu_search_timeout", jb_get(&jb));
        jb_free(&jb);
        wu_ctx_release(c);
        return -1;
    }

    CloseHandle(th);
    *out = *scratch;                       /* move the hit array to the caller */
    scratch->hits  = NULL;
    scratch->count = scratch->cap = 0;
    wu_ctx_release(c);

    jb_init(&jb);
    jb_bool(&jb, "completed", out->completed);
    jb_u64(&jb, "elapsed_ms", out->elapsed_ms);
    jb_num(&jb, "driver_updates_returned", (double)out->total_updates);
    jb_num(&jb, "matches", out->count);
    if (out->error) {
        jb_u64(&jb, "hresult", (unsigned long long)(ULONG)out->error);
        jb_str(&jb, "error", out->error_msg);
    }
    log_event(out->error ? PF_ERR : (out->count ? PF_GOOD : PF_INFO),
              "wu_search_result", jb_get(&jb));
    jb_free(&jb);

    return out->error ? -1 : 0;
}

void wu_free(wures_t *r)
{
    if (!r) return;
    free(r->hits);
    r->hits  = NULL;
    r->count = r->cap = 0;
}
