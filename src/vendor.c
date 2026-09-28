/*
 * vendor.c - vendor-identity reconnaissance for a VID/VEN before sweeping it
 *
 * Three public lookups, chained, each answering a question that changes how you
 * read the sweep that follows:
 *
 *   1. DeviceHunt   - what company owns this vendor ID?
 *   2. Partner CPL  - is that company an active Windows hardware publisher?
 *   3. CPL products - does it actually have certified driver submissions?
 *
 * Why this is worth the three round trips: a vendor that resolves to a real
 * company, appears in the Microsoft hardware partner directory AND has certified
 * submissions is a vendor whose IDs plausibly have Windows Update packages, so a
 * sweep is likely to find something. A vendor that resolves but is absent from
 * the partner directory is usually one of two things - a dormant/legacy ID, or a
 * silicon vendor that reserves IDs for its customers, in which case the drivers
 * are published under the CUSTOMER's name, not the ID holder's. That second case
 * is real and common: DeviceHunt may name the silicon vendor for an ID while the
 * partner directory lists the OEM that actually ships the hardware.
 * Knowing which case you are in stops a zero-hit sweep from being misread.
 *
 * Everything here reads public, unauthenticated endpoints - the partner CPL
 * search is the same directory the site serves to a logged-out browser, and the
 * only cookies involved are the session/bot-management ones a plain GET sets.
 * No credentials are sent and nothing is modified.
 *
 * The product enumeration exists because the CPL product search matches a
 * SUBSTRING of the product name: querying a single letter returns every product
 * containing it. Sweeping "a".."z" and unioning the results therefore enumerates
 * the publisher's certified submissions without knowing any product name in
 * advance. Every letter is queried even after the first hit, because different
 * letters surface different products.
 */

#include "pnpfuzz.h"
#include <winhttp.h>
#include <io.h>
#include <conio.h>
#include <ctype.h>
#include "vendordb.h"

#define VH_HOST_DEVICEHUNT  L"devicehunt.com"
#define VH_HOST_PARTNER     L"partner.microsoft.com"
#define VH_UA               L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) " \
                            L"AppleWebKit/537.36 (KHTML, like Gecko) " \
                            L"Chrome/150.0.0.0 Safari/537.36"
#define VH_CPL_REFERER      L"Referer: https://partner.microsoft.com/en-us/dashboard/hardware/search/cpl\r\n"

/* Politeness delay between the 26 product queries. These are public endpoints
 * doing real work per request; a burst of 26 with no spacing is rude and invites
 * throttling that would corrupt the result set. */
#define VH_LETTER_DELAY_MS  250

/* ----------------------------------------------------------- local list --- */

/* Binary search the compiled-in USB-IF table. Returns the number of names
 * written (a VID can be registered to more than one legal entity), 0 if the
 * vendor is not listed.
 *
 * USB only, deliberately. The table is the USB-IF registry; PCI vendor IDs come
 * from PCI-SIG and are an entirely separate numbering space, so 0x1532 means
 * Razer on USB and something unrelated on PCI. Consulting it for a PCI sweep
 * would confidently return the wrong company. */
static int vendordb_lookup(pf_bus bus, unsigned vid, char names[][256], int cap)
{
    int lo = 0, hi = PF_VENDORDB_COUNT - 1, at = -1, i, n = 0;

    if (bus != PF_BUS_USB || cap <= 0) return 0;

    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (pf_vendordb_vid[mid] == (unsigned short)vid) { at = mid; break; }
        if (pf_vendordb_vid[mid] < (unsigned short)vid) lo = mid + 1;
        else                                            hi = mid - 1;
    }
    if (at < 0) return 0;

    /* Equal keys are adjacent; rewind to the first so duplicates are complete. */
    while (at > 0 && pf_vendordb_vid[at - 1] == (unsigned short)vid) at--;

    for (i = at; i < PF_VENDORDB_COUNT && n < cap &&
                 pf_vendordb_vid[i] == (unsigned short)vid; i++) {
        strncpy(names[n], pf_vendordb_name[i], 255);
        names[n][255] = '\0';
        n++;
    }
    return n;
}

/* ------------------------------------------------------------ http glue --- */

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} vbuf;

static void vbuf_init(vbuf *b) { b->buf = NULL; b->len = 0; b->cap = 0; }
static void vbuf_free(vbuf *b) { free(b->buf); b->buf = NULL; b->len = b->cap = 0; }

static int vbuf_add(vbuf *b, const char *p, size_t n)
{
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 8192;
        char  *np;
        while (nc < b->len + n + 1) nc *= 2;
        /* Cap the reply we will hold. A runaway or hostile response must not be
         * allowed to exhaust the process. */
        if (nc > (size_t)8 * 1024 * 1024) return -1;
        np = (char *)realloc(b->buf, nc);
        if (!np) return -1;
        b->buf = np;
        b->cap = nc;
    }
    memcpy(b->buf + b->len, p, n);
    b->len += n;
    b->buf[b->len] = '\0';
    return 0;
}

/* One session for the whole recon pass, so WinHTTP's automatic cookie jar keeps
 * the partner-site cookies the seed request sets. */
typedef struct {
    HINTERNET session;
    HINTERNET conn_dh;
    HINTERNET conn_ms;
} vhttp;

static void vhttp_close(vhttp *h)
{
    if (h->conn_ms) WinHttpCloseHandle(h->conn_ms);
    if (h->conn_dh) WinHttpCloseHandle(h->conn_dh);
    if (h->session) WinHttpCloseHandle(h->session);
    h->conn_ms = h->conn_dh = h->session = NULL;
}

static int vhttp_open(vhttp *h)
{
    memset(h, 0, sizeof(*h));
    h->session = WinHttpOpen(VH_UA, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h->session) return -1;
    /* resolve, connect, send, receive */
    WinHttpSetTimeouts(h->session, 10000, 10000, 15000, 20000);
    return 0;
}

/* Issue one request and collect the body. `verb` is "GET" or "POST"; `body` is
 * NULL for GET. Returns the HTTP status, or -1 on a transport failure. */
static int vhttp_req(HINTERNET conn, const wchar_t *verb, const wchar_t *path,
                     const wchar_t *extra_headers, const char *body, vbuf *out)
{
    HINTERNET req;
    DWORD     status = 0, cb = sizeof(status);
    BOOL      ok;
    int       rc = -1;

    req = WinHttpOpenRequest(conn, verb, path, NULL, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req) return -1;

    ok = WinHttpSendRequest(req,
                            extra_headers ? extra_headers : WINHTTP_NO_ADDITIONAL_HEADERS,
                            extra_headers ? (DWORD)-1L : 0,
                            body ? (LPVOID)body : WINHTTP_NO_REQUEST_DATA,
                            body ? (DWORD)strlen(body) : 0,
                            body ? (DWORD)strlen(body) : 0, 0);
    if (!ok) goto done;
    if (!WinHttpReceiveResponse(req, NULL)) goto done;

    if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &cb,
                             WINHTTP_NO_HEADER_INDEX))
        status = 0;

    for (;;) {
        DWORD avail = 0, got = 0;
        char  chunk[8192];
        if (!WinHttpQueryDataAvailable(req, &avail)) break;
        if (avail == 0) break;
        while (avail > 0) {
            DWORD want = avail > sizeof(chunk) ? (DWORD)sizeof(chunk) : avail;
            if (!WinHttpReadData(req, chunk, want, &got) || got == 0) { avail = 0; break; }
            if (vbuf_add(out, chunk, got) != 0) { avail = 0; break; }
            avail -= got;
        }
    }
    rc = (int)status;

done:
    WinHttpCloseHandle(req);
    return rc;
}

/* ---------------------------------------------------------- text helpers -- */

static void vtrim(char *s)
{
    size_t n;
    char  *p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    n = strlen(s);
    while (n && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\r' || s[n-1] == '\n'))
        s[--n] = '\0';
}

/* Minimal HTML entity decode for the handful that show up in company names. */
static void vunescape_html(char *s)
{
    char *r = s, *w = s;
    while (*r) {
        if (*r == '&') {
            if (!strncmp(r, "&amp;", 5))       { *w++ = '&'; r += 5; continue; }
            if (!strncmp(r, "&quot;", 6))      { *w++ = '"'; r += 6; continue; }
            if (!strncmp(r, "&#39;", 5))       { *w++ = '\''; r += 5; continue; }
            if (!strncmp(r, "&apos;", 6))      { *w++ = '\''; r += 6; continue; }
            if (!strncmp(r, "&lt;", 4))        { *w++ = '<'; r += 4; continue; }
            if (!strncmp(r, "&gt;", 4))        { *w++ = '>'; r += 4; continue; }
            /* an em dash written as an entity is a separator, normalise it so the
             * splitter below sees one form only */
            if (!strncmp(r, "&mdash;", 7))     { *w++ = '\x01'; r += 7; continue; }
            if (!strncmp(r, "&ndash;", 7))     { *w++ = '\x01'; r += 7; continue; }
        }
        *w++ = *r++;
    }
    *w = '\0';
}

/* DeviceHunt titles read "<Company> - PCI Vendor XXXX - DeviceHunt", where the
 * separator is an em dash. Take the first field. Returns 0 on success. */
static int parse_devicehunt_title(const char *html, char *out, size_t cap)
{
    const char *a, *b;
    char        title[512];
    size_t      n;
    char       *sep;

    a = strstr(html, "<title>");
    if (!a) return -1;
    a += 7;
    b = strstr(a, "</title>");
    if (!b) return -1;
    n = (size_t)(b - a);
    if (n >= sizeof(title)) n = sizeof(title) - 1;
    memcpy(title, a, n);
    title[n] = '\0';

    vunescape_html(title);

    /* Normalise a literal UTF-8 em dash (E2 80 94) / en dash (E2 80 93) to the
     * same marker the entity decoder produced. */
    {
        char *p = title;
        while ((p = strstr(p, "\xE2\x80")) != NULL) {
            if ((unsigned char)p[2] == 0x94 || (unsigned char)p[2] == 0x93) {
                p[0] = '\x01';
                memmove(p + 1, p + 3, strlen(p + 3) + 1);
                p += 1;
            } else {
                p += 2;
            }
        }
    }

    /* A 404 page titles itself "404 - Page Not Found - DeviceHunt". Treat any
     * title whose first field starts with 404 as not-indexed. */
    sep = strchr(title, '\x01');
    if (sep) *sep = '\0';
    else {
        /* fall back to a plain hyphen separator if the site ever changes */
        sep = strstr(title, " - ");
        if (sep) *sep = '\0';
    }
    vtrim(title);
    if (!title[0]) return -1;
    if (!strncmp(title, "404", 3)) return -1;

    strncpy(out, title, cap - 1);
    out[cap - 1] = '\0';
    return 0;
}

/* Extract the string value of "key":"..." starting the search at `from`.
 * Returns a pointer just past the value, or NULL. */
static const char *json_str(const char *from, const char *end, const char *key,
                            char *out, size_t cap)
{
    char        pat[64];
    const char *p;
    size_t      w = 0;

    _snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    pat[sizeof(pat) - 1] = '\0';

    p = strstr(from, pat);
    if (!p || (end && p >= end)) { if (cap) out[0] = '\0'; return NULL; }
    p += strlen(pat);

    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) {
            p++;
            if (w + 1 < cap) {
                char c = *p;
                out[w++] = (c == 'n') ? '\n' : (c == 't') ? '\t' : c;
            }
            p++;
            continue;
        }
        if (w + 1 < cap) out[w++] = *p;
        p++;
    }
    if (cap) out[w] = '\0';
    return (*p == '"') ? p + 1 : p;
}

/* Percent-encode for a query string; space becomes '+' as the site's own UI does. */
static void url_encode(const char *in, char *out, size_t cap)
{
    static const char *hex = "0123456789ABCDEF";
    size_t w = 0;
    for (; *in && w + 4 < cap; in++) {
        unsigned char c = (unsigned char)*in;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out[w++] = (char)c;
        } else if (c == ' ') {
            out[w++] = '+';
        } else {
            out[w++] = '%';
            out[w++] = hex[(c >> 4) & 0xF];
            out[w++] = hex[c & 0xF];
        }
    }
    out[w < cap ? w : cap - 1] = '\0';
}

static void a2w(const char *a, wchar_t *w, size_t cap)
{
    size_t i = 0;
    for (; a[i] && i + 1 < cap; i++) w[i] = (wchar_t)(unsigned char)a[i];
    w[i] = L'\0';
}

/* ------------------------------------------------------------- products --- */

static int vendor_add_product(vendor_info_t *vi, const char *account_id,
                              const char *sub_id, const char *name,
                              const char *os, int declarative, int universal)
{
    int i;

    if (!name || !name[0]) return 0;

    /* Distinct by submission id: the same product name legitimately appears
     * several times as separate certified submissions, and collapsing those
     * would under-report. Fall back to name when no id is present. */
    for (i = 0; i < vi->n_products; i++) {
        if (sub_id[0] && vi->products[i].submission_id[0]) {
            if (!strcmp(vi->products[i].submission_id, sub_id)) return 0;
        } else if (!_stricmp(vi->products[i].product_name, name)) {
            return 0;
        }
    }

    if (vi->n_products >= vi->cap_products) {
        int   nc = vi->cap_products ? vi->cap_products * 2 : 32;
        void *np = realloc(vi->products, (size_t)nc * sizeof(cpl_product_t));
        if (!np) return -1;
        vi->products = (cpl_product_t *)np;
        vi->cap_products = nc;
    }

    memset(&vi->products[vi->n_products], 0, sizeof(cpl_product_t));
    strncpy(vi->products[vi->n_products].account_id, account_id ? account_id : "",
            sizeof(vi->products[0].account_id) - 1);
    strncpy(vi->products[vi->n_products].submission_id, sub_id, sizeof(vi->products[0].submission_id) - 1);
    strncpy(vi->products[vi->n_products].product_name, name, sizeof(vi->products[0].product_name) - 1);
    strncpy(vi->products[vi->n_products].os_codes, os ? os : "", sizeof(vi->products[0].os_codes) - 1);
    vi->products[vi->n_products].declarative = declarative;
    vi->products[vi->n_products].universal   = universal;
    vi->n_products++;
    return 1;
}

/* Walk each "Document":{...} record in a GetCplData reply. */
static int parse_cpl_products(const char *json, const char *account_id, vendor_info_t *vi)
{
    const char *p = json;
    int         added = 0;

    for (;;) {
        const char *rec, *end;
        char sub[40], name[256], os[512], flag[16];
        int  decl = 0, uni = 0;

        rec = strstr(p, "\"Document\":{");
        if (!rec) break;
        rec += 12;
        end = strstr(rec, "\"Document\":{");   /* next record bounds this one */

        json_str(rec, end, "SubmissionId", sub, sizeof(sub));
        json_str(rec, end, "ProductName", name, sizeof(name));
        json_str(rec, end, "SelectedOsCodes", os, sizeof(os));

        /* booleans are unquoted, so look for the literal */
        {
            const char *f = strstr(rec, "\"IsDeclarativeDriver\":true");
            if (f && (!end || f < end)) decl = 1;
            f = strstr(rec, "\"IsUniversalDriver\":true");
            if (f && (!end || f < end)) uni = 1;
        }
        (void)flag;

        if (vendor_add_product(vi, account_id, sub, name, os, decl, uni) == 1) added++;

        if (!end) break;
        p = end;
    }
    return added;
}

/* --------------------------------------------------------------- lookup --- */

/* Walk every element of the accounts array. A name prefix commonly matches
 * SEVERAL distinct publishers - "raytheon" returns Raytheon Company, Raytheon
 * Anschuetz GmbH and Raytheon Technologies - and they are unrelated accounts
 * with unrelated driver catalogues. Taking the first would quietly hide the
 * rest, so collect them all and let the caller decide. */
static int parse_cpl_accounts(const char *json, vendor_info_t *vi)
{
    const char *p = json;

    vi->n_accounts = 0;
    vi->truncated_accounts = 0;

    for (;;) {
        char id[32], pub[256];
        const char *after;

        after = json_str(p, NULL, "AccountId", id, sizeof(id));
        if (!after || !id[0]) break;
        json_str(after, NULL, "PublisherName", pub, sizeof(pub));

        if (vi->n_accounts >= PF_CPL_MAX_ACCOUNTS) { vi->truncated_accounts = 1; break; }

        memset(&vi->accounts[vi->n_accounts], 0, sizeof(cpl_account_t));
        strncpy(vi->accounts[vi->n_accounts].account_id, id,
                sizeof(vi->accounts[0].account_id) - 1);
        strncpy(vi->accounts[vi->n_accounts].publisher, pub,
                sizeof(vi->accounts[0].publisher) - 1);
        vi->n_accounts++;

        p = after;
    }
    return vi->n_accounts;
}

/* Rank a publisher against the name DeviceHunt gave us, so that when several
 * match there is a defensible default rather than "whichever came first". */
static int score_account(const char *dh_name, const char *publisher)
{
    size_t ld, lp;

    if (!dh_name || !dh_name[0] || !publisher || !publisher[0]) return 0;
    if (!_stricmp(dh_name, publisher)) return 1000;

    ld = strlen(dh_name);
    lp = strlen(publisher);

    /* "Aladdin Knowledge Systems" vs "Aladdin Knowledge Systems LTD." - the
     * directory name extends ours. The less it extends, the better the match. */
    if (lp >= ld && !_strnicmp(publisher, dh_name, ld))
        return 800 - (int)(lp - ld > 200 ? 200 : lp - ld);
    if (ld >= lp && !_strnicmp(dh_name, publisher, lp))
        return 700 - (int)(ld - lp > 200 ? 200 : ld - lp);

    {   /* case-insensitive substring anywhere */
        char a[256], b[256];
        size_t i;
        strncpy(a, dh_name, sizeof(a) - 1);   a[sizeof(a) - 1] = 0;
        strncpy(b, publisher, sizeof(b) - 1); b[sizeof(b) - 1] = 0;
        for (i = 0; a[i]; i++) a[i] = (char)tolower((unsigned char)a[i]);
        for (i = 0; b[i]; i++) b[i] = (char)tolower((unsigned char)b[i]);
        if (strstr(b, a) || strstr(a, b)) return 500;
    }
    return 100;
}

/* Ask the partner directory for accounts whose publisher name matches `query`.
 * Returns the number found, or -1 on a transport error. */
static int cpl_find_accounts(vhttp *h, const char *query, vendor_info_t *vi)
{
    char    enc[512], path_a[768];
    wchar_t path_w[768];
    vbuf    body;
    int     status, n = 0;

    url_encode(query, enc, sizeof(enc));
    _snprintf(path_a, sizeof(path_a),
              "/en-us/dashboard/hardware/search/accounts?publisher=%s", enc);
    path_a[sizeof(path_a) - 1] = '\0';
    a2w(path_a, path_w, sizeof(path_w) / sizeof(path_w[0]));

    vbuf_init(&body);
    status = vhttp_req(h->conn_ms, L"GET", path_w,
                       L"Accept: application/json, text/plain, */*\r\n"
                       VH_CPL_REFERER, NULL, &body);

    if (status == 200 && body.buf && strstr(body.buf, "\"AccountId\"")) {
        n = parse_cpl_accounts(body.buf, vi);
    } else if (status < 0) {
        n = -1;
    }
    vbuf_free(&body);
    return n;
}

/* Trim the trailing word from a company name, so "Aladdin Knowledge Systems"
 * degrades to "Aladdin Knowledge" then "Aladdin". Returns 0 when nothing is
 * left to trim. Corporate suffixes rarely match the partner directory's own
 * spelling, so shortening is what finds the account. */
static int shorten_name(char *s)
{
    char *sp = strrchr(s, ' ');
    if (!sp) return 0;
    *sp = '\0';
    vtrim(s);
    return (strlen(s) >= 3);
}

/* Decide which of several matching publishers to enumerate. */
static void choose_accounts(vendor_info_t *vi, const vendor_opts_t *opt)
{
    int i, best = 0;

    for (i = 0; i < vi->n_accounts; i++) {
        vi->accounts[i].score = score_account(vi->dh_name, vi->accounts[i].publisher);
        if (vi->accounts[i].score > vi->accounts[best].score) best = i;
    }

    if (vi->n_accounts <= 0) return;

    /* An explicit id always wins - no prompting, no guessing. */
    if (opt->pick_account && opt->pick_account[0]) {
        int hit = 0;
        for (i = 0; i < vi->n_accounts; i++) {
            if (!strcmp(vi->accounts[i].account_id, opt->pick_account)) {
                vi->accounts[i].selected = 1;
                hit = 1;
            }
        }
        if (!hit)
            log_console(PF_WARN, "--cpl-account %s is not among the matches; "
                                 "enumerating the best name match instead.",
                        opt->pick_account);
        else { vi->n_selected = 1; return; }
    }

    if (opt->scan_all || vi->n_accounts == 1) {
        for (i = 0; i < vi->n_accounts; i++) vi->accounts[i].selected = 1;
        vi->n_selected = vi->n_accounts;
        return;
    }

    /* Several matches and no instruction. Surface the ambiguity rather than
     * silently picking: these are different companies, and the drivers being
     * hunted may belong to any of them. */
    log_console(PF_WARN, "%d publishers match \"%s\" in the partner directory:",
                vi->n_accounts, vi->cpl_query_used);
    for (i = 0; i < vi->n_accounts; i++)
        log_console(PF_INFO, "    %d) %-40s (%s)%s",
                    i + 1, vi->accounts[i].publisher, vi->accounts[i].account_id,
                    i == best ? "  <- closest name match" : "");
    log_console(PF_INFO, "  These are separate partner accounts with separate driver "
                         "catalogues, so the drivers you are after may sit under any of "
                         "them.");

    if (opt->interactive) {
        char line[64];
        log_console(PF_INFO, "  Enter a number, or 'a' for all [default %d]: ", best + 1);
        if (fgets(line, sizeof(line), stdin)) {
            char *t = line;
            while (*t == ' ' || *t == '\t') t++;
            if (*t == 'a' || *t == 'A') {
                for (i = 0; i < vi->n_accounts; i++) vi->accounts[i].selected = 1;
                vi->n_selected = vi->n_accounts;
                return;
            }
            if (*t >= '1' && *t <= '9') {
                int pick = atoi(t);
                if (pick >= 1 && pick <= vi->n_accounts) {
                    vi->accounts[pick - 1].selected = 1;
                    vi->n_selected = 1;
                    return;
                }
            }
        }
        /* empty line, EOF or nonsense: fall through to the default */
    } else {
        log_console(PF_INFO, "  No console to ask on (stdin is redirected), so defaulting to "
                             "the closest name match. Use --cpl-all to enumerate every one, "
                             "or --cpl-account <id> to choose in advance.");
    }

    vi->accounts[best].selected = 1;
    vi->n_selected = 1;
}

/* Enumerate one publisher's certified submissions by single-letter substring.
 * Progress is reported per letter: this is 26 network round trips with a
 * politeness delay between them, so a silent ten seconds reads as a hang.
 * step_base/step_total express progress across ALL selected publishers, so the
 * percentage answers "how far through the whole recon am I" rather than
 * restarting at zero for each account. */
static void enumerate_account(vhttp *h, vendor_info_t *vi, cpl_account_t *acc,
                              int step_base, int step_total, int multi)
{
    int before = vi->n_products;
    int i, status;

    for (i = 0; i < 26 && !g_abort; i++) {
        char post[256];
        vbuf reply;
        int  found_before = vi->n_products;
        int  step = step_base + i + 1;

        _snprintf(post, sizeof(post),
                  "{\"accountId\":\"%s\",\"productName\":\"%c\",\"duFlagOption\":\"All\","
                  "\"certificationStatusOption\":\"Certified\","
                  "\"selectedOsCode\":\"All Operating Systems\",\"page\":1}",
                  acc->account_id, 'a' + i);
        post[sizeof(post) - 1] = '\0';

        vbuf_init(&reply);
        status = vhttp_req(h->conn_ms, L"POST",
                           L"/en-us/dashboard/hardware/Search/GetCplData",
                           L"Content-Type: application/json;charset=UTF-8\r\n"
                           L"Accept: application/json, text/plain, */*\r\n"
                           L"Origin: https://partner.microsoft.com\r\n"
                           VH_CPL_REFERER,
                           post, &reply);
        if (status == 200 && reply.buf) {
            parse_cpl_products(reply.buf, acc->account_id, vi);
            vi->letters_ok++;
        }
        vbuf_free(&reply);
        vi->letters_tried++;

        {
            int gained = vi->n_products - found_before;
            double pct = step_total ? (double)step * 100.0 / (double)step_total : 100.0;
            if (multi)
                log_console(gained ? PF_GOOD : PF_INFO,
                            "    [%3d/%3d %5.1f%%] %s '%c'%s  (%d total)",
                            step, step_total, pct, acc->publisher, 'a' + i,
                            status != 200 ? "  query failed" :
                            gained ? "" : "  -",
                            vi->n_products);
            else
                log_console(gained ? PF_GOOD : PF_INFO,
                            "    [%2d/26 %5.1f%%] '%c'%s%s  (%d found so far)",
                            i + 1, pct, 'a' + i,
                            gained ? "  +" : "   ",
                            status != 200 ? " query failed" :
                            gained ? "new" : "-",
                            vi->n_products);
        }

        if (i < 25 && !g_abort) Sleep(VH_LETTER_DELAY_MS);
    }
    acc->n_products = vi->n_products - before;
}

int vendor_lookup(const char *bus, unsigned vid, const vendor_opts_t *opt,
                  vendor_info_t *vi)
{
    vhttp        h;
    vbuf         body;
    char         path_a[256];
    wchar_t      path_w[256];
    vendor_opts_t defaults;
    pf_bus       busid;
    int          status, i;

    memset(vi, 0, sizeof(*vi));
    if (!opt) {
        memset(&defaults, 0, sizeof(defaults));
        opt = &defaults;
    }
    busid = (bus && !_stricmp(bus, "pci")) ? PF_BUS_PCI : PF_BUS_USB;

    /* --- 0. Local USB-IF table ---------------------------------------- */
    /* Tried before the network because it is authoritative for USB (it IS the
     * registry), instant, and works offline. DeviceHunt is the fallback for what
     * it does not cover: PCI entirely, and any USB vendor registered after this
     * table was generated. */
    {
        char local[4][256];
        int  n = vendordb_lookup(busid, vid, local, 4);
        if (n > 0) {
            vi->dh_found = 1;
            vi->from_local = 1;
            strncpy(vi->dh_name, local[0], sizeof(vi->dh_name) - 1);
            vi->dh_name[sizeof(vi->dh_name) - 1] = '\0';
            log_console(PF_GOOD, "  Vendor       : %s", vi->dh_name);
            log_console(PF_INFO, "                 (local %s, %d vendors - no lookup needed)",
                        PF_VENDORDB_SOURCE, PF_VENDORDB_COUNT);
            for (i = 1; i < n; i++)
                log_console(PF_INFO, "                 also registered to: %s", local[i]);
        }
    }

    if (vhttp_open(&h) != 0) {
        strncpy(vi->error, "could not initialise WinHTTP", sizeof(vi->error) - 1);
        /* A local hit is still a complete stage 1; only the partner lookups are
         * lost, so report what we have rather than failing outright. */
        return vi->dh_found ? 0 : -1;
    }

    /* --- 1. DeviceHunt: vendor ID -> company name --------------------- */
    h.conn_dh = vi->from_local ? NULL
              : WinHttpConnect(h.session, VH_HOST_DEVICEHUNT,
                               INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (h.conn_dh) {
        _snprintf(path_a, sizeof(path_a), "/view/type/%s/vendor/%04X",
                  (bus && !_stricmp(bus, "pci")) ? "pci" : "usb", vid);
        path_a[sizeof(path_a) - 1] = '\0';
        a2w(path_a, path_w, sizeof(path_w) / sizeof(path_w[0]));

        vbuf_init(&body);
        status = vhttp_req(h.conn_dh, L"GET", path_w, NULL, NULL, &body);
        if (status == 200 && body.buf &&
            parse_devicehunt_title(body.buf, vi->dh_name, sizeof(vi->dh_name)) == 0) {
            vi->dh_found = 1;
        } else if (status < 0) {
            strncpy(vi->error, "DeviceHunt unreachable", sizeof(vi->error) - 1);
        }
        vbuf_free(&body);
    }

    /* Report stage 1 immediately. The partner lookups that follow take tens of
     * seconds, and the vendor name is the single most useful thing here - there
     * is no reason to withhold it until the end. (A local hit already printed
     * above and skipped the network entirely.) */
    if (!vi->from_local) {
        if (vi->dh_found)
            log_console(PF_GOOD, "  DeviceHunt   : %s", vi->dh_name);
        else if (busid == PF_BUS_PCI)
            log_console(PF_WARN, "  DeviceHunt   : no entry for PCI vendor %04X. That does NOT "
                                 "mean the ID is invalid - DeviceHunt may simply not have "
                                 "indexed it.", vid);
        else
            log_console(PF_WARN, "  DeviceHunt   : no entry for %04X, and it is not in the local "
                                 "%s either. Unassigned, or newer than both lists.",
                        vid, PF_VENDORDB_SOURCE);
    }

    if (!vi->dh_found) { vhttp_close(&h); return 0; }

    /* --- 2. Partner Center: seed cookies, then find the publishers ----- */
    h.conn_ms = WinHttpConnect(h.session, VH_HOST_PARTNER, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!h.conn_ms) { vhttp_close(&h); return 0; }

    vbuf_init(&body);
    status = vhttp_req(h.conn_ms, L"GET", L"/en-us/dashboard/hardware/search/cpl",
                       NULL, NULL, &body);
    vbuf_free(&body);
    if (status < 0) {
        strncpy(vi->error, "partner.microsoft.com unreachable", sizeof(vi->error) - 1);
        vhttp_close(&h);
        return 0;
    }

    log_console(PF_INFO, "  Partner CPL  : searching the hardware partner directory for "
                         "\"%s\"...", vi->dh_name);
    {
        char attempt[256];
        int  n = 0, tries = 0;
        strncpy(attempt, vi->dh_name, sizeof(attempt) - 1);
        attempt[sizeof(attempt) - 1] = '\0';
        for (;;) {
            n = cpl_find_accounts(&h, attempt, vi);
            if (n > 0) {
                strncpy(vi->cpl_query_used, attempt, sizeof(vi->cpl_query_used) - 1);
                vi->cpl_found = 1;
                break;
            }
            if (++tries >= 4 || !shorten_name(attempt)) break;
            log_console(PF_INFO, "                 no match; retrying as \"%s\"", attempt);
        }
    }

    if (!vi->cpl_found) {
        log_console(PF_WARN, "  Partner CPL  : no publisher matching that name.");
        vhttp_close(&h);
        return 0;
    }
    if (vi->n_accounts == 1)
        log_console(PF_GOOD, "  Partner CPL  : %s  (account %s)",
                    vi->accounts[0].publisher, vi->accounts[0].account_id);

    /* --- 3. Pick publisher(s), then enumerate each --------------------- */
    choose_accounts(vi, opt);

    {
        int total = vi->n_selected * 26, base = 0;
        log_console(PF_INFO, "  Certified    : enumerating submissions a-z across %d "
                             "publisher(s), %d queries...", vi->n_selected, total);
        for (i = 0; i < vi->n_accounts && !g_abort; i++) {
            if (!vi->accounts[i].selected) continue;
            enumerate_account(&h, vi, &vi->accounts[i], base, total, vi->n_selected > 1);
            base += 26;
            if (vi->n_selected > 1)
                log_console(PF_GOOD, "    %s: %d submission(s)",
                            vi->accounts[i].publisher, vi->accounts[i].n_products);
        }
        if (g_abort)
            log_console(PF_WARN, "  Certified    : interrupted after %d of %d queries.",
                        vi->letters_tried, total);
    }

    vhttp_close(&h);
    return 0;
}

void vendor_free(vendor_info_t *vi)
{
    free(vi->products);
    vi->products = NULL;
    vi->n_products = vi->cap_products = 0;
}

/* --------------------------------------------------------------- report --- */

void vendor_report(const vendor_info_t *vi, const char *bus, unsigned vid)
{
    jb_t jb;
    int  i, j, shown;

    /* Stages 1 and 2 already reported themselves live during the lookup - the
     * vendor name and publisher matter too much to withhold while the 26-query
     * enumeration runs. This is the summary of what was found. */
    log_console(PF_INFO, "Vendor recon summary for %s\\VID_%04X", bus, vid);

    if (vi->dh_found) {
        if (!vi->cpl_found) {
            log_console(PF_WARN, "                 Either the vendor no longer ships Windows "
                                 "drivers, or it reserves IDs for its customers and the "
                                 "drivers are published under THEIR name instead.");
        } else {
            if (vi->n_accounts > 1) {
                log_console(PF_GOOD, "  Publishers   : %d matched \"%s\"",
                            vi->n_accounts, vi->cpl_query_used);
                for (i = 0; i < vi->n_accounts; i++)
                    log_console(vi->accounts[i].selected ? PF_GOOD : PF_INFO,
                                "      %s %-38s (%s)%s",
                                vi->accounts[i].selected ? "[x]" : "[ ]",
                                vi->accounts[i].publisher,
                                vi->accounts[i].account_id,
                                vi->accounts[i].selected ? "" : "  not enumerated");
                if (vi->truncated_accounts)
                    log_console(PF_WARN, "      (more matches existed than could be listed; "
                                         "narrow the name to see the rest)");
                if (vi->n_selected < vi->n_accounts)
                    log_console(PF_INFO, "      --cpl-all enumerates every one; "
                                         "--cpl-account <id> picks a specific publisher.");
            } else if (_stricmp(vi->accounts[0].publisher, vi->dh_name) != 0) {
                log_console(PF_INFO, "  Publishers   : matched on \"%s\"", vi->cpl_query_used);
            }

            if (vi->n_products == 0) {
                log_console(PF_WARN, "  Certified    : none found across %d letter queries. "
                                     "The publisher exists but has no certified submissions "
                                     "visible here.", vi->letters_ok);
            } else {
                log_console(PF_GOOD, "  Certified    : %d distinct submission(s) from %d letter "
                                     "queries", vi->n_products, vi->letters_ok);
                /* Group under the publisher they belong to, so a multi-account
                 * scan does not blur two companies' catalogues together. */
                for (i = 0; i < vi->n_accounts; i++) {
                    if (!vi->accounts[i].selected) continue;
                    if (vi->n_selected > 1)
                        log_console(PF_GOOD, "    %s (%s): %d",
                                    vi->accounts[i].publisher,
                                    vi->accounts[i].account_id,
                                    vi->accounts[i].n_products);
                    shown = 0;
                    for (j = 0; j < vi->n_products && shown < 12; j++) {
                        if (strcmp(vi->products[j].account_id,
                                   vi->accounts[i].account_id) != 0) continue;
                        log_console(PF_GOOD, "      - %s%s%s",
                                    vi->products[j].product_name,
                                    vi->products[j].universal ? " [universal]" : "",
                                    vi->products[j].declarative ? " [declarative]" : "");
                        shown++;
                    }
                    if (vi->accounts[i].n_products > shown)
                        log_console(PF_INFO, "      ... and %d more (all of them are in the "
                                             "JSONL)", vi->accounts[i].n_products - shown);
                }
            }
        }
    }

    /* The whole point of the recon: say what it implies for the sweep. */
    if (vi->dh_found && vi->cpl_found && vi->n_products > 0)
        log_console(PF_GOOD, "  Outlook      : STRONG - active publisher with certified drivers, "
                             "so Windows Update packages for this vendor are plausible.");
    else if (vi->dh_found && vi->cpl_found)
        log_console(PF_INFO, "  Outlook      : MIXED - publisher exists but no certified "
                             "submissions surfaced.");
    else if (vi->dh_found)
        log_console(PF_INFO, "  Outlook      : WEAK - vendor is known but absent from the "
                             "hardware partner directory.");
    else
        log_console(PF_INFO, "  Outlook      : UNKNOWN - nothing resolved; the sweep is still "
                             "valid, there is just no prior expectation.");

    if (vi->error[0])
        log_console(PF_WARN, "  (recon note: %s)", vi->error);

    jb_init(&jb);
    jb_str(&jb, "bus", bus);
    jb_u64(&jb, "vid", vid);
    jb_bool(&jb, "vendor_resolved", vi->dh_found);
    jb_str(&jb, "vendor_name", vi->dh_name);
    jb_str(&jb, "vendor_name_source", vi->from_local ? "local-usbif" : "devicehunt");
    jb_bool(&jb, "cpl_found", vi->cpl_found);
    jb_str(&jb, "cpl_query_used", vi->cpl_query_used);
    jb_num(&jb, "cpl_accounts_matched", vi->n_accounts);
    jb_num(&jb, "cpl_accounts_enumerated", vi->n_selected);
    jb_bool(&jb, "cpl_accounts_truncated", vi->truncated_accounts);
    jb_num(&jb, "certified_submissions", vi->n_products);
    jb_num(&jb, "letters_queried", vi->letters_tried);
    jb_num(&jb, "letters_ok", vi->letters_ok);
    if (vi->error[0]) jb_str(&jb, "error", vi->error);
    log_event(PF_INFO, "vendor_recon", jb_get(&jb));
    jb_free(&jb);

    /* Every matched publisher is recorded, enumerated or not, so a later read of
     * the log shows exactly what was considered and what was skipped. */
    for (i = 0; i < vi->n_accounts; i++) {
        jb_t aj;
        jb_init(&aj);
        jb_str(&aj, "account_id", vi->accounts[i].account_id);
        jb_str(&aj, "publisher", vi->accounts[i].publisher);
        jb_num(&aj, "name_score", vi->accounts[i].score);
        jb_bool(&aj, "enumerated", vi->accounts[i].selected);
        jb_num(&aj, "certified_submissions", vi->accounts[i].n_products);
        log_event(PF_INFO, "vendor_cpl_account", jb_get(&aj));
        jb_free(&aj);
    }

    for (i = 0; i < vi->n_products; i++) {
        jb_t pj;
        jb_init(&pj);
        jb_str(&pj, "account_id", vi->products[i].account_id);
        jb_str(&pj, "submission_id", vi->products[i].submission_id);
        jb_str(&pj, "product_name", vi->products[i].product_name);
        jb_str(&pj, "os_codes", vi->products[i].os_codes);
        jb_bool(&pj, "universal", vi->products[i].universal);
        jb_bool(&pj, "declarative", vi->products[i].declarative);
        log_event(PF_INFO, "vendor_certified_product", jb_get(&pj));
        jb_free(&pj);
    }
}
