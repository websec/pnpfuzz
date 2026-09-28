/*
 * hwid.c - search-space parsing, mixed-radix odometer, hardware-ID synthesis
 *
 * Design points that matter:
 *   - Values are ALWAYS hexadecimal, so `10` is 0x10 and never decimal, and
 *     0x0000 is reachable across the full 0x0-0xFFFF PID range.
 *   - The position in the space is a single 64-bit index, so --resume is exact
 *     and total counts do not overflow.
 *   - Class/SubClass/Protocol become real compatible IDs on the device node,
 *     so sweeping them produces a distinguishable driver-match result rather
 *     than keying on VID/PID alone.
 */

#include "pnpfuzz.h"

/* ---------------------------------------------------------------- parse -- */

static int parse_hex(const char *s, uint32_t *out)
{
    char     tmp[32];
    size_t   n;
    uint32_t v = 0;
    int      digits = 0;
    int      i;

    if (!s) return -1;
    while (*s == ' ' || *s == '\t') s++;

    n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t')) n--;
    if (n == 0 || n >= sizeof(tmp)) return -1;
    memcpy(tmp, s, n);
    tmp[n] = '\0';

    i = 0;
    if (tmp[0] == '0' && (tmp[1] == 'x' || tmp[1] == 'X')) i = 2;
    if (!tmp[i]) return -1;

    for (; tmp[i]; i++) {
        int d;
        if      (tmp[i] >= '0' && tmp[i] <= '9') d = tmp[i] - '0';
        else if (tmp[i] >= 'a' && tmp[i] <= 'f') d = tmp[i] - 'a' + 10;
        else if (tmp[i] >= 'A' && tmp[i] <= 'F') d = tmp[i] - 'A' + 10;
        else return -1;
        if (digits >= 8) return -1;
        v = (v << 4) | (uint32_t)d;
        digits++;
    }
    if (!digits) return -1;
    *out = v;
    return 0;
}

static int axis_push(axis_t *a, uint32_t v, int *cap)
{
    if (a->n >= *cap) {
        int nc = *cap ? *cap * 2 : 64;
        uint32_t *p = (uint32_t *)realloc(a->v, (size_t)nc * sizeof(uint32_t));
        if (!p) return -1;
        a->v = p;
        *cap = nc;
    }
    a->v[a->n++] = v;
    return 0;
}

int axis_parse(axis_t *a, const char *spec, uint32_t max, const char *name)
{
    char  buf[4096];
    char *tok, *ctx = NULL;
    int   cap = 0;

    axis_free(a);               /* repeating a flag must not leak the first */
    memset(a, 0, sizeof(*a));
    if (!spec || !*spec) return -1;

    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    for (tok = strtok_s(buf, ",", &ctx); tok; tok = strtok_s(NULL, ",", &ctx)) {
        char *dash;
        uint32_t lo, hi, i;

        while (*tok == ' ') tok++;
        if (!*tok) continue;

        if (strcmp(tok, "*") == 0) {
            lo = 0;
            hi = max;
        } else if ((dash = strchr(tok + 1, '-')) != NULL) {
            *dash = '\0';
            if (parse_hex(tok, &lo) != 0 || parse_hex(dash + 1, &hi) != 0) {
                log_console(PF_ERR, "%s: cannot parse range '%s-%s' (values are hex)",
                            name, tok, dash + 1);
                axis_free(a);
                return -1;
            }
            if (lo > hi) { uint32_t t = lo; lo = hi; hi = t; }
        } else {
            if (parse_hex(tok, &lo) != 0) {
                log_console(PF_ERR, "%s: cannot parse '%s' (values are hex, e.g. 046D or 0x046D)",
                            name, tok);
                axis_free(a);
                return -1;
            }
            hi = lo;
        }

        if (hi > max) {
            log_console(PF_ERR, "%s: value 0x%X exceeds the maximum 0x%X", name, hi, max);
            axis_free(a);
            return -1;
        }
        if ((uint64_t)a->n + (hi - lo + 1) > PF_MAX_AXIS_VALUES) {
            log_console(PF_ERR, "%s: more than %d values requested", name, PF_MAX_AXIS_VALUES);
            axis_free(a);
            return -1;
        }
        for (i = lo; ; i++) {
            if (axis_push(a, i, &cap) != 0) { axis_free(a); return -1; }
            if (i == hi) break;
        }
    }

    if (a->n == 0) {
        log_console(PF_ERR, "%s: empty specification", name);
        return -1;
    }
    a->given = 1;
    return 0;
}

void axis_single(axis_t *a, uint32_t value)
{
    int cap = 0;
    axis_free(a);
    memset(a, 0, sizeof(*a));
    if (axis_push(a, value, &cap) != 0) {
        /* An axis of length zero would divide by zero in space_at. There is
         * nothing sensible to continue with. */
        fprintf(stderr, "[-] out of memory building the search space\n");
        exit(1);
    }
    a->given = 0;
}

void axis_free(axis_t *a)
{
    free(a->v);
    a->v = NULL;
    a->n = 0;
}

/* ------------------------------------------------------------------ bus -- */

const char *pf_bus_name(pf_bus b)
{
    return (b == PF_BUS_PCI) ? "PCI" : "USB";
}

const char *pf_bus_enumerator(pf_bus b)
{
    return (b == PF_BUS_PCI) ? "PCI" : "USB";
}

/* ---------------------------------------------------------------- space -- */

int space_finalise(space_t *sp, char *err, size_t errcap)
{
    uint64_t t;

    if (!sp->vid.n || !sp->pid.n) {
        _snprintf(err, errcap, "--vid is required (--pid defaults to the full 0000-FFFF range)");
        err[errcap - 1] = '\0';
        return -1;
    }
    if (!sp->rev.n)  axis_single(&sp->rev,  0);
    if (!sp->mi.n)   axis_single(&sp->mi,   0);
    if (!sp->cls.n)  axis_single(&sp->cls,  0);
    if (!sp->sub.n)  axis_single(&sp->sub,  0);
    if (!sp->prot.n) axis_single(&sp->prot, 0);
    if (!sp->subsys.n) axis_single(&sp->subsys, 0);

    /* SubClass/Protocol only mean anything under a Class. */
    if ((sp->sub.given || sp->prot.given) && !sp->cls.given) {
        _snprintf(err, errcap,
                  "--subclass/--protocol require --class (USB compatible IDs are "
                  "Class, Class+SubClass, Class+SubClass+Prot)");
        err[errcap - 1] = '\0';
        return -1;
    }
    if (sp->prot.given && !sp->sub.given) {
        _snprintf(err, errcap, "--protocol requires --subclass");
        err[errcap - 1] = '\0';
        return -1;
    }

    /* Multiply with an overflow check. A tool whose whole point is exhaustive
     * coverage must never silently wrap and sweep a fraction of the space. */
    {
        const axis_t *ax[8];
        int j;
        t = 1;
        ax[0] = &sp->vid;  ax[1] = &sp->pid;  ax[2] = &sp->rev;  ax[3] = &sp->mi;
        ax[4] = &sp->cls;  ax[5] = &sp->sub;  ax[6] = &sp->prot; ax[7] = &sp->subsys;
        for (j = 0; j < 8; j++) {
            if (ax[j]->n <= 0 || t > (~(uint64_t)0) / (uint64_t)ax[j]->n) {
                _snprintf(err, errcap,
                          "the requested search space is too large to enumerate "
                          "(narrow at least one axis)");
                err[errcap - 1] = '\0';
                return -1;
            }
            t *= (uint64_t)ax[j]->n;
        }
    }
    sp->total = t;
    return 0;
}

uint64_t space_total(const space_t *sp)
{
    return sp->total;
}

void space_free(space_t *sp)
{
    axis_free(&sp->vid);  axis_free(&sp->pid);  axis_free(&sp->rev);
    axis_free(&sp->mi);   axis_free(&sp->cls);  axis_free(&sp->sub);
    axis_free(&sp->prot); axis_free(&sp->subsys);
}

/* Odometer order, fastest first: PID, REV, MI, Prot, SubClass, Class, VID.
 * PID being fastest is deliberate: a batch is then a run of consecutive PIDs
 * on one VID, so every ID in a batch shares the same compatible IDs. */
void space_at(const space_t *sp, uint64_t index, combo_t *out)
{
    uint64_t x = index;
    int i_pid, i_rev, i_mi, i_prot, i_sub, i_cls, i_vid, i_subsys;
    char base[PF_MAX_ID];
    int  n;

    memset(out, 0, sizeof(*out));
    out->index = index;

    i_pid    = (int)(x % (uint64_t)sp->pid.n);    x /= (uint64_t)sp->pid.n;
    i_rev    = (int)(x % (uint64_t)sp->rev.n);    x /= (uint64_t)sp->rev.n;
    i_mi     = (int)(x % (uint64_t)sp->mi.n);     x /= (uint64_t)sp->mi.n;
    i_prot   = (int)(x % (uint64_t)sp->prot.n);   x /= (uint64_t)sp->prot.n;
    i_sub    = (int)(x % (uint64_t)sp->sub.n);    x /= (uint64_t)sp->sub.n;
    i_cls    = (int)(x % (uint64_t)sp->cls.n);    x /= (uint64_t)sp->cls.n;
    i_subsys = (int)(x % (uint64_t)sp->subsys.n); x /= (uint64_t)sp->subsys.n;
    i_vid    = (int)(x % (uint64_t)sp->vid.n);

    out->vid    = sp->vid.v[i_vid];
    out->pid    = sp->pid.v[i_pid];
    out->rev    = sp->rev.v[i_rev];
    out->mi     = sp->mi.v[i_mi];
    out->cls    = sp->cls.v[i_cls];
    out->sub    = sp->sub.v[i_sub];
    out->prot   = sp->prot.v[i_prot];
    out->subsys = sp->subsys.v[i_subsys];

    if (sp->bus == PF_BUS_PCI) {
        /* PCI/PCIe enumerate on VEN (vendor, PCI-SIG assigned) and DEV, the
         * direct analogue of USB's VID and PID. SUBSYS is the 32-bit subsystem
         * pair and CC the class code (class, subclass, prog-IF) - the analogue
         * of USB's Class/SubClass/Protocol triplet.
         *
         * On real hardware Windows reports PCI\VEN&DEV&SUBSYS&REV as the most
         * specific HARDWARE id and the bare PCI\VEN&DEV only as a COMPATIBLE
         * id. Driver matching considers both lists, and third-party INFs
         * overwhelmingly key on VEN&DEV (with or without SUBSYS), so the bare
         * form is emitted as a hardware id here: it is what makes a DEV sweep
         * match anything, and a match on it is exactly the finding of interest.
         */
        _snprintf(base, sizeof(base), "PCI\\VEN_%04X&DEV_%04X", out->vid, out->pid);
        base[sizeof(base) - 1] = '\0';

        n = 0;
        if (sp->subsys.given && sp->rev.given) {
            _snprintf(out->ids[n++], PF_MAX_ID, "%s&SUBSYS_%08X&REV_%02X",
                      base, out->subsys, out->rev);
            _snprintf(out->ids[n++], PF_MAX_ID, "%s&SUBSYS_%08X", base, out->subsys);
            if (sp->with_plain)
                _snprintf(out->ids[n++], PF_MAX_ID, "%s", base);
        } else if (sp->subsys.given) {
            _snprintf(out->ids[n++], PF_MAX_ID, "%s&SUBSYS_%08X", base, out->subsys);
            if (sp->with_plain)
                _snprintf(out->ids[n++], PF_MAX_ID, "%s", base);
        } else if (sp->rev.given) {
            _snprintf(out->ids[n++], PF_MAX_ID, "%s&REV_%02X", base, out->rev);
            if (sp->with_plain)
                _snprintf(out->ids[n++], PF_MAX_ID, "%s", base);
        } else {
            _snprintf(out->ids[n++], PF_MAX_ID, "%s", base);
        }
        out->n_ids = n;
        for (i_pid = 0; i_pid < n; i_pid++) out->ids[i_pid][PF_MAX_ID - 1] = '\0';

        strncpy(out->label, out->ids[0], PF_MAX_ID - 1);
        out->label[PF_MAX_ID - 1] = '\0';

        /* Class-code compatible IDs, most specific first, exactly as the PCI
         * enumerator reports them. */
        n = 0;
        if (sp->cls.given) {
            if (sp->sub.given && sp->prot.given) {
                _snprintf(out->compat[n++], PF_MAX_ID, "PCI\\VEN_%04X&CC_%02X%02X%02X",
                          out->vid, out->cls, out->sub, out->prot);
                _snprintf(out->compat[n++], PF_MAX_ID, "PCI\\CC_%02X%02X%02X",
                          out->cls, out->sub, out->prot);
            }
            if (sp->sub.given) {
                _snprintf(out->compat[n++], PF_MAX_ID, "PCI\\VEN_%04X&CC_%02X%02X",
                          out->vid, out->cls, out->sub);
                _snprintf(out->compat[n++], PF_MAX_ID, "PCI\\CC_%02X%02X",
                          out->cls, out->sub);
            }
            _snprintf(out->compat[n++], PF_MAX_ID, "PCI\\VEN_%04X", out->vid);
        }
        out->n_compat = n;
        for (i_pid = 0; i_pid < n; i_pid++) out->compat[i_pid][PF_MAX_ID - 1] = '\0';
        return;
    }

    _snprintf(base, sizeof(base), "USB\\VID_%04X&PID_%04X", out->vid, out->pid);
    base[sizeof(base) - 1] = '\0';

    /* Hardware IDs, most specific first - the order a real USB hub reports. */
    n = 0;
    if (sp->rev.given && sp->mi.given) {
        _snprintf(out->ids[n++], PF_MAX_ID, "%s&REV_%04X&MI_%02X", base, out->rev, out->mi);
        _snprintf(out->ids[n++], PF_MAX_ID, "%s&MI_%02X", base, out->mi);
        if (sp->with_plain) {
            _snprintf(out->ids[n++], PF_MAX_ID, "%s&REV_%04X", base, out->rev);
            _snprintf(out->ids[n++], PF_MAX_ID, "%s", base);
        }
    } else if (sp->rev.given) {
        _snprintf(out->ids[n++], PF_MAX_ID, "%s&REV_%04X", base, out->rev);
        if (sp->with_plain)
            _snprintf(out->ids[n++], PF_MAX_ID, "%s", base);
    } else if (sp->mi.given) {
        _snprintf(out->ids[n++], PF_MAX_ID, "%s&MI_%02X", base, out->mi);
        if (sp->with_plain)
            _snprintf(out->ids[n++], PF_MAX_ID, "%s", base);
    } else {
        _snprintf(out->ids[n++], PF_MAX_ID, "%s", base);
    }
    out->n_ids = n;

    {
        int k;
        for (k = 0; k < n; k++) out->ids[k][PF_MAX_ID - 1] = '\0';
    }
    strncpy(out->label, out->ids[0], PF_MAX_ID - 1);
    out->label[PF_MAX_ID - 1] = '\0';

    /* Compatible IDs, most specific first. */
    n = 0;
    if (sp->cls.given) {
        if (sp->sub.given && sp->prot.given)
            _snprintf(out->compat[n++], PF_MAX_ID, "USB\\Class_%02X&SubClass_%02X&Prot_%02X",
                      out->cls, out->sub, out->prot);
        if (sp->sub.given)
            _snprintf(out->compat[n++], PF_MAX_ID, "USB\\Class_%02X&SubClass_%02X",
                      out->cls, out->sub);
        _snprintf(out->compat[n++], PF_MAX_ID, "USB\\Class_%02X", out->cls);
    }
    out->n_compat = n;
    {
        int k;
        for (k = 0; k < n; k++) out->compat[k][PF_MAX_ID - 1] = '\0';
    }
}
