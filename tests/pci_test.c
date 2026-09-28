/* PCI identity synthesis: the shapes Windows' PCI enumerator reports. */
#include <stdio.h>
#include <string.h>
#include "pnpfuzz.h"

static int fails = 0, checks = 0;
static void ck(int c, const char *w){ checks++; if(!c){ fails++; printf("FAIL: %s\n", w);} }
static void eq(const char *got, const char *want, const char *w)
{
    checks++;
    if (strcmp(got, want) != 0) { fails++; printf("FAIL: %s\n  got  '%s'\n  want '%s'\n", w, got, want); }
}
void log_console(pf_level lvl, const char *fmt, ...) { (void)lvl; (void)fmt; }

static void mk(space_t *sp, pf_bus bus, const char *ven, const char *dev,
               const char *subsys, const char *rev, const char *cc_cls,
               const char *cc_sub, const char *cc_prot)
{
    char err[256];
    memset(sp, 0, sizeof(*sp));
    sp->bus = bus;
    axis_parse(&sp->vid, ven, 0xFFFF, "--ven");
    axis_parse(&sp->pid, dev, 0xFFFF, "--dev");
    if (subsys)  axis_parse(&sp->subsys, subsys, 0xFFFFFFFFu, "--subsys");
    if (rev)     axis_parse(&sp->rev, rev, 0xFF, "--rev");
    if (cc_cls)  axis_parse(&sp->cls, cc_cls, 0xFF, "--class");
    if (cc_sub)  axis_parse(&sp->sub, cc_sub, 0xFF, "--subclass");
    if (cc_prot) axis_parse(&sp->prot, cc_prot, 0xFF, "--protocol");
    space_finalise(sp, err, sizeof(err));
}

int main(void)
{
    space_t sp; combo_t c;

    /* plain VEN/DEV - the default sweep shape */
    mk(&sp, PF_BUS_PCI, "8086", "1234", NULL, NULL, NULL, NULL, NULL);
    space_at(&sp, 0, &c);
    ck(c.n_ids == 1, "plain PCI emits one hardware id");
    eq(c.ids[0], "PCI\\VEN_8086&DEV_1234", "plain PCI hardware id");
    eq(c.label,  "PCI\\VEN_8086&DEV_1234", "label is the primary id");
    ck(c.n_compat == 0, "no compat ids without a class code");
    space_free(&sp);

    /* SUBSYS + REV: most specific first, as the enumerator reports */
    mk(&sp, PF_BUS_PCI, "10DE", "2482", "38831043", "A1", NULL, NULL, NULL);
    space_at(&sp, 0, &c);
    eq(c.ids[0], "PCI\\VEN_10DE&DEV_2482&SUBSYS_38831043&REV_A1", "subsys+rev id");
    eq(c.ids[1], "PCI\\VEN_10DE&DEV_2482&SUBSYS_38831043", "subsys id");
    space_free(&sp);

    /* SUBSYS alone */
    mk(&sp, PF_BUS_PCI, "10DE", "2482", "38831043", NULL, NULL, NULL, NULL);
    space_at(&sp, 0, &c);
    eq(c.ids[0], "PCI\\VEN_10DE&DEV_2482&SUBSYS_38831043", "subsys-only id");
    space_free(&sp);

    /* REV alone uses PCI's 2-digit revision, not USB's 4-digit bcdDevice */
    mk(&sp, PF_BUS_PCI, "8086", "1234", NULL, "07", NULL, NULL, NULL);
    space_at(&sp, 0, &c);
    eq(c.ids[0], "PCI\\VEN_8086&DEV_1234&REV_07", "rev id is two hex digits");
    space_free(&sp);

    /* class code: class/subclass/prog-IF -> CC_ccsspp, vendor-scoped then bare */
    mk(&sp, PF_BUS_PCI, "8086", "1234", NULL, NULL, "01", "06", "01");
    space_at(&sp, 0, &c);
    eq(c.compat[0], "PCI\\VEN_8086&CC_010601", "vendor-scoped full class code");
    eq(c.compat[1], "PCI\\CC_010601",          "bare full class code");
    eq(c.compat[2], "PCI\\VEN_8086&CC_0106",   "vendor-scoped short class code");
    eq(c.compat[3], "PCI\\CC_0106",            "bare short class code");
    eq(c.compat[4], "PCI\\VEN_8086",           "vendor-only compat id");
    space_free(&sp);

    /* USB must be untouched by the PCI work */
    mk(&sp, PF_BUS_USB, "046D", "C52B", NULL, NULL, NULL, NULL, NULL);
    space_at(&sp, 0, &c);
    eq(c.ids[0], "USB\\VID_046D&PID_C52B", "USB shape unchanged");
    space_free(&sp);

    /* DEV is the fast axis on PCI too, so a batch stays within one VEN */
    mk(&sp, PF_BUS_PCI, "8086,10DE", "0000-000F", NULL, NULL, NULL, NULL, NULL);
    ck(space_total(&sp) == 32, "two vendors x sixteen devices");
    space_at(&sp, 0,  &c); ck(c.vid == 0x8086 && c.pid == 0x0000, "first combo");
    space_at(&sp, 15, &c); ck(c.vid == 0x8086 && c.pid == 0x000F, "last of vendor 1");
    space_at(&sp, 16, &c); ck(c.vid == 0x10DE && c.pid == 0x0000, "rolls to vendor 2");
    space_free(&sp);

    printf("PCI identity tests: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
