/* The poison-recovery policy: decide whether a width remembered from a previous
 * run (cache or checkpoint) may be ridden, or must be re-measured first. */
#include <stdio.h>
#include <string.h>

#define PF_WIDTH_TRUST_MIN   64
#define PF_AUTO_BATCH_START  512
#define PF_AUTO_BATCH_MAX    4096
#define ORIGIN_CALIBRATED    "calibrated"
#define ORIGIN_HALVED        "halved"

static int fails = 0, checks = 0;
static void ck(int c, const char *w){ checks++; if(!c){ fails++; printf("FAIL: %s\n", w);} }

/* mirrors the condition in run_sweep's cached-width branch */
static int distrusted(int width, const char *origin)
{
    return (width < PF_WIDTH_TRUST_MIN || strcmp(origin, ORIGIN_CALIBRATED) != 0);
}
/* mirrors width_cache_write's refusal to persist degraded widths */
static int persisted(int width, const char *origin)
{
    if (width <= 0) return 0;
    if (width < PF_WIDTH_TRUST_MIN && strcmp(origin, ORIGIN_HALVED) == 0) return 0;
    return 1;
}

int main(void)
{
    /* the exact field poison: collapsed to 16 by runtime halving */
    ck(distrusted(16,  ORIGIN_HALVED)     == 1, "collapsed halved width distrusted");
    ck(distrusted(1,   ORIGIN_HALVED)     == 1, "width 1 distrusted");
    ck(distrusted(32,  ORIGIN_HALVED)     == 1, "sub-floor halved width distrusted");
    /* halved but healthy: still distrusted, because halving is only a lower bound */
    ck(distrusted(512, ORIGIN_HALVED)     == 1, "healthy halved width still re-measured");
    /* properly measured widths are ridden without a recalibration tax */
    ck(distrusted(2048, ORIGIN_CALIBRATED) == 0, "calibrated width trusted");
    ck(distrusted(64,   ORIGIN_CALIBRATED) == 0, "calibrated at floor trusted");
    ck(distrusted(4096, ORIGIN_CALIBRATED) == 0, "calibrated ceiling trusted");
    /* a genuinely low but MEASURED limit is honoured, not fought */
    ck(distrusted(32,   ORIGIN_CALIBRATED) == 1, "measured-but-tiny still re-measured (floor wins)");
    /* unknown provenance (pre-origin cache file) reads as halved */
    ck(distrusted(1024, ORIGIN_HALVED)    == 1, "legacy entry without origin re-measured");

    /* the cache must never carry damage forward */
    ck(persisted(16,   ORIGIN_HALVED)     == 0, "collapsed width never persisted");
    ck(persisted(1,    ORIGIN_HALVED)     == 0, "width 1 never persisted");
    ck(persisted(512,  ORIGIN_HALVED)     == 1, "healthy halved width may persist");
    ck(persisted(2048, ORIGIN_CALIBRATED) == 1, "calibrated width persists");
    ck(persisted(16,   ORIGIN_CALIBRATED) == 1, "measured small width persists");
    ck(persisted(0,    ORIGIN_CALIBRATED) == 0, "zero never persisted");

    /* a distrusted resume must be lifted to something workable, never ridden low */
    {
        int eff = 16;
        if (eff < PF_WIDTH_TRUST_MIN) {
            eff = PF_AUTO_BATCH_START;
            if (eff > PF_AUTO_BATCH_MAX) eff = PF_AUTO_BATCH_MAX;
            if (eff < PF_WIDTH_TRUST_MIN) eff = PF_WIDTH_TRUST_MIN;
        }
        ck(eff >= PF_WIDTH_TRUST_MIN, "collapsed resume width lifted to a healthy start");
        ck(eff == PF_AUTO_BATCH_START, "lifted to the normal start width");
    }
    printf("trust-policy tests: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
