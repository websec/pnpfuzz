/* Simulates run_sweep's index bookkeeping around the unverified-prefix resweep:
 * the sweep must cover every combination, re-run the unverified region exactly
 * once when calibration measures a narrower width, dedupe reported hits, and
 * always terminate. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define END              65536
#define START_WIDTH      512
#define FLOOR            16

static int fails = 0, checks = 0;
static void ck(int c, const char *w){ checks++; if(!c){ fails++; printf("FAIL: %s\n", w);} }

/* hit_at: index where the first WU hit is discovered.
 * true_width: the lossless width calibration will measure. */
static void sim(unsigned long hit_at, int true_width, int expect_resweep)
{
    unsigned char *covered = calloc(END, 1);
    unsigned long index = 0, unverified_from = 0;
    int have_ref = 0, unverified_maxw = 0, resweep_done = 0, eff = START_WIDTH;
    int resweeps = 0, iters = 0, reported = 0, dup_reports = 0;
    unsigned long i;

    while (index < END) {
        unsigned long first = index, k;
        int w = eff;
        if (++iters > 100000) break;                 /* runaway guard */
        if (!have_ref && w > unverified_maxw) unverified_maxw = w;

        for (k = 0; k < (unsigned long)w && index < END; k++) covered[index++]++;

        /* discover a hit once the batch spans hit_at */
        if (!have_ref && first <= hit_at && hit_at < index) {
            have_ref = 1;
            eff = true_width;
            if (reported++) dup_reports++;           /* first report of the hit */
            if (!resweep_done && unverified_maxw > eff && unverified_from < index) {
                resweep_done = 1; resweeps++;
                /* undo coverage claim for the region, then rewind */
                for (i = unverified_from; i < index; i++) covered[i]--;
                index = unverified_from;
            }
        }
    }

    ck(iters < 100000, "sweep terminates");
    ck(resweeps == expect_resweep, "resweep happened exactly when expected");
    ck(resweeps <= 1, "resweep never happens more than once");
    ck(dup_reports == 0, "hit reported once despite resweep");
    for (i = 0; i < END; i++) {
        if (covered[i] != 1) { ck(0, "every combination covered exactly once"); break; }
    }
    if (i == END) ck(1, "every combination covered exactly once");
    free(covered);
}

int main(void)
{
    /* calibration finds a NARROWER width than the opening phase -> resweep */
    sim(300,   64,  1);
    sim(5000,  128, 1);
    sim(60000, 16,  1);
    /* calibration finds an EQUAL or WIDER width -> no resweep needed */
    sim(300,   512, 0);
    sim(300,   4096,0);
    sim(40000, 2048,0);
    /* hit on the very first batch, narrow result */
    sim(0,     FLOOR, 1);
    /* hit on the very last batch */
    sim(END-1, 64,  1);
    printf("resweep sim: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
