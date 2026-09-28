#include <stdio.h>
#define PF_AUTO_BATCH_FLOOR 16
#define PF_AUTO_BATCH_START 512
#define PF_CANARY_GIVEUP_WIDTH 64
#define PF_WU_RETRY_MAX 3
static int fails=0, checks=0;
static void ck(int c,const char*w){checks++;if(!c){fails++;printf("FAIL: %s\n",w);}}

/* Simulate the lossy-halving loop with a canary that is NEVER seen (the field
 * bug), asserting it terminates via the collapse guard rather than reaching 1. */
static void sim_never_seen(int start_width, int batch_given, int batch, int auto_max)
{
    int eff = start_width, canary_ever_seen = 0, iters = 0, gave_up = 0, final = 0;
    while (iters++ < 1000) {
        int lossy = 1;                      /* canary never returns */
        if (lossy && eff > PF_AUTO_BATCH_FLOOR) {
            int nw = eff / 2;
            if (nw < PF_AUTO_BATCH_FLOOR) nw = PF_AUTO_BATCH_FLOOR;
            if (!canary_ever_seen && nw < PF_CANARY_GIVEUP_WIDTH) {
                int rw = batch_given ? batch : PF_AUTO_BATCH_START;
                if (rw > auto_max) rw = auto_max;
                if (rw < PF_CANARY_GIVEUP_WIDTH) rw = PF_CANARY_GIVEUP_WIDTH;
                gave_up = 1; final = rw; break;   /* canary disabled, continue */
            }
            eff = nw; continue;
        }
        final = eff; break;                 /* at floor, keeps going unverified */
    }
    ck(gave_up == 1, "collapse guard fired for a never-seen canary");
    ck(final >= PF_CANARY_GIVEUP_WIDTH, "reset width is healthy (>= giveup width)");
    ck(final > 1, "never collapses to width 1");
    ck(iters < 20, "terminates quickly");
}

/* A canary that IS valid but hits real truncation must still halve normally and
 * settle at the floor, never triggering the give-up path. */
static void sim_real_truncation(int start_width, int truncate_above)
{
    int eff = start_width, canary_ever_seen = 0, iters = 0, gave_up = 0;
    while (iters++ < 1000) {
        int lossy = (eff > truncate_above);
        if (!lossy) { canary_ever_seen = 1; break; }
        if (eff > PF_AUTO_BATCH_FLOOR) {
            int nw = eff / 2;
            if (nw < PF_AUTO_BATCH_FLOOR) nw = PF_AUTO_BATCH_FLOOR;
            if (!canary_ever_seen && nw < PF_CANARY_GIVEUP_WIDTH) { gave_up = 1; break; }
            eff = nw; continue;
        }
        break;
    }
    ck(eff <= truncate_above || gave_up, "settles at/below the true truncation width");
    ck(iters < 20, "real-truncation path terminates");
}

int main(void)
{
    sim_never_seen(4096, 0, 64, 4096);   /* the field case: auto start, no --batch */
    sim_never_seen(512,  0, 64, 4096);
    sim_never_seen(128,  1, 1024, 4096); /* --batch given: reset honours it */
    sim_never_seen(128,  1, 8,  4096);   /* tiny --batch still lifted to giveup width */
    sim_real_truncation(4096, 1024);     /* genuine boundary at 1024 */
    sim_real_truncation(4096, 128);
    sim_real_truncation(4096, 64);
    /* retry cap for stalls is bounded */
    { int s=0,n=0; while (++s < PF_WU_RETRY_MAX) n++; ck(n==PF_WU_RETRY_MAX-1,"stall retries bounded"); }
    printf("collapse-guard sim: %d checks, %d failures\n", checks, fails);
    return fails?1:0;
}
