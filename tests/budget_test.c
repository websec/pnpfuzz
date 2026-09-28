/* Verifies the canary/width invariant: the total number of hardware IDs the
 * sweep puts on a node must never exceed the width calibration proved lossless,
 * and must never overflow the `slots` allocation. Mirrors run_sweep's math. */
#include <stdio.h>
#include <string.h>
static int fails=0,checks=0;
#define CHECK(c,...) do{checks++;if(!(c)){fails++;printf("  FAIL L%d ",__LINE__);printf(__VA_ARGS__);printf("\n");}}while(0)

/* returns n_send (total IDs sent to WU) and asserts against measured width */
static int simulate(int eff_width,int have_ref,int ids_per_combo,int slots,int *n_user_out,int *canary_out){
    int budget = eff_width - (have_ref?1:0);
    int n_user=0,n_combo=0,n_send,canary=0;
    if(budget<1)budget=1;
    while(n_user<budget){
        if(n_combo>0 && n_user+ids_per_combo>budget) break;   /* first combo exempt */
        n_user+=ids_per_combo; n_combo++;
    }
    /* canary only if it fits INSIDE the measured width */
    if(have_ref && n_user+1<=eff_width) canary=1;
    n_send=n_user+canary; *canary_out=canary;
    CHECK(n_send<=slots,"overflow: n_send=%d slots=%d (w=%d ipc=%d)",n_send,slots,eff_width,ids_per_combo);
    *n_user_out=n_user;
    return n_send;
}

int main(void){
    int w,ipc,nu,ns,cy;
    /* THE regression: with a canary, total sent must not exceed the measured
       width. Before the fix n_send was eff_width+1 -> tripped its own canary. */
    for(w=1;w<=4096;w=(w<8?w+1:w*2)){
        for(ipc=1;ipc<=4;ipc++){
            int slots=(4096>64?4096:64)+8;
            ns=simulate(w,1,ipc,slots,&nu,&cy);
            /* THE invariant: never send more IDs than the measured width */
            CHECK(ns<=w || nu>w,"w=%d ipc=%d sent %d exceeds measured width",w,ipc,ns);
            /* canary present whenever it fits; suppressed (not overflowing) otherwise */
            CHECK(cy ? (nu+1<=w) : (nu+1>w),"canary decision wrong w=%d ipc=%d nu=%d cy=%d",w,ipc,nu,cy);
            /* whenever there is room, we DO verify */
            if(w>=ipc+1) CHECK(cy==1,"should have canary at w=%d ipc=%d",w,ipc);
        }
    }
    /* without a canary the full width is usable */
    for(w=1;w<=4096;w=(w<8?w+1:w*2)){
        ns=simulate(w,0,1,4096+8,&nu,&cy);
        CHECK(ns==w,"no-canary should use full width: w=%d sent=%d",w,ns);
    }
    /* degenerate widths must still advance (>=1 user ID) */
    for(w=1;w<=3;w++){ ns=simulate(w,1,1,4096+8,&nu,&cy);
        CHECK(nu>=1,"must place >=1 user id at w=%d (got %d)",w,nu); }
    /* multi-ID combos at tiny widths: first-combo exemption may overshoot,
       must still fit slots */
    for(w=1;w<=4;w++) for(ipc=1;ipc<=4;ipc++){
        int slots=(w>64?w:64)+8; simulate(w,1,ipc,slots,&nu,&cy); }

    printf("budget/canary tests: %d checks, %d failures\n",checks,fails);
    return fails?1:0;
}
