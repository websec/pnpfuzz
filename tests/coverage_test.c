#include "pnpfuzz.h"
#include <stdarg.h>
void log_console(pf_level l,const char*f,...){(void)l;(void)f;}
/* Exhaustive check on a multi-axis space: every index maps to a unique
 * combination, and the union covers the whole Cartesian product exactly once.
 * If this ever fails, a sweep silently misses part of its search space. */
int main(void){
    space_t sp; combo_t c; char err[256]; uint64_t i,total; char *seen;
    memset(&sp,0,sizeof(sp));
    axis_parse(&sp.vid,"046D,1199,056A",0xFFFF,"vid");
    axis_parse(&sp.pid,"0-13",0xFFFF,"pid");        /* 20 */
    axis_parse(&sp.rev,"100,200",0xFFFF,"rev");     /* 2  */
    axis_parse(&sp.mi,"0,1,2",0xFF,"mi");           /* 3  */
    axis_parse(&sp.cls,"03,08",0xFF,"cls");         /* 2  */
    axis_parse(&sp.sub,"01,06",0xFF,"sub");         /* 2  */
    axis_parse(&sp.prot,"01,50",0xFF,"prot");       /* 2  */
    if(space_finalise(&sp,err,sizeof(err))!=0){printf("finalise failed: %s\n",err);return 1;}
    total=space_total(&sp);
    printf("space total = %llu (expect 3*20*2*3*2*2*2 = %d)\n",(unsigned long long)total,3*20*2*3*2*2*2);
    if(total!=(uint64_t)(3*20*2*3*2*2*2)){printf("WRONG TOTAL\n");return 1;}
    seen=calloc((size_t)total,1);
    for(i=0;i<total;i++){
        int iv,ip,ir,im,ic,is,ipr; uint64_t k;
        space_at(&sp,i,&c);
        for(iv=0;iv<sp.vid.n&&sp.vid.v[iv]!=c.vid;iv++);
        for(ip=0;ip<sp.pid.n&&sp.pid.v[ip]!=c.pid;ip++);
        for(ir=0;ir<sp.rev.n&&sp.rev.v[ir]!=c.rev;ir++);
        for(im=0;im<sp.mi.n&&sp.mi.v[im]!=c.mi;im++);
        for(ic=0;ic<sp.cls.n&&sp.cls.v[ic]!=c.cls;ic++);
        for(is=0;is<sp.sub.n&&sp.sub.v[is]!=c.sub;is++);
        for(ipr=0;ipr<sp.prot.n&&sp.prot.v[ipr]!=c.prot;ipr++);
        if(iv==sp.vid.n||ip==sp.pid.n||ir==sp.rev.n||im==sp.mi.n||
           ic==sp.cls.n||is==sp.sub.n||ipr==sp.prot.n){printf("index %llu: value not on any axis\n",(unsigned long long)i);return 1;}
        k=((((((uint64_t)iv*sp.cls.n+ic)*sp.sub.n+is)*sp.prot.n+ipr)*sp.mi.n+im)*sp.rev.n+ir)*sp.pid.n+ip;
        if(k>=total){printf("index %llu -> k %llu out of range\n",(unsigned long long)i,(unsigned long long)k);return 1;}
        if(seen[k]){printf("DUPLICATE combination at index %llu\n",(unsigned long long)i);return 1;}
        seen[k]=1;
        /* PID is the fastest axis: consecutive indices in a batch must share
           every slower axis, which is what makes one node per batch valid. */
        if(i>0 && (i % sp.pid.n)!=0){
            combo_t prev; space_at(&sp,i-1,&prev);
            if(prev.vid!=c.vid||prev.rev!=c.rev||prev.mi!=c.mi||prev.cls!=c.cls||
               prev.sub!=c.sub||prev.prot!=c.prot){
                printf("index %llu: slow axis changed mid-batch\n",(unsigned long long)i);return 1;}
            if(prev.n_compat!=c.n_compat||strcmp(prev.compat[0],c.compat[0])!=0){
                printf("index %llu: compat ids changed mid-batch\n",(unsigned long long)i);return 1;}
        }
    }
    for(i=0;i<total;i++) if(!seen[i]){printf("MISSING combination %llu\n",(unsigned long long)i);return 1;}
    printf("all %llu combinations reached exactly once; batches never span a slow-axis change\n",
           (unsigned long long)total);
    free(seen); space_free(&sp); return 0;
}
