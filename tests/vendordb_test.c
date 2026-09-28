/* Verify the generated table: sorted, searchable, and the known VIDs resolve. */
#include <stdio.h>
#include <string.h>
typedef enum { PF_BUS_USB=0, PF_BUS_PCI } pf_bus;
#include "vendordb.h"
static int fails=0, checks=0;
static void ck(int c,const char*w){checks++;if(!c){fails++;printf("FAIL: %s\n",w);}}
static void eq(const char*g,const char*w,const char*n){checks++;if(strcmp(g,w)){fails++;printf("FAIL %s\n got '%s'\n want '%s'\n",n,g,w);}}

static int vendordb_lookup(pf_bus bus, unsigned vid, char names[][256], int cap)
{
    int lo=0, hi=PF_VENDORDB_COUNT-1, at=-1, i, n=0;
    if (bus != PF_BUS_USB || cap <= 0) return 0;
    while (lo<=hi){ int mid=lo+(hi-lo)/2;
        if(pf_vendordb_vid[mid]==(unsigned short)vid){at=mid;break;}
        if(pf_vendordb_vid[mid]<(unsigned short)vid) lo=mid+1; else hi=mid-1; }
    if(at<0) return 0;
    while(at>0 && pf_vendordb_vid[at-1]==(unsigned short)vid) at--;
    for(i=at;i<PF_VENDORDB_COUNT&&n<cap&&pf_vendordb_vid[i]==(unsigned short)vid;i++){
        strncpy(names[n],pf_vendordb_name[i],255); names[n][255]=0; n++; }
    return n;
}
int main(void)
{
    char nm[4][256]; int i, n;

    /* table invariants the binary search depends on */
    for (i = 1; i < PF_VENDORDB_COUNT; i++)
        if (pf_vendordb_vid[i] < pf_vendordb_vid[i-1]) { ck(0,"table sorted ascending"); break; }
    if (i == PF_VENDORDB_COUNT) ck(1,"table sorted ascending");
    for (i = 0; i < PF_VENDORDB_COUNT; i++)
        if (!pf_vendordb_name[i] || !pf_vendordb_name[i][0]) { ck(0,"no empty names"); break; }
    if (i == PF_VENDORDB_COUNT) ck(1,"no empty names");
    ck(PF_VENDORDB_COUNT > 13000, "table has the full vendor list");

    /* well-known ids resolve to their registered owner */
    n = vendordb_lookup(PF_BUS_USB, 0x1532, nm, 4);
    ck(n == 1, "1532 resolves");
    eq(nm[0], "Razer (Asia-Pacific) Pte Ltd.", "1532 is Razer");

    n = vendordb_lookup(PF_BUS_USB, 0x046D, nm, 4);
    eq(nm[0], "Logitech Inc.", "046D is Logitech");

    /* boundaries: first and last entries must be findable */
    n = vendordb_lookup(PF_BUS_USB, pf_vendordb_vid[0], nm, 4);
    ck(n >= 1, "first entry findable");
    n = vendordb_lookup(PF_BUS_USB, pf_vendordb_vid[PF_VENDORDB_COUNT-1], nm, 4);
    ck(n >= 1, "last entry findable");

    /* a VID with two registered entities returns both */
    n = vendordb_lookup(PF_BUS_USB, 0x17CC, nm, 4);
    ck(n == 2, "17CC returns both legal entities");

    /* PCI must never consult the USB registry */
    ck(vendordb_lookup(PF_BUS_PCI, 0x046D, nm, 4) == 0, "PCI bus never uses the USB table");
    ck(vendordb_lookup(PF_BUS_PCI, 0x1532, nm, 4) == 0, "PCI bus rejected for Razer id too");

    /* a gap in the registry must miss cleanly, not return a neighbour */
    {
        unsigned v, missing = 0xFFFF;
        for (v = 0xFFFF; v > 0; v--) {
            int found = 0;
            for (i = 0; i < PF_VENDORDB_COUNT; i++)
                if (pf_vendordb_vid[i] == (unsigned short)v) { found = 1; break; }
            if (!found) { missing = v; break; }
        }
        ck(vendordb_lookup(PF_BUS_USB, missing, nm, 4) == 0, "unregistered VID misses cleanly");
    }
    /* cap is respected */
    ck(vendordb_lookup(PF_BUS_USB, 0x17CC, nm, 1) == 1, "cap of 1 honoured on a duplicate");

    /* every entry must be retrievable by its own id (exhaustive) */
    {
        int bad = 0;
        for (i = 0; i < PF_VENDORDB_COUNT; i++)
            if (vendordb_lookup(PF_BUS_USB, pf_vendordb_vid[i], nm, 4) < 1) { bad++; break; }
        ck(bad == 0, "every one of 13756 entries is findable");
    }
    printf("vendordb table: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
