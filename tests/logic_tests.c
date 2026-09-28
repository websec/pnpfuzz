#include "pnpfuzz.h"
#include <stdarg.h>
#include <strings.h>
#define _stricmp strcasecmp
#define _strnicmp strncasecmp
#include "id_related.inc"

static int fails = 0, checks = 0;
static int quiet = 1;
void log_console(pf_level lvl, const char *fmt, ...)
{ if (!quiet) { va_list ap; va_start(ap,fmt); vfprintf(stderr,fmt,ap); va_end(ap); fputc('\n',stderr);} }

#define CHECK(cond, ...) do { checks++; if(!(cond)){ fails++; \
    printf("  FAIL %s:%d  ", __func__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while(0)

static void t_parse(void)
{
    axis_t a; char *s;
    CHECK(axis_parse(&a,"046D",0xFFFF,"vid")==0 && a.n==1 && a.v[0]==0x046D, "046D"); axis_free(&a);
    CHECK(axis_parse(&a,"0x046D",0xFFFF,"vid")==0 && a.n==1 && a.v[0]==0x046D, "0x046D"); axis_free(&a);
    /* values are hex on purpose: '10' is 0x10, not decimal ten */
    CHECK(axis_parse(&a,"10",0xFFFF,"vid")==0 && a.v[0]==0x10, "10 -> 0x10"); axis_free(&a);
    /* 0x0000 must be reachable as a valid PID */
    CHECK(axis_parse(&a,"0",0xFFFF,"pid")==0 && a.n==1 && a.v[0]==0, "zero reachable"); axis_free(&a);
    CHECK(axis_parse(&a,"0-FFFF",0xFFFF,"pid")==0 && a.n==65536 && a.v[0]==0 && a.v[65535]==0xFFFF,
          "full range 0x0-0xFFFF"); axis_free(&a);
    CHECK(axis_parse(&a,"*",0xFFFF,"pid")==0 && a.n==65536, "star"); axis_free(&a);
    CHECK(axis_parse(&a,"1,2,A-C",0xFFFF,"pid")==0 && a.n==5 && a.v[2]==0xA && a.v[4]==0xC, "list+range"); axis_free(&a);
    CHECK(axis_parse(&a,"C-A",0xFFFF,"pid")==0 && a.n==3 && a.v[0]==0xA, "reversed range swaps"); axis_free(&a);
    CHECK(axis_parse(&a," 046D ",0xFFFF,"vid")==0 && a.v[0]==0x046D, "surrounding spaces"); axis_free(&a);
    /* rejections */
    CHECK(axis_parse(&a,"GHIJ",0xFFFF,"vid")!=0, "non-hex rejected");
    CHECK(axis_parse(&a,"10000",0xFFFF,"vid")!=0, "over max rejected");
    CHECK(axis_parse(&a,"",0xFFFF,"vid")!=0, "empty rejected");
    CHECK(axis_parse(&a,"1FF",0xFF,"class")!=0, "over byte max rejected");
    CHECK(axis_parse(&a,"1-",0xFFFF,"pid")!=0, "half range rejected");
    CHECK(axis_parse(&a,"0x",0xFFFF,"pid")!=0, "bare 0x rejected");
    /* repeating a flag must reuse the axis, not leak the previous buffer */
    CHECK(axis_parse(&a,"1-100",0xFFFF,"pid")==0, "first parse");
    CHECK(axis_parse(&a,"2",0xFFFF,"pid")==0 && a.n==1 && a.v[0]==2, "reparse replaces");
    axis_free(&a);
    (void)s;
}

static void mkspace(space_t *sp, const char *vid, const char *pid,
                    const char *rev, const char *cls)
{
    char err[256];
    memset(sp,0,sizeof(*sp));
    axis_parse(&sp->vid, vid, 0xFFFF, "vid");
    axis_parse(&sp->pid, pid, 0xFFFF, "pid");
    if (rev) axis_parse(&sp->rev, rev, 0xFFFF, "rev");
    if (cls) axis_parse(&sp->cls, cls, 0xFF, "class");
    CHECK(space_finalise(sp, err, sizeof(err))==0, "finalise: %s", err);
}

static void t_odometer(void)
{
    space_t sp; combo_t c; uint64_t i;
    mkspace(&sp,"046D,1199","0-2",NULL,NULL);
    CHECK(space_total(&sp)==6, "total=6 got %llu",(unsigned long long)space_total(&sp));

    /* PID must be the fastest axis: a batch of consecutive indices has to be
       consecutive PIDs on one VID, or batching breaks. */
    space_at(&sp,0,&c); CHECK(c.vid==0x046D&&c.pid==0,"i0");
    space_at(&sp,1,&c); CHECK(c.vid==0x046D&&c.pid==1,"i1 pid fastest");
    space_at(&sp,2,&c); CHECK(c.vid==0x046D&&c.pid==2,"i2");
    space_at(&sp,3,&c); CHECK(c.vid==0x1199&&c.pid==0,"i3 vid rolls");
    space_at(&sp,5,&c); CHECK(c.vid==0x1199&&c.pid==2,"i5 last");

    /* every index must map to a distinct combination -> no lost coverage */
    {
        int seen[2][3]; int a,b; memset(seen,0,sizeof(seen));
        for (i=0;i<6;i++){ space_at(&sp,i,&c);
            a = (c.vid==0x046D)?0:1; b=(int)c.pid; seen[a][b]++; }
        for(a=0;a<2;a++) for(b=0;b<3;b++) CHECK(seen[a][b]==1,"coverage %d,%d=%d",a,b,seen[a][b]);
    }
    CHECK(strcmp(sp.pid.v?"":"","")==0,"noop");
    space_free(&sp);

    /* --start/--resume seek must be exact, not just sequential */
    mkspace(&sp,"046D","0-FFFF",NULL,NULL);
    CHECK(space_total(&sp)==65536,"65536");
    space_at(&sp,40000,&c);
    CHECK(c.pid==40000,"seek 40000 -> pid %u",c.pid);
    CHECK(strcmp(c.label,"USB\\VID_046D&PID_9C40")==0,"label %s",c.label);
    space_free(&sp);
}

static void t_ids(void)
{
    space_t sp; combo_t c;
    /* default: bare VID/PID only */
    mkspace(&sp,"046D","C077",NULL,NULL);
    space_at(&sp,0,&c);
    CHECK(c.n_ids==1 && strcmp(c.ids[0],"USB\\VID_046D&PID_C077")==0,"plain: %s",c.ids[0]);
    CHECK(c.n_compat==0,"no compat by default");
    space_free(&sp);

    /* with --rev: most specific first, like a real hub reports */
    mkspace(&sp,"046D","C077","0100",NULL);
    space_at(&sp,0,&c);
    CHECK(c.n_ids==1 && strcmp(c.ids[0],"USB\\VID_046D&PID_C077&REV_0100")==0,"rev: %s",c.ids[0]);
    sp.with_plain=1; space_at(&sp,0,&c);
    CHECK(c.n_ids==2 && strcmp(c.ids[1],"USB\\VID_046D&PID_C077")==0,"with-plain: %s",c.ids[1]);
    space_free(&sp);

    /* class -> compatible IDs, most specific first */
    memset(&sp,0,sizeof(sp));
    axis_parse(&sp.vid,"046D",0xFFFF,"vid"); axis_parse(&sp.pid,"C077",0xFFFF,"pid");
    axis_parse(&sp.cls,"03",0xFF,"cls");
    axis_parse(&sp.sub,"01",0xFF,"sub"); axis_parse(&sp.prot,"01",0xFF,"prot");
    { char e[256]; CHECK(space_finalise(&sp,e,sizeof(e))==0,"finalise: %s",e); }
    space_at(&sp,0,&c);
    CHECK(c.n_compat==3,"3 compat ids, got %d",c.n_compat);
    CHECK(strcmp(c.compat[0],"USB\\Class_03&SubClass_01&Prot_01")==0,"c0 %s",c.compat[0]);
    CHECK(strcmp(c.compat[2],"USB\\Class_03")==0,"c2 %s",c.compat[2]);
    space_free(&sp);
}

static void t_deps(void)
{
    space_t sp; char err[256];
    memset(&sp,0,sizeof(sp));
    axis_parse(&sp.vid,"046D",0xFFFF,"vid"); axis_parse(&sp.pid,"1",0xFFFF,"pid");
    axis_parse(&sp.sub,"01",0xFF,"sub");
    CHECK(space_finalise(&sp,err,sizeof(err))!=0,"--subclass without --class must fail");
    space_free(&sp);

    memset(&sp,0,sizeof(sp));
    axis_parse(&sp.pid,"1",0xFFFF,"pid");
    CHECK(space_finalise(&sp,err,sizeof(err))!=0,"--pid without --vid must fail");
    space_free(&sp);

    /* overflow guard */
    memset(&sp,0,sizeof(sp));
    axis_parse(&sp.vid,"*",0xFFFF,"vid"); axis_parse(&sp.pid,"*",0xFFFF,"pid");
    axis_parse(&sp.rev,"*",0xFFFF,"rev"); axis_parse(&sp.mi,"*",0xFF,"mi");
    axis_parse(&sp.cls,"*",0xFF,"cls");   axis_parse(&sp.sub,"*",0xFF,"sub");
    axis_parse(&sp.prot,"*",0xFF,"prot");
    CHECK(space_finalise(&sp,err,sizeof(err))!=0,"2^80 space must be rejected, not wrapped");
    space_free(&sp);
}

static void t_id_related(void)
{
    CHECK(id_related("USB\\VID_046D&PID_0001","USB\\VID_046D&PID_0001"),"exact");
    CHECK(id_related("usb\\vid_046d&pid_0001","USB\\VID_046D&PID_0001"),"case insensitive");
    CHECK(id_related("USB\\VID_046D&PID_0001","USB\\VID_046D&PID_0001&REV_0100"),"prefix at boundary");
    CHECK(id_related("USB\\VID_046D&PID_0001&REV_0100","USB\\VID_046D&PID_0001"),"reversed order");
    /* the substring test the naive version would get wrong */
    CHECK(!id_related("USB\\VID_046D&PID_0001","USB\\VID_046D&PID_00012"),"NOT a mid-component prefix");
    CHECK(!id_related("USB\\VID_046D&PID_0001","USB\\VID_046D&PID_0002"),"different pid");
    CHECK(!id_related("","USB\\VID_046D&PID_0001"),"empty");
    CHECK(!id_related("USB\\VID_046D&PID_0001",""),"empty rhs");
}

int main(void)
{
    printf("pnpfuzz logic tests\n");
    t_parse(); t_odometer(); t_ids(); t_deps(); t_id_related();
    printf("%d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
