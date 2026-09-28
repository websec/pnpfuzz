/* Parsers for the vendor-recon replies, exercised against the real response
 * shapes captured from devicehunt.com and partner.microsoft.com. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>

#define PF_MAX_ID 192
#define _snprintf snprintf
static int fails = 0, checks = 0;
static void ck(int c, const char *w){ checks++; if(!c){ fails++; printf("FAIL: %s\n", w);} }
static void eq(const char *got, const char *want, const char *w)
{
    checks++;
    if (strcmp(got, want)) { fails++; printf("FAIL: %s\n  got  '%s'\n  want '%s'\n", w, got, want); }
}

/* ---- copies of the parser internals under test ---- */
static void vtrim(char *s)
{
    size_t n; char *p = s;
    while (*p==' '||*p=='\t'||*p=='\r'||*p=='\n') p++;
    if (p!=s) memmove(s,p,strlen(p)+1);
    n=strlen(s);
    while (n && (s[n-1]==' '||s[n-1]=='\t'||s[n-1]=='\r'||s[n-1]=='\n')) s[--n]='\0';
}
static void vunescape_html(char *s)
{
    char *r=s,*w=s;
    while(*r){
        if(*r=='&'){
            if(!strncmp(r,"&amp;",5)){*w++='&';r+=5;continue;}
            if(!strncmp(r,"&quot;",6)){*w++='"';r+=6;continue;}
            if(!strncmp(r,"&#39;",5)){*w++='\'';r+=5;continue;}
            if(!strncmp(r,"&apos;",6)){*w++='\'';r+=6;continue;}
            if(!strncmp(r,"&lt;",4)){*w++='<';r+=4;continue;}
            if(!strncmp(r,"&gt;",4)){*w++='>';r+=4;continue;}
            if(!strncmp(r,"&mdash;",7)){*w++='\x01';r+=7;continue;}
            if(!strncmp(r,"&ndash;",7)){*w++='\x01';r+=7;continue;}
        }
        *w++=*r++;
    }
    *w='\0';
}
static int parse_devicehunt_title(const char *html, char *out, size_t cap)
{
    const char *a,*b; char title[512]; size_t n; char *sep;
    a=strstr(html,"<title>"); if(!a) return -1; a+=7;
    b=strstr(a,"</title>"); if(!b) return -1;
    n=(size_t)(b-a); if(n>=sizeof(title)) n=sizeof(title)-1;
    memcpy(title,a,n); title[n]='\0';
    vunescape_html(title);
    { char *p=title;
      while((p=strstr(p,"\xE2\x80"))!=NULL){
        if((unsigned char)p[2]==0x94||(unsigned char)p[2]==0x93){
            p[0]='\x01'; memmove(p+1,p+3,strlen(p+3)+1); p+=1;
        } else p+=2;
      } }
    sep=strchr(title,'\x01');
    if(sep) *sep='\0';
    else { sep=strstr(title," - "); if(sep) *sep='\0'; }
    vtrim(title);
    if(!title[0]) return -1;
    if(!strncmp(title,"404",3)) return -1;
    strncpy(out,title,cap-1); out[cap-1]='\0';
    return 0;
}
static const char *json_str(const char *from,const char *end,const char *key,char *out,size_t cap)
{
    char pat[64]; const char *p; size_t w=0;
    _snprintf(pat,sizeof(pat),"\"%s\":\"",key); pat[sizeof(pat)-1]='\0';
    p=strstr(from,pat);
    if(!p||(end&&p>=end)){ if(cap) out[0]='\0'; return NULL; }
    p+=strlen(pat);
    while(*p&&*p!='"'){
        if(*p=='\\'&&p[1]){ p++; if(w+1<cap){ char c=*p; out[w++]=(c=='n')?'\n':(c=='t')?'\t':c; } p++; continue; }
        if(w+1<cap) out[w++]=*p;
        p++;
    }
    if(cap) out[w]='\0';
    return (*p=='"')?p+1:p;
}
static int parse_accounts(const char *json, char ids[][32], char pubs[][256], int cap)
{
    const char *p = json; int n = 0;
    for (;;) {
        char id[32], pub[256]; const char *after;
        after = json_str(p, NULL, "AccountId", id, sizeof(id));
        if (!after || !id[0]) break;
        json_str(after, NULL, "PublisherName", pub, sizeof(pub));
        if (n >= cap) break;
        strncpy(ids[n], id, 31); ids[n][31] = 0;
        strncpy(pubs[n], pub, 255); pubs[n][255] = 0;
        n++;
        p = after;
    }
    return n;
}
static int score_account(const char *dh, const char *pub)
{
    size_t ld, lp;
    if (!dh || !dh[0] || !pub || !pub[0]) return 0;
    if (!strcasecmp(dh, pub)) return 1000;
    ld = strlen(dh); lp = strlen(pub);
    if (lp >= ld && !strncasecmp(pub, dh, ld)) return 800 - (int)(lp-ld > 200 ? 200 : lp-ld);
    if (ld >= lp && !strncasecmp(dh, pub, lp)) return 700 - (int)(ld-lp > 200 ? 200 : ld-lp);
    { char a[256], b[256]; size_t i;
      strncpy(a, dh, 255); a[255]=0; strncpy(b, pub, 255); b[255]=0;
      for (i=0;a[i];i++) a[i]=(char)tolower((unsigned char)a[i]);
      for (i=0;b[i];i++) b[i]=(char)tolower((unsigned char)b[i]);
      if (strstr(b,a)||strstr(a,b)) return 500; }
    return 100;
}
static int best_of(const char *dh, char pubs[][256], int n)
{
    int i, best = 0;
    for (i = 1; i < n; i++)
        if (score_account(dh, pubs[i]) > score_account(dh, pubs[best])) best = i;
    return best;
}
static void url_encode(const char *in,char *out,size_t cap)
{
    static const char *hex="0123456789ABCDEF"; size_t w=0;
    for(;*in&&w+4<cap;in++){
        unsigned char c=(unsigned char)*in;
        if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'||c=='~') out[w++]=(char)c;
        else if(c==' ') out[w++]='+';
        else { out[w++]='%'; out[w++]=hex[(c>>4)&0xF]; out[w++]=hex[c&0xF]; }
    }
    out[w<cap?w:cap-1]='\0';
}
static int shorten_name(char *s)
{
    char *sp=strrchr(s,' ');
    if(!sp) return 0;
    *sp='\0'; vtrim(s);
    return (strlen(s)>=3);
}
/* count distinct submissions in a GetCplData reply */
static int count_records(const char *json, char names[][256], int cap)
{
    const char *p=json; int n=0;
    for(;;){
        const char *rec,*end; char sub[40],name[256];
        rec=strstr(p,"\"Document\":{"); if(!rec) break; rec+=12;
        end=strstr(rec,"\"Document\":{");
        json_str(rec,end,"SubmissionId",sub,sizeof(sub));
        json_str(rec,end,"ProductName",name,sizeof(name));
        if(n<cap) strncpy(names[n],name,255);
        n++;
        if(!end) break;
        p=end;
    }
    return n;
}

int main(void)
{
    char out[256];

    /* --- DeviceHunt titles (em dash is the real separator) --- */
    ck(parse_devicehunt_title(
        "<html><head><title>Aladdin Knowledge Systems \xE2\x80\x94 PCI Vendor 416C \xE2\x80\x94 DeviceHunt</title>",
        out, sizeof(out)) == 0, "valid title parses");
    eq(out, "Aladdin Knowledge Systems", "first field of the title");

    ck(parse_devicehunt_title("<title>404 \xE2\x80\x94 Page Not Found \xE2\x80\x94 DeviceHunt</title>",
        out, sizeof(out)) == -1, "404 title rejected");

    ck(parse_devicehunt_title("<title>Advanced Micro Devices, Inc. \xE2\x80\x94 PCI Vendor 1022 \xE2\x80\x94 DeviceHunt</title>",
        out, sizeof(out)) == 0, "name with commas/periods");
    eq(out, "Advanced Micro Devices, Inc.", "punctuation preserved");

    ck(parse_devicehunt_title("<title>Smith &amp; Nephew \xE2\x80\x94 PCI Vendor 1234 \xE2\x80\x94 DeviceHunt</title>",
        out, sizeof(out)) == 0, "entity in name");
    eq(out, "Smith & Nephew", "&amp; decoded");

    ck(parse_devicehunt_title("<title>Acme Corp &mdash; PCI Vendor 1234 &mdash; DeviceHunt</title>",
        out, sizeof(out)) == 0, "entity-encoded dash separator");
    eq(out, "Acme Corp", "entity dash splits");

    ck(parse_devicehunt_title("<html>no title here</html>", out, sizeof(out)) == -1, "missing title");
    ck(parse_devicehunt_title("<title></title>", out, sizeof(out)) == -1, "empty title");

    /* --- accounts endpoint --- */
    {
        const char *acc = "[{\"AccountId\":\"52944960\",\"PublisherName\":\"Aladdin Knowledge Systems LTD.\","
                          "\"PublisherSearchFriendlyName\":\"52944960 - Aladdin Knowledge Systems LTD.\"}]";
        char id[32], pub[256];
        json_str(acc, NULL, "AccountId", id, sizeof(id));
        json_str(acc, NULL, "PublisherName", pub, sizeof(pub));
        eq(id, "52944960", "account id");
        eq(pub, "Aladdin Knowledge Systems LTD.", "publisher name");
    }
    {
        const char *acc = "[{\"AccountId\":\"10000042\",\"PublisherName\":\"Contoso B.V.\","
                          "\"PublisherSearchFriendlyName\":\"10000042 - Contoso B.V.\"}]";
        char id[32], pub[256];
        json_str(acc, NULL, "AccountId", id, sizeof(id));
        json_str(acc, NULL, "PublisherName", pub, sizeof(pub));
        eq(id, "10000042", "account id");
        eq(pub, "Contoso B.V.", "publisher");
    }
    { char empty[32]; json_str("[]", NULL, "AccountId", empty, sizeof(empty));
      eq(empty, "", "empty account list yields empty id"); }

    /* --- GetCplData: a sample multi-record CPL reply --- */
    {
        const char *cpl =
        "{\"ResultCount\":7,\"Skip\":0,\"PageResults\":["
        "{\"Score\":0,\"Highlights\":{},\"Document\":{\"SubmissionId\":\"1000000000000000001\",\"ProductName\":\"Sample Device A\",\"SelectedOsCodes\":\"Windows 11 Client, version 22H2 x64 (Ni)\\nWindows Server 2008\",\"IsDeclarativeDriver\":true,\"IsUniversalDriver\":true,\"PublisherId\":10000042}},"
        "{\"Score\":0,\"Highlights\":{},\"Document\":{\"SubmissionId\":\"1000000000000000002\",\"ProductName\":\"Sample Device B\",\"SelectedOsCodes\":\"Windows 11 Client, version 22H2 x64 (Ni)\",\"IsDeclarativeDriver\":true,\"IsUniversalDriver\":true,\"PublisherId\":10000042}},"
        "{\"Score\":0,\"Highlights\":{},\"Document\":{\"SubmissionId\":\"1000000000000000003\",\"ProductName\":\"SampleDeviceC [24H2]\",\"SelectedOsCodes\":\"Windows 11 Client, version 24H2 x64 (Ge)\",\"IsDeclarativeDriver\":true,\"IsUniversalDriver\":true,\"PublisherId\":10000042}},"
        "{\"Score\":0,\"Highlights\":{},\"Document\":{\"SubmissionId\":\"1000000000000000004\",\"ProductName\":\"Sample Device D [25H2]\",\"SelectedOsCodes\":\"Windows 11 Client, version 25H2 x64 (Ge)\",\"IsDeclarativeDriver\":true,\"IsUniversalDriver\":true,\"PublisherId\":10000042}}"
        "],\"NextPage\":false,\"SearchAttributes\":null}";
        char names[8][256];
        int n = count_records(cpl, names, 8);
        ck(n == 4, "all four records walked");
        eq(names[0], "Sample Device A", "record 1 name");
        eq(names[1], "Sample Device B", "record 2 name");
        eq(names[2], "SampleDeviceC [24H2]", "record 3 name");
        eq(names[3], "Sample Device D [25H2]", "record 4 name");
    }
    /* empty result set must yield nothing, not a phantom record */
    {
        char names[4][256];
        ck(count_records("{\"ResultCount\":0,\"Skip\":0,\"PageResults\":[],\"NextPage\":false}", names, 4) == 0,
           "empty PageResults yields no records");
    }

    /* --- url encoding as the site's own UI does it --- */
    url_encode("Aladdin Knowledge Systems", out, sizeof(out));
    eq(out, "Aladdin+Knowledge+Systems", "spaces become +");
    url_encode("Contoso B.V.", out, sizeof(out));
    eq(out, "Contoso+B.V.", "periods are safe");
    url_encode("Smith & Nephew", out, sizeof(out));
    eq(out, "Smith+%26+Nephew", "ampersand percent-encoded");

    /* --- progressive shortening finds accounts whose suffix differs --- */
    {
        char nm[256];
        strcpy(nm, "Aladdin Knowledge Systems");
        ck(shorten_name(nm) == 1, "shorten once");   eq(nm, "Aladdin Knowledge", "-> two words");
        ck(shorten_name(nm) == 1, "shorten twice");  eq(nm, "Aladdin", "-> one word");
        ck(shorten_name(nm) == 0, "cannot shorten a single word");
    }
    {
        char nm[256];
        strcpy(nm, "AMD Inc");
        ck(shorten_name(nm) == 1, "two-word name shortens");
        eq(nm, "AMD", "-> AMD");
    }

    /* --- multiple publishers for one name (the Raytheon case) --- */
    {
        const char *multi =
        "[{\"AccountId\":\"30896210\",\"PublisherName\":\"Raytheon Company\",\"PublisherSearchFriendlyName\":\"30896210 - Raytheon Company\"},"
        "{\"AccountId\":\"76778810\",\"PublisherName\":\"Raytheon Anschuetz GmbH\",\"PublisherSearchFriendlyName\":\"76778810 - Raytheon Anschuetz GmbH\"},"
        "{\"AccountId\":\"78476470\",\"PublisherName\":\"Raytheon Technologies\",\"PublisherSearchFriendlyName\":\"78476470 - Raytheon Technologies\"}]";
        char ids[8][32], pubs[8][256];
        int n = parse_accounts(multi, ids, pubs, 8);
        ck(n == 3, "all three Raytheon accounts parsed");
        eq(ids[0], "30896210", "acct 1 id");   eq(pubs[0], "Raytheon Company", "acct 1 name");
        eq(ids[1], "76778810", "acct 2 id");   eq(pubs[1], "Raytheon Anschuetz GmbH", "acct 2 name");
        eq(ids[2], "78476470", "acct 3 id");   eq(pubs[2], "Raytheon Technologies", "acct 3 name");

        /* the closest name match must win the default, not simply the first */
        ck(best_of("Raytheon Company", pubs, n) == 0, "exact match picks Raytheon Company");
        ck(best_of("Raytheon Technologies", pubs, n) == 2, "exact match picks Technologies");
        ck(best_of("Raytheon Anschuetz", pubs, n) == 1, "prefix match picks Anschuetz");
    }
    /* a single-element array still parses as one account */
    {
        char ids[4][32], pubs[4][256];
        ck(parse_accounts("[{\"AccountId\":\"10000042\",\"PublisherName\":\"Contoso B.V.\"}]",
                          ids, pubs, 4) == 1, "single account");
        eq(pubs[0], "Contoso B.V.", "single account name");
    }
    /* an empty array must yield zero, never a phantom */
    {
        char ids[4][32], pubs[4][256];
        ck(parse_accounts("[]", ids, pubs, 4) == 0, "empty account array");
    }
    /* overflow must clamp, not scribble */
    {
        char ids[2][32], pubs[2][256];
        const char *five =
        "[{\"AccountId\":\"1\",\"PublisherName\":\"A\"},{\"AccountId\":\"2\",\"PublisherName\":\"B\"},"
        "{\"AccountId\":\"3\",\"PublisherName\":\"C\"},{\"AccountId\":\"4\",\"PublisherName\":\"D\"}]";
        ck(parse_accounts(five, ids, pubs, 2) == 2, "clamped to capacity");
        eq(ids[1], "2", "second kept intact when clamped");
    }
    /* scoring ranks the way the selector depends on */
    {
        ck(score_account("Aladdin Knowledge Systems", "Aladdin Knowledge Systems") == 1000,
           "exact name scores highest");
        ck(score_account("Aladdin Knowledge Systems", "Aladdin Knowledge Systems LTD.") >
           score_account("Aladdin Knowledge Systems", "Aladdin Agency"),
           "suffix extension beats unrelated sibling");
        ck(score_account("Raytheon", "Raytheon Company") >
           score_account("Raytheon", "Something Else"), "prefix beats no relation");
        ck(score_account("", "Anything") == 0, "empty name scores zero");
    }

    printf("vendor recon parsers: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
