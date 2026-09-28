#include <string.h>
#include <stdio.h>
#include <stdint.h>
typedef struct { uint32_t *v; int n; int given; } axis_t;
typedef struct { axis_t vid, pid; } space_t;
static int ref_vid_in_space(const space_t *sp, const char *hwid)
{
    unsigned    vid = 0;
    const char *p;
    int         i, digits = 0;
    if (!hwid || !hwid[0]) return 0;
    p = strstr(hwid, "VID_");
    if (!p) p = strstr(hwid, "vid_");
    if (!p) return 0;
    p += 4;
    for (i = 0; i < 4 && p[i]; i++) {
        char c = p[i]; int d;
        if      (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        vid = (vid << 4) | (unsigned)d;
        digits++;
    }
    if (digits == 0) return 0;
    for (i = 0; i < sp->vid.n; i++)
        if (sp->vid.v[i] == vid) return 1;
    return 0;
}
static int fails = 0, checks = 0;
static void ck(int cond, const char *what){ checks++; if(!cond){ fails++; printf("FAIL: %s\n", what);} }
int main(void)
{
    uint32_t one[1]   = {0x1532};
    uint32_t multi[3] = {0x1EF9, 0x046D, 0x1234};
    space_t s1, s3;
    s1.vid.v = one;   s1.vid.n = 1;
    s3.vid.v = multi; s3.vid.n = 3;

    /* a foreign vendor id must never match a single-vendor sweep */
    ck(ref_vid_in_space(&s1, "USB\\VID_1234&PID_5678") == 0, "foreign vendor rejected (1234 vs 1532)");
    ck(ref_vid_in_space(&s1, "USB\\VID_1532&PID_005E") == 1, "same vendor accepted");
    ck(ref_vid_in_space(&s1, "USB\\VID_1532&PID_0F12") == 1, "same vendor accepted 2");
    /* case-insensitivity of the hex digits and token */
    ck(ref_vid_in_space(&s1, "USB\\VID_1532&PID_abcd") == 1, "lowercase pid ok");
    ck(ref_vid_in_space(&s1, "usb\\vid_1532&pid_005e") == 1, "lowercase token+hex ok");
    /* multi-VID membership */
    ck(ref_vid_in_space(&s3, "USB\\VID_046D&PID_C52B") == 1, "multi: middle vendor accepted");
    ck(ref_vid_in_space(&s3, "USB\\VID_1234&PID_5678") == 1, "multi: last vendor accepted");
    ck(ref_vid_in_space(&s3, "USB\\VID_1532&PID_005E") == 0, "multi: absent vendor rejected");
    /* malformed / edge inputs must not crash or false-accept */
    ck(ref_vid_in_space(&s1, "") == 0, "empty rejected");
    ck(ref_vid_in_space(&s1, NULL) == 0, "null rejected");
    ck(ref_vid_in_space(&s1, "USB\\PID_1532") == 0, "no VID_ token rejected");
    ck(ref_vid_in_space(&s1, "USB\\VID_") == 0, "truncated VID_ rejected");
    ck(ref_vid_in_space(&s1, "USB\\VID_ZZZZ&PID_0001") == 0, "non-hex rejected");
    ck(ref_vid_in_space(&s1, "USB\\VID_153&PID_0001") == 0, "short vid does not match 1532");
    /* compatible-ID style string has no VID_ at all */
    ck(ref_vid_in_space(&s1, "USB\\Class_03&SubClass_01") == 0, "compat id rejected");
    printf("ref_vid_in_space: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
