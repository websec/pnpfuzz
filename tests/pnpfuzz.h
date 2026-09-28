/* Shim: just enough of pnpfuzz.h to compile hwid.c on Linux for testing. */
#ifndef PNPFUZZ_H
#define PNPFUZZ_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define PF_MAX_ID           192
#define PF_MAX_COMPAT       8
#define PF_MAX_AXIS_VALUES  0x10000
#define _snprintf snprintf
#define strtok_s strtok_r

typedef enum { PF_DEBUG=0, PF_INFO, PF_GOOD, PF_WARN, PF_ERR } pf_level;
void log_console(pf_level lvl, const char *fmt, ...);

typedef struct { uint32_t *v; int n; int given; } axis_t;
typedef enum { PF_BUS_USB=0, PF_BUS_PCI } pf_bus;
typedef struct { axis_t vid,pid,rev,mi,cls,sub,prot,subsys; pf_bus bus; int with_plain; uint64_t total; } space_t;
const char *pf_bus_name(pf_bus b);
const char *pf_bus_enumerator(pf_bus b);
typedef struct {
    uint64_t index;
    unsigned vid,pid,rev,mi,cls,sub,prot,subsys;
    char ids[4][PF_MAX_ID]; int n_ids;
    char compat[PF_MAX_COMPAT][PF_MAX_ID]; int n_compat;
    char label[PF_MAX_ID];
} combo_t;

int  axis_parse(axis_t *a, const char *spec, uint32_t max, const char *name);
void axis_single(axis_t *a, uint32_t value);
void axis_free(axis_t *a);
int      space_finalise(space_t *sp, char *err, size_t errcap);
uint64_t space_total(const space_t *sp);
void     space_at(const space_t *sp, uint64_t index, combo_t *out);
void     space_free(space_t *sp);
#endif
