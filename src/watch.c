/*
 * watch.c - PnP notification observer
 *
 * Registers for device-instance notifications so the run log records what the
 * PnP manager actually did and when, rather than inferring it from polling
 * pnputil. In install mode this is the evidence trail
 * that shows the Device Install Service reacting to CM_Setup_DevNode.
 */

#include "pnpfuzz.h"
#include <cfgmgr32.h>

#define WATCH_CAP 4096

static HCMNOTIFICATION   g_handle;
static CRITICAL_SECTION  g_lock;
static int               g_lock_init;
static pnpev_t           g_ring[WATCH_CAP];
static int               g_head;      /* next write slot            */
static int               g_taken;     /* next unread slot           */
static int               g_dropped;
static DWORD             g_t0;
static int               g_active;
static int               g_log_all;

static const char *action_name(CM_NOTIFY_ACTION a)
{
    switch (a) {
    case CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL:   return "DEVICE_INTERFACE_ARRIVAL";
    case CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL:   return "DEVICE_INTERFACE_REMOVAL";
    case CM_NOTIFY_ACTION_DEVICEQUERYREMOVE:        return "DEVICE_QUERY_REMOVE";
    case CM_NOTIFY_ACTION_DEVICEQUERYREMOVEFAILED:  return "DEVICE_QUERY_REMOVE_FAILED";
    case CM_NOTIFY_ACTION_DEVICEREMOVEPENDING:      return "DEVICE_REMOVE_PENDING";
    case CM_NOTIFY_ACTION_DEVICEREMOVECOMPLETE:     return "DEVICE_REMOVE_COMPLETE";
    case CM_NOTIFY_ACTION_DEVICECUSTOMEVENT:        return "DEVICE_CUSTOM_EVENT";
    case CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED: return "DEVICE_INSTANCE_ENUMERATED";
    case CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED:    return "DEVICE_INSTANCE_STARTED";
    case CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED:    return "DEVICE_INSTANCE_REMOVED";
    default:                                        return "UNKNOWN";
    }
}

static DWORD CALLBACK on_pnp(HCMNOTIFICATION h, PVOID ctx, CM_NOTIFY_ACTION action,
                             PCM_NOTIFY_EVENT_DATA data, DWORD size)
{
    pnpev_t ev;
    int ours;

    (void)h; (void)ctx; (void)size;
    if (!g_active) return ERROR_SUCCESS;

    memset(&ev, 0, sizeof(ev));
    strncpy(ev.type, action_name(action), sizeof(ev.type) - 1);
    ev.t_ms = GetTickCount() - g_t0;

    if (data && data->FilterType == CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE) {
        WideCharToMultiByte(CP_UTF8, 0, data->u.DeviceInstance.InstanceId, -1,
                            ev.instance, sizeof(ev.instance), NULL, NULL);
    } else if (data && data->FilterType == CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE) {
        WideCharToMultiByte(CP_UTF8, 0, data->u.DeviceInterface.SymbolicLink, -1,
                            ev.instance, sizeof(ev.instance), NULL, NULL);
    }
    ev.instance[sizeof(ev.instance) - 1] = '\0';

    ours = (_strnicmp(ev.instance, PF_NODE_PREFIX_A, strlen(PF_NODE_PREFIX_A)) == 0);
    ev.ours = ours;
    if (!ours && !g_log_all) return ERROR_SUCCESS;

    EnterCriticalSection(&g_lock);
    if ((g_head + 1) % WATCH_CAP == g_taken) {
        g_dropped++;                       /* consumer fell behind */
    } else {
        g_ring[g_head] = ev;
        g_head = (g_head + 1) % WATCH_CAP;
    }
    LeaveCriticalSection(&g_lock);

    return ERROR_SUCCESS;
}

int watch_start(int log_all)
{
    CM_NOTIFY_FILTER filter;
    CONFIGRET cr;

    if (!g_lock_init) {
        InitializeCriticalSection(&g_lock);
        g_lock_init = 1;
    }
    g_t0      = GetTickCount();
    g_head    = g_taken = g_dropped = 0;
    g_log_all = log_all;
    g_active  = 1;

    memset(&filter, 0, sizeof(filter));
    filter.cbSize     = sizeof(filter);
    filter.FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE;
    filter.Flags      = CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES;

    cr = CM_Register_Notification(&filter, NULL, on_pnp, &g_handle);
    if (cr != CR_SUCCESS) {
        char msg[128];
        jb_t jb;
        g_active = 0;
        jb_init(&jb);
        jb_str(&jb, "api", "CM_Register_Notification");
        jb_str(&jb, "error_text", pf_cr_msg(cr, msg, sizeof(msg)));
        log_event(PF_WARN, "pnp_watch_failed", jb_get(&jb));
        jb_free(&jb);
        return -1;
    }
    log_event(PF_INFO, "pnp_watch_started", log_all ? "\"scope\":\"all\"" : "\"scope\":\"pnpfuzz\"");
    return 0;
}

void watch_stop(void)
{
    g_active = 0;
    if (g_handle) {
        CM_Unregister_Notification(g_handle);
        g_handle = NULL;
    }
    if (g_dropped) {
        jb_t jb;
        jb_init(&jb);
        jb_num(&jb, "dropped_events", g_dropped);
        log_event(PF_WARN, "pnp_watch_overflow", jb_get(&jb));
        jb_free(&jb);
    }
    log_event(PF_INFO, "pnp_watch_stopped", NULL);
}

void watch_mark(void)
{
    if (!g_lock_init) return;
    EnterCriticalSection(&g_lock);
    g_taken = g_head;
    LeaveCriticalSection(&g_lock);
}

int watch_take(pnpev_t *out, int cap)
{
    int n = 0;
    if (!g_lock_init) return 0;

    EnterCriticalSection(&g_lock);
    while (g_taken != g_head && n < cap) {
        out[n++] = g_ring[g_taken];
        g_taken = (g_taken + 1) % WATCH_CAP;
    }
    LeaveCriticalSection(&g_lock);
    return n;
}
