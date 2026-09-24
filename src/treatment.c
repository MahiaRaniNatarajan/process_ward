#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
/*
 * treatment.c
 * -----------
 * See treatment.h for the module's purpose.
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>

#include "treatment.h"

typedef struct {
    const char *name;
    int signum;
    const char *tier;
} AllowedSignal;

static const AllowedSignal ALLOWED_SIGNALS[] = {
    {"SIGTERM", SIGTERM, "yellow"},
    {"SIGKILL", SIGKILL, "red"},
    {"SIGSTOP", SIGSTOP, "yellow"},
    {"SIGCONT", SIGCONT, "yellow"},
};
#define NUM_ALLOWED (int)(sizeof(ALLOWED_SIGNALS) / sizeof(ALLOWED_SIGNALS[0]))

static const AllowedSignal *lookup(const char *name_upper) {
    for (int i = 0; i < NUM_ALLOWED; i++) {
        if (strcmp(ALLOWED_SIGNALS[i].name, name_upper) == 0) {
            return &ALLOWED_SIGNALS[i];
        }
    }
    return NULL;
}

const char *safety_tier_for(const char *signal_name_upper) {
    const AllowedSignal *a = lookup(signal_name_upper);
    return a ? a->tier : NULL;
}

int send_signal(int pid, const char *signal_name, int confirmed,
                 TreatmentResult *out, char *err_buf, size_t err_buf_len) {
    char upper[16];
    size_t i = 0;
    for (; signal_name[i] && i < sizeof(upper) - 1; i++) {
        upper[i] = (char)toupper((unsigned char)signal_name[i]);
    }
    upper[i] = '\0';

    const AllowedSignal *sig = lookup(upper);
    if (!sig) {
        snprintf(err_buf, err_buf_len,
                 "'%s' is not an allowed treatment. Allowed: SIGTERM, SIGKILL, SIGSTOP, SIGCONT",
                 upper);
        return -1;
    }

    if (strcmp(sig->tier, "red") == 0 && !confirmed) {
        snprintf(err_buf, err_buf_len,
                 "%s is a dangerous (red-tier) treatment and requires explicit confirmation (confirmed=true).",
                 upper);
        return -1;
    }

    if (kill((pid_t)pid, sig->signum) != 0) {
        if (errno == ESRCH) {
            snprintf(err_buf, err_buf_len, "PID %d no longer exists.", pid);
        } else if (errno == EPERM) {
            snprintf(err_buf, err_buf_len,
                     "Permission denied sending %s to PID %d. You can only signal "
                     "processes you own (or run as root).",
                     upper, pid);
        } else {
            snprintf(err_buf, err_buf_len, "Failed to send %s to PID %d: %s",
                     upper, pid, strerror(errno));
        }
        return -1;
    }

    out->pid = pid;
    snprintf(out->signal_name, sizeof(out->signal_name), "%s", upper);
    snprintf(out->safety_tier, sizeof(out->safety_tier), "%s", sig->tier);
    snprintf(out->status, sizeof(out->status), "sent");
    return 0;
}
