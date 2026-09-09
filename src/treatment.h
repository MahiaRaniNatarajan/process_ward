/*
 * treatment.h
 * -----------
 * Executes treatments (signals) with explicit safety tiers.
 *
 * Safety tiers (from the design doc):
 *   green  -> automatic / informational, always allowed
 *   yellow -> user-approved, potentially disruptive
 *   red    -> dangerous, requires explicit confirmation flag
 *
 * Only a fixed allow-list of signals can ever be sent. Normal Unix
 * permissions still apply on top of this (you can only signal processes
 * you own, unless running as root).
 */
#ifndef TREATMENT_H
#define TREATMENT_H

#include "common.h"

typedef struct {
    int pid;
    char signal_name[16];
    char safety_tier[SAFETY_LEN];
    char status[16];
} TreatmentResult;

/* Look up the safety tier ("green"/"yellow"/"red") for an allowed signal
 * name, or NULL if the signal is not in the allow-list. */
const char *safety_tier_for(const char *signal_name_upper);

/* Apply a treatment (signal) to a process.
 * On success returns 0 and fills *out; on failure returns -1 and writes
 * a human-readable reason into err_buf (must be at least 256 bytes). */
int send_signal(int pid, const char *signal_name, int confirmed,
                 TreatmentResult *out, char *err_buf, size_t err_buf_len);

#endif /* TREATMENT_H */
