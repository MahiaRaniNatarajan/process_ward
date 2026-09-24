/*
 * incident.h
 * ----------
 * Two related pieces of "medical records":
 *
 *   - Process Incident Report: a structured record of a diagnosed
 *     problem (PID, name, parent, condition, evidence, severity,
 *     suspected cause, recommended treatment, and - once known -
 *     what treatment was actually performed and its result), printed
 *     and saved to ~/.process_ward/incidents/.
 *
 *   - Process Recovery History: an append-only, timestamped log of
 *     every recovery action Process Ward has taken, for traceability
 *     and accountability, saved to ~/.process_ward/recovery.log.
 */
#ifndef INCIDENT_H
#define INCIDENT_H

#include "common.h"
#include "treatment.h"

/* Formats a full incident report for `d` into `out` (multi-line
 * plain text). If `treated` is non-zero, the "treatment
 * performed"/"treatment result" fields are filled from `tr`/`outcome`;
 * otherwise they read "not yet treated". */
void format_incident_report(const Diagnosis *d, int treated,
                             const TreatmentResult *tr, const char *outcome,
                             char *out, size_t out_len);

/* Saves an incident report to disk (~/.process_ward/incidents/) and
 * returns the path it was written to in `path_out` (must be at least
 * 600 bytes). Returns 0 on success. */
int incident_save(const Diagnosis *d, int treated, const TreatmentResult *tr,
                   const char *outcome, char *path_out, size_t path_out_len);

/* Appends one timestamped line to the recovery history log. */
void recovery_log_append(const char *fmt, ...);

/* Prints the whole recovery history log to stdout. */
void recovery_log_print(void);

#endif /* INCIDENT_H */
