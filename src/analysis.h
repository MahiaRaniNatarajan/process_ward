/*
 * analysis.h
 * ----------
 * Turns a list of per-process diagnoses into a system-wide "hospital
 * report": overall health score, capability scores, and detected
 * patterns (e.g. reaping deficiency, process proliferation).
 *
 * All scores are computed from explicit rules over the observed data,
 * never arbitrary numbers.
 */
#ifndef ANALYSIS_H
#define ANALYSIS_H

#include "common.h"

void health_report(const Diagnosis *diagnoses, int count, HealthReport *out);
void capability_analysis(const Diagnosis *diagnoses, int count,
                          const HealthReport *report,
                          Capability *out, int *out_count);
void detect_patterns(const Diagnosis *diagnoses, int count,
                      const HealthReport *report,
                      Pattern *out, int *out_count);
void root_cause_candidates(const Diagnosis *diagnoses, int count,
                            RootCause *out, int *out_count);
void full_report(const Diagnosis *diagnoses, int count, FullReport *out);

#endif /* ANALYSIS_H */
