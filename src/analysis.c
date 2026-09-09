/*
 * analysis.c
 * ----------
 * See analysis.h for the module's purpose.
 */
#include <stdio.h>
#include <string.h>

#include "analysis.h"

static double clampd(double v, double lo, double hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static double round1(double v) { return ((double)(long)(v * 10 + (v >= 0 ? 0.5 : -0.5))) / 10.0; }

static const char *starts_with(const char *s, const char *prefix) {
    size_t n = strlen(prefix);
    return strncmp(s, prefix, n) == 0 ? s : NULL;
}

void health_report(const Diagnosis *diagnoses, int count, HealthReport *out) {
    memset(out, 0, sizeof(*out));
    out->total_processes = count;

    for (int i = 0; i < count; i++) {
        const Diagnosis *d = &diagnoses[i];
        if (strcmp(d->severity, "HEALTHY") == 0) out->healthy++;
        else if (strcmp(d->severity, "OBSERVATION") == 0) out->observation++;
        else if (strcmp(d->severity, "WARNING") == 0) out->warning++;
        else if (strcmp(d->severity, "CRITICAL") == 0) out->critical++;

        const Process *p = &d->process;
        if (p->state_code == 'Z') out->zombie_count++;
        if (p->state_code == 'T') out->stopped_count++;
        if (p->state_code == 'S') out->sleeping_count++;

        for (int j = 0; j < d->finding_count; j++) {
            if (starts_with(d->findings[j].condition, "Orphan")) {
                out->orphan_count++;
            }
        }
    }

    double score = 100.0;
    score -= out->critical * 8;
    score -= out->warning * 3;
    score -= out->observation * 0.5;
    score = clampd(score, 0.0, 100.0);

    double reaping_health = clampd(100.0 - out->zombie_count * 20, 0.0, 1e18);
    double stability = clampd(100.0 - out->critical * 10 - out->warning * 2, 0.0, 1e18);
    double process_mgmt = clampd(100.0 - out->orphan_count * 2 - out->zombie_count * 15, 0.0, 1e18);

    out->overall_health = round1(score);
    out->process_stability = round1(stability);
    out->process_management = round1(process_mgmt);
    out->reaping_health = round1(reaping_health);
}

static const char *bucket(double score) {
    if (score >= 90) return "Excellent";
    if (score >= 75) return "Good";
    if (score >= 50) return "Moderate";
    return "Weak";
}

void capability_analysis(const Diagnosis *diagnoses, int count,
                          const HealthReport *report,
                          Capability *out, int *out_count) {
    (void)diagnoses;
    (void)count;
    int total = report->total_processes > 1 ? report->total_processes : 1;

    double reaping_score = clampd(100 - report->zombie_count * 20, 0.0, 1e18);
    double stability_score = report->process_stability;
    double mgmt_score = report->process_management;
    double signal_score = (report->stopped_count == 0) ? 100.0 : 85.0;

    double warn_ratio = total ? round1(100.0 * (report->warning + report->critical) / total) : 0.0;
    double resource_score = clampd(100.0 - warn_ratio, 0.0, 1e18);

    double creation_score = 100.0;

    const char *names[MAX_CAPABILITIES] = {
        "Process Creation", "Process Management", "Process Reaping",
        "Signal Handling", "Process Stability", "Resource Management"
    };
    double scores[MAX_CAPABILITIES] = {
        creation_score, mgmt_score, reaping_score,
        signal_score, stability_score, round1(resource_score)
    };

    *out_count = MAX_CAPABILITIES;
    for (int i = 0; i < MAX_CAPABILITIES; i++) {
        snprintf(out[i].name, sizeof(out[i].name), "%s", names[i]);
        out[i].score = scores[i];
        snprintf(out[i].rating, sizeof(out[i].rating), "%s", bucket(scores[i]));
    }
}

void detect_patterns(const Diagnosis *diagnoses, int count,
                      const HealthReport *report,
                      Pattern *out, int *out_count) {
    int n = 0;

    int zombies = 0, long_lived_zombies = 0;
    for (int i = 0; i < count; i++) {
        if (diagnoses[i].process.state_code == 'Z') {
            zombies++;
            if (diagnoses[i].process.age_seconds > 60) long_lived_zombies++;
        }
    }

    if (zombies >= 1 && long_lived_zombies > 0) {
        Pattern *p = &out[n++];
        snprintf(p->name, sizeof(p->name), "Potential child-reaping deficiency");
        snprintf(p->confidence, sizeof(p->confidence), "%s", long_lived_zombies >= 2 ? "high" : "medium");
        snprintf(p->evidence, sizeof(p->evidence), "%d zombie process(es), %d older than 60s",
                 zombies, long_lived_zombies);
        snprintf(p->classification, sizeof(p->classification), "problem");
    }

    int orphans = 0;
    for (int i = 0; i < count; i++) {
        for (int j = 0; j < diagnoses[i].finding_count; j++) {
            if (starts_with(diagnoses[i].findings[j].condition, "Orphan")) {
                orphans++;
                break;
            }
        }
    }
    if (orphans > 0 && long_lived_zombies == 0) {
        Pattern *p = &out[n++];
        snprintf(p->name, sizeof(p->name), "Normal orphan reparenting");
        snprintf(p->confidence, sizeof(p->confidence), "high");
        snprintf(p->evidence, sizeof(p->evidence),
                 "%d process(es) reparented to init/systemd, no long-lived zombies present", orphans);
        snprintf(p->classification, sizeof(p->classification), "normal");
    }

    int stopped = 0;
    for (int i = 0; i < count; i++) {
        if (diagnoses[i].process.state_code == 'T') stopped++;
    }
    if (stopped >= 2) {
        Pattern *p = &out[n++];
        snprintf(p->name, sizeof(p->name), "High process-control activity");
        snprintf(p->confidence, sizeof(p->confidence), "medium");
        snprintf(p->evidence, sizeof(p->evidence), "%d processes currently stopped (SIGSTOP)", stopped);
        snprintf(p->classification, sizeof(p->classification), "observation");
    }

    if (report->total_processes > 300) {
        Pattern *p = &out[n++];
        snprintf(p->name, sizeof(p->name), "Process proliferation / resource pressure");
        snprintf(p->confidence, sizeof(p->confidence), "medium");
        snprintf(p->evidence, sizeof(p->evidence), "%d total processes observed", report->total_processes);
        snprintf(p->classification, sizeof(p->classification), "problem");
    }

    if (n == 0) {
        Pattern *p = &out[n++];
        snprintf(p->name, sizeof(p->name), "No significant patterns detected");
        snprintf(p->confidence, sizeof(p->confidence), "high");
        snprintf(p->evidence, sizeof(p->evidence), "System is operating within normal parameters");
        snprintf(p->classification, sizeof(p->classification), "normal");
    }

    *out_count = n;
}

void root_cause_candidates(const Diagnosis *diagnoses, int count,
                            RootCause *out, int *out_count) {
    int n = 0;
    for (int i = 0; i < count && n < MAX_ROOT_CAUSES; i++) {
        for (int j = 0; j < diagnoses[i].finding_count; j++) {
            if (starts_with(diagnoses[i].findings[j].condition, "Child-Reaping Deficiency")) {
                RootCause *rc = &out[n++];
                rc->pid = diagnoses[i].pid;
                snprintf(rc->name, sizeof(rc->name), "%s", diagnoses[i].name);
                snprintf(rc->reason, sizeof(rc->reason), "%s", diagnoses[i].findings[j].likely_cause);
                break;
            }
        }
    }
    *out_count = n;
}

void full_report(const Diagnosis *diagnoses, int count, FullReport *out) {
    memset(out, 0, sizeof(*out));
    health_report(diagnoses, count, &out->health);
    capability_analysis((const Diagnosis *)diagnoses, count, &out->health,
                         out->capabilities, &out->capability_count);
    detect_patterns(diagnoses, count, &out->health, out->patterns, &out->pattern_count);
    root_cause_candidates(diagnoses, count, out->root_causes, &out->root_cause_count);
}
