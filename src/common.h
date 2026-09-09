/*
 * common.h
 * --------
 * Shared struct definitions used across all modules of Process Ward.
 */
#ifndef COMMON_H
#define COMMON_H

#include <string.h>

#define NAME_LEN        64
#define CMDLINE_LEN     512
#define STATE_NAME_LEN  32
#define UID_LEN         16
#define COND_LEN        80
#define ICON_LEN        16
#define SEV_LEN         16
#define EVIDENCE_LEN    200
#define MAX_EVIDENCE    6
#define OS_CONCEPT_LEN  120
#define CAUSE_LEN       220
#define ACTION_LEN      24
#define LABEL_LEN       140
#define SAFETY_LEN      8
#define NOTE_LEN        340
#define CMD_LEN         160
#define MAX_FINDINGS    8

/* ---- Process facts, collected straight from /proc, no diagnosis ---- */
typedef struct {
    int pid;
    int ppid;
    int pgrp;
    int session;
    char name[NAME_LEN];
    char cmdline[CMDLINE_LEN];
    char state_code;                 /* 'R', 'S', 'D', 'Z', 'T', 't', 'X', 'I' */
    char state_name[STATE_NAME_LEN];
    int num_threads;
    double cpu_seconds;
    long mem_bytes;
    double mem_mb;
    double age_seconds;
    long vsize;
    char uid[UID_LEN];
    int has_uid;
} Process;

/* ---- A single treatment recommendation ---- */
typedef struct {
    char action[ACTION_LEN];   /* NOTIFY_PARENT, SIGCONT, INVESTIGATE, CHOICE, NONE */
    char label[LABEL_LEN];
    char safety[SAFETY_LEN];   /* green / yellow / red */
    char note[NOTE_LEN];
    char cmd[CMD_LEN];         /* ready-to-run shell command for this specific PID, empty if N/A */
} Treatment;

/* ---- A single rule finding ---- */
typedef struct {
    char condition[COND_LEN];
    char icon[ICON_LEN];
    char severity[SEV_LEN];    /* HEALTHY / OBSERVATION / WARNING / CRITICAL */
    char evidence[MAX_EVIDENCE][EVIDENCE_LEN];
    int evidence_count;
    char os_concept[OS_CONCEPT_LEN];
    int has_likely_cause;
    char likely_cause[CAUSE_LEN];
    Treatment treatment;
} Finding;

/* ---- Full diagnosis for one process ---- */
typedef struct {
    int pid;
    char name[NAME_LEN];
    Process process;
    Finding findings[MAX_FINDINGS];
    int finding_count;
    int primary_index;         /* index into findings[] of the primary diagnosis */
    char severity[SEV_LEN];    /* == findings[primary_index].severity */
} Diagnosis;

/* ---- System-wide health report ---- */
typedef struct {
    double overall_health;
    int total_processes;
    int healthy, observation, warning, critical;
    int zombie_count, orphan_count, stopped_count, sleeping_count;
    double process_stability;
    double process_management;
    double reaping_health;
} HealthReport;

typedef struct {
    char name[40];
    double score;
    char rating[16]; /* Excellent / Good / Moderate / Weak */
} Capability;

#define MAX_CAPABILITIES 6

typedef struct {
    char name[64];
    char confidence[8];    /* high / medium */
    char evidence[200];
    char classification[16]; /* normal / problem / observation */
} Pattern;

#define MAX_PATTERNS 8

typedef struct {
    int pid;
    char name[NAME_LEN];
    char reason[CAUSE_LEN];
} RootCause;

#define MAX_ROOT_CAUSES 64

typedef struct {
    HealthReport health;
    Capability capabilities[MAX_CAPABILITIES];
    int capability_count;
    Pattern patterns[MAX_PATTERNS];
    int pattern_count;
    RootCause root_causes[MAX_ROOT_CAUSES];
    int root_cause_count;
} FullReport;

/* ---- Severity ranking helper (shared) ---- */
static inline int severity_rank(const char *sev) {
    if (strcmp(sev, "HEALTHY") == 0) return 0;
    if (strcmp(sev, "OBSERVATION") == 0) return 1;
    if (strcmp(sev, "WARNING") == 0) return 2;
    if (strcmp(sev, "CRITICAL") == 0) return 3;
    return 0;
}

#endif /* COMMON_H */
