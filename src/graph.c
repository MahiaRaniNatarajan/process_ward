/*
 * graph.c
 * -------
 * See graph.h for the module's purpose.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "graph.h"

#define G_RESET "\033[0m"
#define G_BOLD  "\033[1m"
#define G_DIM   "\033[2m"

static const char *g_color(const char *sev) {
    if (strcmp(sev, "HEALTHY") == 0) return "\033[32m";
    if (strcmp(sev, "OBSERVATION") == 0) return "\033[36m";
    if (strcmp(sev, "WARNING") == 0) return "\033[33m";
    if (strcmp(sev, "CRITICAL") == 0) return "\033[31m";
    return "";
}

static const char *g_mark(const char *sev) {
    if (strcmp(sev, "HEALTHY") == 0) return "\xE2\x9C\x93";       /* checkmark */
    if (strcmp(sev, "OBSERVATION") == 0) return "\xE2\x97\x8F";   /* filled circle */
    if (strcmp(sev, "WARNING") == 0) return "\xE2\x9A\xA0";       /* warning triangle */
    if (strcmp(sev, "CRITICAL") == 0) return "\xF0\x9F\x94\xB4";  /* red circle */
    return "?";
}

static const Diagnosis *find_by_pid(const Diagnosis *diagnoses, int count, int pid) {
    for (int i = 0; i < count; i++) {
        if (diagnoses[i].pid == pid) return &diagnoses[i];
    }
    return NULL;
}

/* Roots = processes whose parent isn't in this snapshot at all (their
 * real parent already exited or is invisible to us), which in
 * practice means pid 1 and kernel threads' ppid 0/2. */
static int is_root(const Diagnosis *diagnoses, int count, const Diagnosis *d) {
    if (d->process.ppid == d->pid) return 1; /* defensive: self-parented */
    if (find_by_pid(diagnoses, count, d->process.ppid) == NULL) return 1;
    return 0;
}

static void print_node(const Diagnosis *d, int depth, int is_last_sibling, unsigned long ancestor_bits) {
    (void)is_last_sibling;
    for (int i = 0; i < depth; i++) {
        int has_more = (ancestor_bits >> i) & 1UL;
        printf(depth - 1 == i ? (has_more ? "\xE2\x94\x9C\xE2\x94\x80\xE2\x94\x80 " /* |-- */
                                           : "\xE2\x94\x94\xE2\x94\x80\xE2\x94\x80 " /* `-- */)
                               : (has_more ? "\xE2\x94\x82   " /* |   */ : "    "));
    }
    const Finding *primary = &d->findings[d->primary_index];
    printf("%s%s%s PID %-7d %-18s [%s: %s]%s\n",
           g_color(d->severity), g_mark(d->severity), G_RESET,
           d->pid, d->process.name, d->severity, primary->condition,
           G_RESET);
}

static void print_subtree(const Diagnosis *diagnoses, int count, int pid,
                           int depth, unsigned long ancestor_bits) {
    /* Gather direct children first so we know which is last (for the
     * tree-drawing characters). */
    int child_idx[512];
    int nchild = 0;
    for (int i = 0; i < count && nchild < 512; i++) {
        if (diagnoses[i].process.ppid == pid && diagnoses[i].pid != pid) {
            child_idx[nchild++] = i;
        }
    }
    for (int c = 0; c < nchild; c++) {
        const Diagnosis *d = &diagnoses[child_idx[c]];
        int is_last = (c == nchild - 1);
        unsigned long bits = ancestor_bits | (is_last ? 0UL : (1UL << depth));
        print_node(d, depth + 1, is_last, bits);
        print_subtree(diagnoses, count, d->pid, depth + 1, bits);
    }
}

void print_causal_graph(const Diagnosis *diagnoses, int count) {
    printf(G_BOLD "\nProcess Causal Graph" G_RESET "\n");
    printf(G_DIM "Parent -> Child relationships for every visible process. "
           "Colored/marked entries show a diagnosed condition.\n" G_RESET);

    int printed_root = 0;
    for (int i = 0; i < count; i++) {
        const Diagnosis *d = &diagnoses[i];
        if (!is_root(diagnoses, count, d)) continue;
        printed_root = 1;
        printf("%s%s%s PID %-7d %-18s [%s: %s]%s\n",
               g_color(d->severity), g_mark(d->severity), G_RESET,
               d->pid, d->process.name, d->severity,
               d->findings[d->primary_index].condition, G_RESET);
        print_subtree(diagnoses, count, d->pid, 0, 0UL);
    }
    if (!printed_root) {
        printf("  (no processes visible)\n");
    }
}

/* ---- family health -------------------------------------------------- */

static int topmost_ancestor(const Diagnosis *diagnoses, int count, int pid) {
    int cur = pid;
    for (int hops = 0; hops < count + 1; hops++) {
        const Diagnosis *d = find_by_pid(diagnoses, count, cur);
        if (!d) return cur;
        if (is_root(diagnoses, count, d)) return cur;
        cur = d->process.ppid;
    }
    return cur;
}

static void collect_family(const Diagnosis *diagnoses, int count, int pid,
                            const Diagnosis **out, int *n) {
    const Diagnosis *self = find_by_pid(diagnoses, count, pid);
    if (self) out[(*n)++] = self;
    for (int i = 0; i < count; i++) {
        if (diagnoses[i].process.ppid == pid && diagnoses[i].pid != pid) {
            collect_family(diagnoses, count, diagnoses[i].pid, out, n);
        }
    }
}

static void print_one_family(const Diagnosis *diagnoses, int count, int root_pid) {
    const Diagnosis *root = find_by_pid(diagnoses, count, root_pid);
    if (!root) {
        printf("  PID %d not found.\n", root_pid);
        return;
    }

    const Diagnosis *members[4096];
    int n = 0;
    collect_family(diagnoses, count, root_pid, members, &n);

    int healthy = 0, observation = 0, warning = 0, critical = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(members[i]->severity, "HEALTHY") == 0) healthy++;
        else if (strcmp(members[i]->severity, "OBSERVATION") == 0) observation++;
        else if (strcmp(members[i]->severity, "WARNING") == 0) warning++;
        else if (strcmp(members[i]->severity, "CRITICAL") == 0) critical++;
    }

    printf(G_BOLD "\n%s (PID %d) - family of %d process%s" G_RESET "\n",
           root->process.name, root_pid, n, n == 1 ? "" : "es");
    for (int i = 0; i < n; i++) {
        const Diagnosis *d = members[i];
        int depth = 0;
        int cur = d->pid;
        while (cur != root_pid) {
            const Diagnosis *dd = find_by_pid(diagnoses, count, cur);
            if (!dd) break;
            cur = dd->process.ppid;
            depth++;
            if (depth > 64) break; /* safety valve against cycles */
        }
        for (int s = 0; s < depth; s++) printf("   ");
        printf("%s\xE2\x94\x9C\xE2\x94\x80\xE2\x94\x80 %s %s%s  PID %-7d  %s\n",
               depth > 0 ? "" : "", g_color(d->severity), g_mark(d->severity), G_RESET,
               d->pid, d->process.name);
    }

    const char *verdict;
    if (critical > 0 && (critical + warning) > n / 2) verdict = "family-wide problem - most members are affected";
    else if (critical > 0 || warning > 0) verdict = "isolated problem - only some members are affected";
    else verdict = "family healthy";
    printf(G_DIM "  -> %d healthy, %d observation, %d warning, %d critical: %s" G_RESET "\n",
           healthy, observation, warning, critical, verdict);
}

void print_family_health(const Diagnosis *diagnoses, int count, int root_pid) {
    if (root_pid != 0) {
        print_one_family(diagnoses, count, root_pid);
        return;
    }

    /* No PID given: group every process by its topmost visible
     * ancestor and print one family block per root. */
    int roots[4096];
    int nroots = 0;
    for (int i = 0; i < count; i++) {
        int top = topmost_ancestor(diagnoses, count, diagnoses[i].pid);
        int seen = 0;
        for (int j = 0; j < nroots; j++) if (roots[j] == top) { seen = 1; break; }
        if (!seen && nroots < 4096) roots[nroots++] = top;
    }
    for (int i = 0; i < nroots; i++) {
        print_one_family(diagnoses, count, roots[i]);
    }
}
