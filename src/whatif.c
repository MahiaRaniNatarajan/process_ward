/*
 * whatif.c
 * --------
 * See whatif.h for the module's purpose.
 */
#include <stdio.h>
#include <stdlib.h>

#include "whatif.h"
#include "common.h"
#include "proc_reader.h"

/* Recursively counts every descendant of `pid` within `all`/`count`
 * and sums their memory, so a deep tree (not just direct children) is
 * accounted for in the blast-radius estimate. */
static void count_descendants(const Process *all, int count, int pid,
                               int *n_procs, double *mem_mb_sum) {
    for (int i = 0; i < count; i++) {
        if (all[i].ppid == pid && all[i].pid != pid) {
            (*n_procs)++;
            *mem_mb_sum += all[i].mem_mb;
            count_descendants(all, count, all[i].pid, n_procs, mem_mb_sum);
        }
    }
}

void whatif_terminate(int pid) {
    Process target;
    if (read_process(pid, &target) != 0) {
        printf("PID %d not found - nothing to simulate.\n", pid);
        return;
    }

    int n;
    Process *all = snapshot(&n);

    int direct_children = 0;
    for (int i = 0; i < n; i++) {
        if (all[i].ppid == pid && all[i].pid != pid) direct_children++;
    }

    int total_descendants = 0;
    double descendant_mem = 0.0;
    count_descendants(all, n, pid, &total_descendants, &descendant_mem);

    Process parent;
    int parent_alive = (target.ppid > 0 && read_process(target.ppid, &parent) == 0);

    printf("\nWhat-if: terminate PID %d (%s) with SIGTERM\n", pid, target.name);
    printf("  - Process will be removed (%.2f MB released directly)\n", target.mem_mb);
    if (direct_children > 0) {
        printf("  - %d direct child process%s may be affected (orphaned or terminated "
               "if it exits on parent death)\n",
               direct_children, direct_children == 1 ? "" : "es");
    } else {
        printf("  - No direct child processes\n");
    }
    if (total_descendants > direct_children) {
        printf("  - %d process(es) total in its descendant tree, an estimated "
               "%.2f MB combined memory footprint\n", total_descendants, descendant_mem);
    }
    if (parent_alive) {
        printf("  - Parent PID %d (%s) remains active\n", target.ppid, parent.name);
    } else if (target.ppid > 0) {
        printf("  - Parent PID %d is not currently visible/running\n", target.ppid);
    }
    printf("  - This is a simulation only: no signal has been sent.\n");
    printf("  - To actually do this: treat %d SIGTERM\n", pid);

    free(all);
}
