/*
 * rule_engine.c
 * -------------
 * See rule_engine.h for the module's purpose.
 */
#include <stdio.h>
#include <string.h>

#include "rule_engine.h"

static Finding *add_finding(Diagnosis *d) {
    Finding *f = &d->findings[d->finding_count++];
    memset(f, 0, sizeof(*f));
    return f;
}

static void add_evidence(Finding *f, const char *text) {
    if (f->evidence_count < MAX_EVIDENCE) {
        snprintf(f->evidence[f->evidence_count], EVIDENCE_LEN, "%s", text);
        f->evidence_count++;
    }
}

void diagnose_process(const Process *proc, const Process *all, int all_count,
                       Diagnosis *out) {
    memset(out, 0, sizeof(*out));
    out->pid = proc->pid;
    snprintf(out->name, NAME_LEN, "%s", proc->name);
    out->process = *proc;

    char buf[EVIDENCE_LEN];

    /* --- Rule: Zombie --------------------------------------------- */
    if (proc->state_code == 'Z') {
        Finding *f = add_finding(out);
        snprintf(f->condition, COND_LEN, "Zombie Process");
        snprintf(f->icon, ICON_LEN, "\xF0\x9F\x92\x80"); /* 💀 */
        int critical = proc->age_seconds > LONG_LIVED_ZOMBIE_SECONDS;
        snprintf(f->severity, SEV_LEN, "%s", critical ? "CRITICAL" : "WARNING");
        add_evidence(f, "State = Z (zombie)");
        snprintf(buf, sizeof(buf), "Parent PID = %d", proc->ppid);
        add_evidence(f, buf);
        add_evidence(f, "Process has completed execution");
        add_evidence(f, "Exit status has not been collected by parent");
        snprintf(f->os_concept, OS_CONCEPT_LEN, "Process termination / process reaping");
        f->has_likely_cause = 1;
        snprintf(f->likely_cause, CAUSE_LEN, "Parent has not called wait()/waitpid() on this child");
        snprintf(f->treatment.action, ACTION_LEN, "NOTIFY_PARENT");
        snprintf(f->treatment.label, LABEL_LEN, "Parent must reap child via wait()/waitpid()");
        snprintf(f->treatment.safety, SAFETY_LEN, "yellow");
        snprintf(f->treatment.note, NOTE_LEN,
                 "A zombie has already terminated; it cannot be killed. "
                 "SIGKILL has no effect. The only real fix is the parent "
                 "reaping it, or the parent's own termination (which "
                 "reparents remaining zombies to init/systemd for cleanup).");
        snprintf(f->treatment.cmd, CMD_LEN,
                 "kill -TERM %d   # terminates parent PID %d so init/systemd reparents and reaps zombie PID %d",
                 proc->ppid, proc->ppid, proc->pid);
    }

    /* --- Rule: Orphan (reparented to init) -------------------------- */
    if (proc->ppid == ORPHAN_PPID && proc->state_code != 'Z') {
        Finding *f = add_finding(out);
        snprintf(f->condition, COND_LEN, "Orphan Process (reparented)");
        snprintf(f->icon, ICON_LEN, "\xF0\x9F\x91\xB6"); /* 👶 */
        snprintf(f->severity, SEV_LEN, "OBSERVATION");
        snprintf(buf, sizeof(buf), "PPID = %d (init/systemd)", ORPHAN_PPID);
        add_evidence(f, buf);
        add_evidence(f, "Original parent has terminated");
        snprintf(f->os_concept, OS_CONCEPT_LEN, "Orphan reparenting");
        f->has_likely_cause = 1;
        snprintf(f->likely_cause, CAUSE_LEN, "Original parent exited before this child did");
        snprintf(f->treatment.action, ACTION_LEN, "NONE");
        snprintf(f->treatment.label, LABEL_LEN, "No action required - this is normal OS behavior");
        snprintf(f->treatment.safety, SAFETY_LEN, "green");
        snprintf(f->treatment.note, NOTE_LEN,
                 "Orphan reparenting to init is a designed safety mechanism, not a fault.");
        f->treatment.cmd[0] = '\0';
    }

    /* --- Rule: Stopped process --------------------------------------- */
    if (proc->state_code == 'T') {
        Finding *f = add_finding(out);
        snprintf(f->condition, COND_LEN, "Stopped Process");
        snprintf(f->icon, ICON_LEN, "\xE2\x8F\xB8"); /* ⏸ */
        snprintf(f->severity, SEV_LEN, "WARNING");
        add_evidence(f, "State = T (stopped)");
        snprintf(f->os_concept, OS_CONCEPT_LEN, "Job control / signal handling");
        f->has_likely_cause = 1;
        snprintf(f->likely_cause, CAUSE_LEN,
                 "Process received SIGSTOP or SIGTSTP and has not been resumed");
        snprintf(f->treatment.action, ACTION_LEN, "SIGCONT");
        snprintf(f->treatment.label, LABEL_LEN, "Send SIGCONT to resume the process");
        snprintf(f->treatment.safety, SAFETY_LEN, "yellow");
        snprintf(f->treatment.note, NOTE_LEN,
                 "Resuming is safe if the process was stopped intentionally for inspection.");
        snprintf(f->treatment.cmd, CMD_LEN, "kill -CONT %d", proc->pid);
    }

    /* --- Rule: Uninterruptible sleep (possible I/O stall) ------------- */
    if (proc->state_code == 'D') {
        Finding *f = add_finding(out);
        snprintf(f->condition, COND_LEN, "Uninterruptible Sleep (possible I/O stall)");
        snprintf(f->icon, ICON_LEN, "\xF0\x9F\xA7\x8A"); /* 🧊 */
        snprintf(f->severity, SEV_LEN, "WARNING");
        add_evidence(f, "State = D (uninterruptible sleep)");
        snprintf(f->os_concept, OS_CONCEPT_LEN, "Blocking I/O / kernel wait state");
        f->has_likely_cause = 1;
        snprintf(f->likely_cause, CAUSE_LEN,
                 "Process is waiting on disk, network filesystem, or a device driver");
        snprintf(f->treatment.action, ACTION_LEN, "INVESTIGATE");
        snprintf(f->treatment.label, LABEL_LEN, "Investigate underlying I/O / device");
        snprintf(f->treatment.safety, SAFETY_LEN, "green");
        snprintf(f->treatment.note, NOTE_LEN,
                 "Processes in state D cannot be killed by signals (not even "
                 "SIGKILL) until the kernel wait completes.");
        snprintf(f->treatment.cmd, CMD_LEN,
                 "cat /proc/%d/stack 2>/dev/null || cat /proc/%d/wchan; echo   # shows what PID %d is blocked on",
                 proc->pid, proc->pid, proc->pid);
    }

    /* --- Rule: High CPU usage ------------------------------------------ */
    if (proc->cpu_seconds >= HIGH_CPU_SECONDS) {
        Finding *f = add_finding(out);
        snprintf(f->condition, COND_LEN, "High CPU Utilization");
        snprintf(f->icon, ICON_LEN, "\xF0\x9F\x94\xA5"); /* 🔥 */
        snprintf(f->severity, SEV_LEN, "WARNING");
        snprintf(buf, sizeof(buf), "Cumulative CPU time = %.2fs", proc->cpu_seconds);
        add_evidence(f, buf);
        snprintf(f->os_concept, OS_CONCEPT_LEN, "CPU scheduling / resource management");
        f->has_likely_cause = 1;
        snprintf(f->likely_cause, CAUSE_LEN, "Compute-heavy workload or a runaway loop");
        snprintf(f->treatment.action, ACTION_LEN, "CHOICE");
        snprintf(f->treatment.label, LABEL_LEN, "Investigate, or send SIGTERM if unwanted");
        snprintf(f->treatment.safety, SAFETY_LEN, "yellow");
        snprintf(f->treatment.note, NOTE_LEN,
                 "Distinguish a legitimate heavy workload from a runaway process before acting.");
        snprintf(f->treatment.cmd, CMD_LEN, "kill -TERM %d", proc->pid);
    }

    /* --- Rule: High memory usage ---------------------------------------- */
    if (proc->mem_mb >= HIGH_MEM_MB) {
        Finding *f = add_finding(out);
        snprintf(f->condition, COND_LEN, "High Memory Utilization");
        snprintf(f->icon, ICON_LEN, "\xF0\x9F\x90\x98"); /* 🐘 */
        snprintf(f->severity, SEV_LEN, "WARNING");
        snprintf(buf, sizeof(buf), "RSS = %.2f MB", proc->mem_mb);
        add_evidence(f, buf);
        snprintf(f->os_concept, OS_CONCEPT_LEN, "Memory management");
        f->has_likely_cause = 1;
        snprintf(f->likely_cause, CAUSE_LEN, "Large working set or a memory leak");
        snprintf(f->treatment.action, ACTION_LEN, "CHOICE");
        snprintf(f->treatment.label, LABEL_LEN, "Investigate, or send SIGTERM if unwanted");
        snprintf(f->treatment.safety, SAFETY_LEN, "yellow");
        snprintf(f->treatment.note, NOTE_LEN,
                 "Check for a growth trend across scans before assuming this is a leak.");
        snprintf(f->treatment.cmd, CMD_LEN, "kill -TERM %d", proc->pid);
    }

    /* --- Rule: Parent with many zombie children (root-cause candidate) - */
    int zombie_kids = 0;
    for (int i = 0; i < all_count; i++) {
        if (all[i].ppid == proc->pid && all[i].state_code == 'Z') {
            zombie_kids++;
        }
    }
    if (zombie_kids >= 2) {
        Finding *f = add_finding(out);
        snprintf(f->condition, COND_LEN, "Child-Reaping Deficiency (root-cause candidate)");
        snprintf(f->icon, ICON_LEN, "\xF0\x9F\xA7\xAC"); /* 🧬 */
        snprintf(f->severity, SEV_LEN, "CRITICAL");
        snprintf(buf, sizeof(buf), "%d zombie children detected", zombie_kids);
        add_evidence(f, buf);
        add_evidence(f, "Parent is alive but is not reaping exited children");
        snprintf(f->os_concept, OS_CONCEPT_LEN, "wait()/waitpid() / SIGCHLD handling");
        f->has_likely_cause = 1;
        snprintf(f->likely_cause, CAUSE_LEN,
                 "Parent process is missing or mishandling a SIGCHLD handler / wait() loop");
        snprintf(f->treatment.action, ACTION_LEN, "NOTIFY_PARENT");
        snprintf(f->treatment.label, LABEL_LEN, "Fix or restart the parent process's reaping logic");
        snprintf(f->treatment.safety, SAFETY_LEN, "yellow");
        snprintf(f->treatment.note, NOTE_LEN,
                 "Treat the parent, not just the zombie children - they are symptoms.");
        snprintf(f->treatment.cmd, CMD_LEN,
                 "kill -TERM %d   # terminates/restarts parent PID %d, flushing its %d zombie children",
                 proc->pid, proc->pid, zombie_kids);
    }

    if (out->finding_count == 0) {
        Finding *f = add_finding(out);
        snprintf(f->condition, COND_LEN, "Healthy");
        snprintf(f->icon, ICON_LEN, "\xF0\x9F\x9F\xA2"); /* 🟢 */
        snprintf(f->severity, SEV_LEN, "HEALTHY");
        add_evidence(f, "No rule conditions matched");
        snprintf(f->os_concept, OS_CONCEPT_LEN, "Normal process lifecycle");
        f->has_likely_cause = 0;
        snprintf(f->treatment.action, ACTION_LEN, "NONE");
        snprintf(f->treatment.label, LABEL_LEN, "No treatment needed");
        snprintf(f->treatment.safety, SAFETY_LEN, "green");
        snprintf(f->treatment.note, NOTE_LEN, "Continue routine monitoring.");
        f->treatment.cmd[0] = '\0';
    }

    /* Stable sort by severity, descending - ties keep original order,
     * mirroring Python's list.sort(key=..., reverse=True) semantics. */
    for (int i = 1; i < out->finding_count; i++) {
        Finding key = out->findings[i];
        int key_rank = severity_rank(key.severity);
        int j = i - 1;
        while (j >= 0 && severity_rank(out->findings[j].severity) < key_rank) {
            out->findings[j + 1] = out->findings[j];
            j--;
        }
        out->findings[j + 1] = key;
    }

    out->primary_index = 0;
    snprintf(out->severity, SEV_LEN, "%s", out->findings[0].severity);
}

void diagnose_all(const Process *processes, int count, Diagnosis *out) {
    for (int i = 0; i < count; i++) {
        diagnose_process(&processes[i], processes, count, &out[i]);
    }
}
