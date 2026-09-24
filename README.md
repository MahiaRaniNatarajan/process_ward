# Process Ward (C port)

Process Ward: a rule-based OS process
health, diagnosis & recovery system. Reads `/proc` directly, diagnoses
process conditions (zombies, orphans, stopped processes, resource
hogs), recommends/executes safety-tiered signal treatments, and prints
a system health report — all in the terminal, no dependencies beyond
a C compiler and libc.

It also keeps a small on-disk "patient chart" (`~/.process_ward/`) so
it can reason across scans, not just about the current instant:
causal/family graphs, a health timeline per process, predictive
resource-risk and leak detection, incident reports, and a recovery
action history.

## Build

```bash
make
```

Produces two binaries: `process_ward` (the CLI) and `make_patients`
(spawns demo zombie/orphan/stopped/CPU-hot processes to scan).

## Usage

Same commands as the Python version, plus the additions below:

```bash
./process_ward              # interactive REPL
./process_ward scan         # one-shot ward table + report
./process_ward report       # report only
./process_ward watch --interval 5
./process_ward show PID
./process_ward treat PID SIGNAL [--yes]
./process_ward treat-all-safe

./process_ward graph               # process causal graph (parent -> child), problems highlighted
./process_ward family [PID]        # process family health (all families, or one rooted at PID)
./process_ward timeline PID [N]    # health timeline for PID (last N samples, default 20)
./process_ward risk                # predictive resource-risk + leak detection across all processes
./process_ward incident PID        # generate + save a structured incident report for PID
./process_ward recovery-history    # show the recovery action history log
./process_ward whatif PID          # simulate terminating PID - no signal sent
```

Every `scan` / `watch` tick (and the REPL equivalents) records one
timeline sample per visible process to `~/.process_ward/history/`, so
`timeline`, `risk` (predictive risk + leak detection) and the
"persisted for" style context get better the more you scan. `treat`
writes a Detect → Diagnose → Treat → Verify trail to
`~/.process_ward/recovery.log` and auto-saves a full incident report
under `~/.process_ward/incidents/` whenever the pre-treatment
condition was WARNING or CRITICAL.

## Layout

```
src/
  common.h        shared structs (Process, Finding, Diagnosis, reports)
  proc_reader.*   reads /proc/<pid>/{stat,status,cmdline,fd,limits} into facts
  rule_engine.*   the "doctor" - rule-based diagnosis
  treatment.*     safety-tiered signal execution (SIGTERM/KILL/STOP/CONT)
  analysis.*      system health score, capabilities, pattern detection
  history.*       on-disk time-series samples + trend analysis
                  (health timeline, predictive risk, leak detection)
  graph.*         parent-child causal graph + process family health
  incident.*      structured incident reports + recovery action history log
  whatif.*        dry-run "what would happen if I terminated PID" simulation
  cli.c           REPL + subcommands + printing (the only entrypoint)
demo/
  make_patients.c spawns real zombie/orphan/stopped/CPU-hot processes
```

Core diagnosis logic mirrors the original Python module-for-module
(same thresholds, same rule order, same severity scoring, same safety
tiers). The history/graph/incident/whatif modules are new, built on
top of that same fact/diagnosis layer.

## Feature reference

1. **Process Causal Graph** - `graph`: parent → child tree of every
   visible process, each line tagged with its live diagnosis so a
   chain like `Parent → Child → Zombie` is visible at a glance.
2. **Process Health Timeline** - `timeline PID [N]`: CPU, memory,
   thread count, file-descriptor count and state, sampled on every
   scan and shown chronologically.
3. **Predictive Resource Risk Detection** - `risk`: fits a trend to
   each process's recent file-descriptor history and warns when it's
   on pace to hit its soft limit within the next ~15 scans (e.g.
   `500 -> 650 -> 800 -> 950 / 1024`).
4. **Treatment Verification** - built into `treat`: re-scans the
   process 0.3s after signaling it and reports whether the diagnosis
   improved, changed, stayed the same, or the process exited.
5. **Resource-Leak Detection** - also part of `risk`: flags memory or
   thread counts that have risen on every single recorded scan, before
   any hard limit is even in sight.
6. **Explainable Diagnosis** - built into `show PID` / the ward table:
   every finding carries its evidence list, the relevant OS concept,
   and (where known) a likely cause - never just a bare verdict.
7. **Process Incident Report** - `incident PID` (on demand) or
   automatically after a `treat` on a WARNING/CRITICAL process: PID,
   name, parent, condition, evidence, severity, suspected cause,
   recommended treatment, and - once treated - what was done and the
   result. Saved under `~/.process_ward/incidents/`.
8. **Process Recovery History** - `recovery-history`: a timestamped
   Detect → Diagnose → Treat → Verify trail of every treatment
   Process Ward has performed, from `~/.process_ward/recovery.log`.
9. **Process Family Health** - `family [PID]`: rolls up an entire
   process family's health (isolated problem vs. family-wide problem),
   not just one process at a time.
10. **What-If Recovery Simulation** - `whatif PID`: shows what
    terminating a process would affect (child processes, estimated
    memory released, whether the parent survives) before anything is
    actually sent.

