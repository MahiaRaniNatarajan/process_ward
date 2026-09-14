# Process Ward (C port)

Process Ward: a rule-based OS process
health, diagnosis & recovery system. Reads `/proc` directly, diagnoses
process conditions (zombies, orphans, stopped processes, resource
hogs), recommends/executes safety-tiered signal treatments, and prints
a system health report — all in the terminal, no dependencies beyond
a C compiler and libc.

## Build

```bash
make
```

Produces two binaries: `process_ward` (the CLI) and `make_patients`
(spawns demo zombie/orphan/stopped/CPU-hot processes to scan).

## Usage

Same commands as the Python version:

```bash
./process_ward              # interactive REPL
./process_ward scan         # one-shot ward table + report
./process_ward report       # report only
./process_ward watch --interval 5
./process_ward show PID
./process_ward treat PID SIGNAL [--yes]
./process_ward treat-all-safe
```

## Layout

```
src/
  common.h        shared structs (Process, Finding, Diagnosis, reports)
  proc_reader.*   reads /proc/<pid>/{stat,status,cmdline} into facts
  rule_engine.*   the "doctor" - rule-based diagnosis
  treatment.*     safety-tiered signal execution (SIGTERM/KILL/STOP/CONT)
  analysis.*      system health score, capabilities, pattern detection
  cli.c           REPL + subcommands + printing (the only entrypoint)
demo/
  make_patients.c spawns real zombie/orphan/stopped/CPU-hot processes
```

Logic mirrors the original Python module-for-module (same thresholds,
same rule order, same severity scoring, same safety tiers).
