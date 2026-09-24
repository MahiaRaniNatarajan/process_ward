/*
 * graph.h
 * -------
 * The "family tree" view: turns the flat process list into a
 * parent-child tree (ppid relationships among *currently visible*
 * processes) so an admin can trace a problem from a child back to its
 * ancestor, and see whether trouble is isolated to one process or
 * spreads across a whole process family.
 */
#ifndef GRAPH_H
#define GRAPH_H

#include "common.h"

/* Prints the full causal graph: every root process (no visible
 * parent) and its descendants, indented, each line tagged with its
 * diagnosis chip/severity so problem chains stand out
 * (e.g. "Parent -> Child -> Zombie"). */
void print_causal_graph(const Diagnosis *diagnoses, int count);

/* Prints the health of one process family: the process at `root_pid`
 * and every descendant, with a per-member health mark and a rolled-up
 * family verdict (isolated problem vs family-wide problem). If
 * `root_pid` is 0, prints every family (grouped by root) in the
 * system, one after another. */
void print_family_health(const Diagnosis *diagnoses, int count, int root_pid);

#endif /* GRAPH_H */
