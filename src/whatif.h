/*
 * whatif.h
 * --------
 * A dry-run "what would happen if" simulation for a potentially
 * disruptive treatment, so an admin can see the blast radius before
 * actually sending a signal. Reads the current process tree; sends
 * no signals.
 */
#ifndef WHATIF_H
#define WHATIF_H

/* Prints a what-if analysis for terminating `pid`: whether it exists,
 * how many direct/total child processes would be affected, how much
 * memory might be released, and whether the parent stays alive. */
void whatif_terminate(int pid);

#endif /* WHATIF_H */
