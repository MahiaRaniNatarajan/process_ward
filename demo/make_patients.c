#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
/*
 * make_patients.c
 * ----------------
 * Creates real, observable "patients" on your Linux system so you have
 * something interesting to scan:
 *
 *   - a zombie process (child exits, parent never reaps it)
 *   - an orphan process (parent exits first, child reparented to init)
 *   - a stopped process (child sent SIGSTOP)
 *   - a CPU-hot process (child busy-loops)
 *
 * Run this, then run process_ward scan/watch in another terminal.
 * Leave this program's terminal open - closing it cleans everything up
 * except the zombie, which will persist until this process exits.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <time.h>

static pid_t make_zombie(void) {
    pid_t pid = fork();
    if (pid == 0) {
        _exit(0); /* child exits immediately... */
    }
    /* ...parent (this process) deliberately never calls waitpid() */
    printf("[zombie] child %d exited and will not be reaped -> zombie\n", (int)pid);
    return pid;
}

/* fork a child, which itself forks a grandchild and exits immediately.
 * The grandchild keeps running (sleeping) and gets reparented to
 * init/systemd once its immediate parent is gone - a textbook orphan. */
static pid_t make_orphan(void) {
    pid_t child_pid = fork();
    if (child_pid == 0) {
        pid_t grandchild_pid = fork();
        if (grandchild_pid == 0) {
            sleep(30);
            _exit(0);
        }
        _exit(0); /* child exits immediately, orphaning the grandchild */
    }
    waitpid(child_pid, NULL, 0);
    printf("[orphan] grandchild reparented to init/systemd\n");
    return child_pid;
}

static pid_t make_stopped(void) {
    pid_t pid = fork();
    if (pid == 0) {
        sleep(60);
        _exit(0);
    }
    usleep(200 * 1000); /* 0.2s */
    kill(pid, SIGSTOP);
    printf("[stopped] child %d sent SIGSTOP\n", (int)pid);
    return pid;
}

static pid_t make_cpu_hot(void) {
    pid_t pid = fork();
    if (pid == 0) {
        time_t end = time(NULL) + 60;
        volatile long x = 0;
        while (time(NULL) < end) {
            x++;
        }
        _exit(0);
    }
    printf("[cpu-hot] child %d busy-looping\n", (int)pid);
    return pid;
}

int main(void) {
    printf("Creating demo patients. Keep this process running.\n");
    pid_t z = make_zombie();
    pid_t o = make_orphan();
    pid_t s = make_stopped();
    pid_t c = make_cpu_hot();
    printf("\nPIDs created: zombie=%d orphan=%d stopped=%d cpu_hot=%d\n",
           (int)z, (int)o, (int)s, (int)c);
    printf("Sleeping for 5 minutes so process_ward has time to observe them.\n");
    printf("Press Ctrl+C to exit (the zombie will be cleaned up on exit).\n");
    sleep(300);
    return 0;
}
