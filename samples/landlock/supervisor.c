// SPDX-License-Identifier: BSD-3-Clause
/*
 * Simple Landlock supervisor that can interactively allow/deny access requests
 *
 * Copyright © 2025 Contributors
 */

#define _GNU_SOURCE
#define __SANE_USERSPACE_TYPES__
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef landlock_create_ruleset
static inline int
landlock_create_ruleset(const struct landlock_ruleset_attr *const attr,
			const size_t size, const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
				    const enum landlock_rule_type rule_type,
				    const void *const rule_attr,
				    const __u32 flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
		       flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd,
					 const __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#define ENV_FS_RO_NAME "LL_FS_RO"
#define ENV_FS_RW_NAME "LL_FS_RW"

/* All access rights */
#define ACCESS_FS_ALL ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_READ_DIR | \
	LANDLOCK_ACCESS_FS_REMOVE_DIR | \
	LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	LANDLOCK_ACCESS_FS_MAKE_CHAR | \
	LANDLOCK_ACCESS_FS_MAKE_DIR | \
	LANDLOCK_ACCESS_FS_MAKE_REG | \
	LANDLOCK_ACCESS_FS_MAKE_SOCK | \
	LANDLOCK_ACCESS_FS_MAKE_FIFO | \
	LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
	LANDLOCK_ACCESS_FS_MAKE_SYM | \
	LANDLOCK_ACCESS_FS_REFER | \
	LANDLOCK_ACCESS_FS_TRUNCATE | \
	LANDLOCK_ACCESS_FS_IOCTL_DEV)

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <command> [args...]\n\n", prog);
	fprintf(stderr, "Run a command with Landlock supervision.\n");
	fprintf(stderr, "The supervisor will prompt for access decisions.\n\n");
	fprintf(stderr, "Example:\n");
	fprintf(stderr, "  %s sh -c 'ls /tmp'\n", prog);
}

int main(int argc, char **argv)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = ACCESS_FS_ALL,
	};
	struct landlock_supervisor_event *event;
	struct landlock_supervisor_response response;
	char event_buf[sizeof(*event) + 4096];
	int ruleset_fd, ret, status;
	pid_t child_pid;
	struct pollfd pfd;
	char answer;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	/* Create supervisor-enabled ruleset */
	ruleset_fd = landlock_create_ruleset(&ruleset_attr,
					     sizeof(ruleset_attr),
					     LANDLOCK_CREATE_RULESET_SUPERVISOR);
	if (ruleset_fd < 0) {
		perror("landlock_create_ruleset");
		return 1;
	}

	/* Add a restrictive rule (deny everything by default) */
	/* In real usage, you'd add rules for paths from environment */

	/* Fork child process */
	child_pid = fork();
	if (child_pid < 0) {
		perror("fork");
		close(ruleset_fd);
		return 1;
	}

	if (child_pid == 0) {
		/* Child: apply ruleset and exec command */
		if (landlock_restrict_self(ruleset_fd, 0) != 0) {
			perror("landlock_restrict_self");
			return 1;
		}
		close(ruleset_fd);

		/* Close standard fds after all error handling */
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);

		execvp(argv[1], &argv[1]);
		/* Cannot use perror here as stderr is closed */
		return 1;
	}

	/* Parent: supervise access requests */
	printf("Supervisor started for PID %d\n", child_pid);

	pfd.fd = ruleset_fd;
	pfd.events = POLLIN;

	event = (struct landlock_supervisor_event *)event_buf;

	while (1) {
		/* Check if child has exited */
		ret = waitpid(child_pid, &status, WNOHANG);
		if (ret > 0) {
			printf("Child exited with status %d\n",
			       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
			break;
		}

		/* Poll for events */
		ret = poll(&pfd, 1, 100);
		if (ret < 0) {
			perror("poll");
			break;
		}
		if (ret == 0)
			continue;

		if (!(pfd.revents & POLLIN))
			continue;

		/* Read event */
		ret = read(ruleset_fd, event_buf, sizeof(event_buf));
		if (ret < 0) {
			if (errno == EAGAIN)
				continue;
			perror("read");
			break;
		}

		/* Display event and prompt */
		printf("\n[PID %u wants access 0x%llx on %s]\n",
		       event->pid, event->access, event->path);
		printf("Allow? (y/n/a(lways)): ");
		fflush(stdout);

		answer = getchar();
		if (answer != '\n')
			while (getchar() != '\n')
				; /* consume rest of line */

		/* Respond */
		response.id = event->id;
		response.reserved = 0;

		switch (answer) {
		case 'y':
		case 'Y':
			response.flags = LANDLOCK_SUPERVISOR_ALLOW;
			printf("Allowed.\n");
			break;
		case 'a':
		case 'A':
			response.flags = LANDLOCK_SUPERVISOR_ALLOW |
					 LANDLOCK_SUPERVISOR_CACHE_EXEC;
			printf("Allowed (cached for executable).\n");
			break;
		default:
			response.flags = LANDLOCK_SUPERVISOR_DENY;
			printf("Denied.\n");
			break;
		}

		ret = write(ruleset_fd, &response, sizeof(response));
		if (ret < 0) {
			perror("write");
			break;
		}
	}

	close(ruleset_fd);
	return 0;
}
