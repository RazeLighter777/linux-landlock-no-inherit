// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - Supervisor
 *
 * Copyright © 2025 Contributors
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"

/* Test that supervisor flag is recognized */
TEST(supervisor_flag)
{
	int ruleset_fd;
	const struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};

	/* Create ruleset with supervisor flag */
	ruleset_fd = landlock_create_ruleset(&ruleset_attr,
					     sizeof(ruleset_attr),
					     LANDLOCK_CREATE_RULESET_SUPERVISOR);
	ASSERT_LE(0, ruleset_fd);

	/* Verify it's a valid fd */
	ASSERT_EQ(0, fcntl(ruleset_fd, F_GETFD));

	close(ruleset_fd);
}

/* Test that invalid flags are rejected */
TEST(supervisor_invalid_flags)
{
	const struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};

	/* Invalid flag combination */
	ASSERT_EQ(-1, landlock_create_ruleset(
			      &ruleset_attr, sizeof(ruleset_attr),
			      LANDLOCK_CREATE_RULESET_SUPERVISOR | (1U << 31)));
	ASSERT_EQ(EINVAL, errno);
}

/* Test basic supervisor read/write operations */
TEST(supervisor_basic_io)
{
	int ruleset_fd;
	struct landlock_supervisor_event event;
	struct landlock_supervisor_response response;
	const struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};

	/* Create supervisor-enabled ruleset */
	ruleset_fd = landlock_create_ruleset(&ruleset_attr,
					     sizeof(ruleset_attr),
					     LANDLOCK_CREATE_RULESET_SUPERVISOR);
	ASSERT_LE(0, ruleset_fd);

	/* Initially, read should return -EAGAIN (no pending requests) */
	ASSERT_EQ(-1, read(ruleset_fd, &event, sizeof(event)));
	ASSERT_EQ(EAGAIN, errno);

	/* Write without pending request should fail */
	response.id = 1;
	response.flags = LANDLOCK_SUPERVISOR_ALLOW;
	response.reserved = 0;
	ASSERT_EQ(-1, write(ruleset_fd, &response, sizeof(response)));
	ASSERT_EQ(ENOENT, errno);

	close(ruleset_fd);
}

/* Test poll() support on supervisor fd */
TEST(supervisor_poll)
{
	int ruleset_fd;
	struct pollfd pfd;
	const struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};

	/* Create supervisor-enabled ruleset */
	ruleset_fd = landlock_create_ruleset(&ruleset_attr,
					     sizeof(ruleset_attr),
					     LANDLOCK_CREATE_RULESET_SUPERVISOR);
	ASSERT_LE(0, ruleset_fd);

	/* Poll should indicate writable but not readable (no events) */
	pfd.fd = ruleset_fd;
	pfd.events = POLLIN | POLLOUT;
	pfd.revents = 0;

	ASSERT_EQ(1, poll(&pfd, 1, 0));
	ASSERT_EQ(POLLOUT, pfd.revents);

	close(ruleset_fd);
}

/* Test that normal ruleset (without supervisor) can't be used for supervisor ops */
TEST(supervisor_not_enabled)
{
	int ruleset_fd;
	struct landlock_supervisor_event event;
	const struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};

	/* Create normal ruleset without supervisor flag */
	ruleset_fd = landlock_create_ruleset(&ruleset_attr,
					     sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);

	/* Read should fail because supervisor is not enabled */
	ASSERT_EQ(-1, read(ruleset_fd, &event, sizeof(event)));
	ASSERT_EQ(EINVAL, errno);

	close(ruleset_fd);
}

TEST_HARNESS_MAIN
