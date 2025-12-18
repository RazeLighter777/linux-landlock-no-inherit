/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - Supervisor support
 *
 * Copyright © 2025 Contributors
 */

#ifndef _SECURITY_LANDLOCK_SUPERVISOR_H
#define _SECURITY_LANDLOCK_SUPERVISOR_H

#include <linux/eventfd.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

struct landlock_ruleset;

/**
 * struct landlock_supervisor_request - Pending supervisor request
 */
struct landlock_supervisor_request {
	/**
	 * @list: Entry in the supervisor's pending request list.
	 */
	struct list_head list;
	/**
	 * @id: Unique identifier for this request.
	 */
	u64 id;
	/**
	 * @pid: Process ID making the request.
	 */
	pid_t pid;
	/**
	 * @access: Requested access rights.
	 */
	u64 access;
	/**
	 * @path: Path being accessed (allocated).
	 */
	char *path;
	/**
	 * @path_len: Length of the path.
	 */
	size_t path_len;
	/**
	 * @response_received: Indicates if response was received.
	 */
	bool response_received;
	/**
	 * @allow: Decision from supervisor (true = allow, false = deny).
	 */
	bool allow;
	/**
	 * @wait: Wait queue for this request.
	 */
	wait_queue_head_t wait;
};

/**
 * struct landlock_supervisor - Supervisor state for a ruleset
 */
struct landlock_supervisor {
	/**
	 * @enabled: Whether supervisor mode is enabled.
	 */
	bool enabled;
	/**
	 * @lock: Protects supervisor state and request list.
	 */
	spinlock_t lock;
	/**
	 * @next_id: Next request ID to assign.
	 */
	u64 next_id;
	/**
	 * @pending_requests: List of pending supervisor requests.
	 */
	struct list_head pending_requests;
	/**
	 * @wait_queue: Wait queue for poll() support.
	 */
	wait_queue_head_t wait_queue;
	/**
	 * @eventfd_ctx: Optional eventfd context for notifications.
	 */
	struct eventfd_ctx *eventfd_ctx;
};

int landlock_supervisor_init(struct landlock_supervisor *supervisor);
void landlock_supervisor_destroy(struct landlock_supervisor *supervisor);
int landlock_supervisor_check(struct landlock_ruleset *ruleset,
			      const char *path, u64 access);

#endif /* _SECURITY_LANDLOCK_SUPERVISOR_H */
