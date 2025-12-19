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
struct task_struct;
struct dentry;

/**
 * enum landlock_supervisor_match_type - Cache entry match type
 */
enum landlock_supervisor_match_type {
	LANDLOCK_MATCH_PID = 1,
	LANDLOCK_MATCH_PID_SUBTREE,
	LANDLOCK_MATCH_EXEC,
	LANDLOCK_MATCH_EXEC_SUBTREE,
	LANDLOCK_MATCH_ALL,
};

/**
 * struct landlock_supervisor_cache - Cache entry for pre-approved access
 */
struct landlock_supervisor_cache {
	/**
	 * @list: Entry in supervisor's cache list.
	 */
	struct list_head list;
	/**
	 * @id: Unique cache entry ID.
	 */
	u64 id;
	/**
	 * @ruleset: Single-layer ruleset for this cache entry.
	 */
	struct landlock_ruleset *ruleset;
	/**
	 * @match_type: Type of matching for this entry.
	 */
	enum landlock_supervisor_match_type match_type;
	/**
	 * @task: Task structure for PID-based matching (holds reference).
	 */
	struct task_struct *task;
	/**
	 * @exec_dentry: Dentry for executable-based matching (holds reference).
	 */
	struct dentry *exec_dentry;
};

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
	/**
	 * @cache_list: List of cache entries.
	 */
	struct list_head cache_list;
	/**
	 * @next_cache_id: Next cache entry ID to assign.
	 */
	u64 next_cache_id;
};

int landlock_supervisor_init(struct landlock_supervisor *supervisor);
void landlock_supervisor_destroy(struct landlock_supervisor *supervisor);
int landlock_supervisor_check(struct landlock_ruleset *ruleset,
			      const char *path, u64 access);
long landlock_supervisor_ioctl(struct landlock_ruleset *ruleset,
			       unsigned int cmd, unsigned long arg);

/* Helper to get ruleset from fd (from syscalls.c) */
struct landlock_ruleset *get_ruleset_from_fd(const int fd,
					     const fmode_t mode);

#endif /* _SECURITY_LANDLOCK_SUPERVISOR_H */
