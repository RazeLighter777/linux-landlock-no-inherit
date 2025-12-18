// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - Supervisor support
 *
 * Copyright © 2025 Contributors
 */

#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "supervisor.h"
#include "ruleset.h"

/**
 * landlock_supervisor_init - Initialize a supervisor
 * @supervisor: Supervisor structure to initialize
 *
 * Returns 0 on success, negative error code on failure.
 */
int landlock_supervisor_init(struct landlock_supervisor *supervisor)
{
	if (!supervisor)
		return -EINVAL;

	supervisor->enabled = true;
	spin_lock_init(&supervisor->lock);
	supervisor->next_id = 1;
	INIT_LIST_HEAD(&supervisor->pending_requests);
	init_waitqueue_head(&supervisor->wait_queue);
	supervisor->eventfd_ctx = NULL;

	return 0;
}

/**
 * landlock_supervisor_destroy - Clean up supervisor resources
 * @supervisor: Supervisor structure to destroy
 */
void landlock_supervisor_destroy(struct landlock_supervisor *supervisor)
{
	struct landlock_supervisor_request *req, *tmp;
	unsigned long flags;

	if (!supervisor || !supervisor->enabled)
		return;

	spin_lock_irqsave(&supervisor->lock, flags);

	/* Wake up and clean pending requests */
	list_for_each_entry_safe(req, tmp, &supervisor->pending_requests, list) {
		list_del(&req->list);
		req->response_received = true;
		req->allow = false;
		wake_up(&req->wait);
		kfree(req->path);
		kfree(req);
	}

	if (supervisor->eventfd_ctx) {
		eventfd_ctx_put(supervisor->eventfd_ctx);
		supervisor->eventfd_ctx = NULL;
	}

	supervisor->enabled = false;
	spin_unlock_irqrestore(&supervisor->lock, flags);
}

/**
 * landlock_supervisor_check - Check access with supervisor
 * @ruleset: Ruleset with supervisor enabled
 * @path: Path being accessed
 * @access: Access rights requested
 *
 * Returns 0 if allowed, negative error code if denied.
 */
int landlock_supervisor_check(struct landlock_ruleset *ruleset,
			      const char *path, u64 access)
{
	struct landlock_supervisor *supervisor;
	struct landlock_supervisor_request *req;
	unsigned long flags;
	int ret;
	bool allow;

	if (!ruleset)
		return -EINVAL;

	supervisor = ruleset->supervisor;
	if (!supervisor || !supervisor->enabled)
		return 0; /* No supervisor, allow by default */

	/* Allocate request */
	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->path = kstrdup(path, GFP_KERNEL);
	if (!req->path) {
		kfree(req);
		return -ENOMEM;
	}

	req->path_len = strlen(path) + 1;
	req->pid = task_pid_nr(current);
	req->access = access;
	req->response_received = false;
	init_waitqueue_head(&req->wait);

	spin_lock_irqsave(&supervisor->lock, flags);
	req->id = supervisor->next_id++;
	list_add_tail(&req->list, &supervisor->pending_requests);
	spin_unlock_irqrestore(&supervisor->lock, flags);

	/* Wake up supervisor (poll/read) */
	wake_up_interruptible(&supervisor->wait_queue);

	/* Notify via eventfd if configured */
	if (supervisor->eventfd_ctx)
		eventfd_signal(supervisor->eventfd_ctx);

	/* Wait for response */
	ret = wait_event_interruptible(req->wait, req->response_received);

	/* Remove from list and get decision before freeing */
	spin_lock_irqsave(&supervisor->lock, flags);
	if (!list_empty(&req->list))
		list_del(&req->list);
	allow = req->allow;
	spin_unlock_irqrestore(&supervisor->lock, flags);

	kfree(req->path);
	kfree(req);

	if (ret < 0)
		return ret; /* Interrupted by signal */

	return allow ? 0 : -EACCES;
}
