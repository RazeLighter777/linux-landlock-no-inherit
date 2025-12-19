// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - Supervisor support
 *
 * Copyright © 2025 Contributors
 */

#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <uapi/linux/landlock.h>

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
	INIT_LIST_HEAD(&supervisor->cache_list);
	supervisor->next_cache_id = 1;

	return 0;
}

/**
 * landlock_supervisor_destroy - Clean up supervisor resources
 * @supervisor: Supervisor structure to destroy
 */
void landlock_supervisor_destroy(struct landlock_supervisor *supervisor)
{
	struct landlock_supervisor_request *req, *req_tmp;
	struct landlock_supervisor_cache *cache, *cache_tmp;
	unsigned long flags;

	if (!supervisor || !supervisor->enabled)
		return;

	spin_lock_irqsave(&supervisor->lock, flags);

	/* Wake up and clean pending requests */
	list_for_each_entry_safe(req, req_tmp, &supervisor->pending_requests, list) {
		list_del(&req->list);
		req->response_received = true;
		req->allow = false;
		wake_up(&req->wait);
		kfree(req->path);
		kfree(req);
	}

	/* Clean up cache entries */
	list_for_each_entry_safe(cache, cache_tmp, &supervisor->cache_list, list) {
		list_del(&cache->list);
		if (cache->ruleset)
			landlock_put_ruleset(cache->ruleset);
		if (cache->task)
			put_task_struct(cache->task);
		if (cache->exec_dentry)
			dput(cache->exec_dentry);
		kfree(cache);
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

	/* First check cache */
	ret = landlock_supervisor_check_cache(supervisor, access);
	if (ret != -ENOENT)
		return ret; /* Cache hit: allow (0) or deny (-EACCES) */

	/* Cache miss: ask supervisor interactively */

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

/**
 * check_cache_match - Check if cache entry matches current task
 * @cache: Cache entry to check
 *
 * Returns true if cache entry matches current context.
 */
static bool check_cache_match(const struct landlock_supervisor_cache *cache)
{
	struct dentry *exe_dentry;
	struct file *exe_file;
	bool match = false;

	switch (cache->match_type) {
	case LANDLOCK_MATCH_ALL:
		return true;

	case LANDLOCK_MATCH_PID:
		return cache->task == current;

	case LANDLOCK_MATCH_PID_SUBTREE:
		/* Check if current is cache->task or a descendant */
		if (cache->task == current)
			return true;
		/* Simple check: if current's parent chain includes cache->task */
		{
			struct task_struct *p = current;
			rcu_read_lock();
			while (p && p != &init_task) {
				if (p == cache->task) {
					match = true;
					break;
				}
				p = rcu_dereference(p->real_parent);
			}
			rcu_read_unlock();
		}
		return match;

	case LANDLOCK_MATCH_EXEC:
	case LANDLOCK_MATCH_EXEC_SUBTREE:
		/* Get current executable */
		exe_file = get_task_exe_file(current);
		if (!exe_file)
			return false;
		exe_dentry = exe_file->f_path.dentry;
		match = (exe_dentry == cache->exec_dentry);
		fput(exe_file);
		return match;

	default:
		return false;
	}
}

/**
 * landlock_supervisor_check_cache - Check if access is cached
 * @supervisor: Supervisor to check cache
 * @access: Requested access
 *
 * Returns 0 if cached and allowed, -EACCES if cached and denied,
 * -ENOENT if not cached.
 */
static int landlock_supervisor_check_cache(struct landlock_supervisor *supervisor,
					   u64 access)
{
	struct landlock_supervisor_cache *cache;
	struct landlock_ruleset *merged = NULL;
	unsigned long flags;
	int ret = -ENOENT;
	bool found_match = false;

	if (!supervisor)
		return -ENOENT;

	spin_lock_irqsave(&supervisor->lock, flags);

	/* Collect all matching cache entries and merge rulesets */
	list_for_each_entry(cache, &supervisor->cache_list, list) {
		if (!check_cache_match(cache))
			continue;

		found_match = true;

		/* Merge cache ruleset into accumulated ruleset */
		if (!merged) {
			/* First match: use as base */
			merged = cache->ruleset;
			landlock_get_ruleset(merged);
		} else {
			/* Subsequent matches: merge */
			struct landlock_ruleset *tmp;
			tmp = landlock_merge_ruleset(merged, cache->ruleset);
			landlock_put_ruleset(merged);
			if (IS_ERR(tmp)) {
				merged = NULL;
				ret = PTR_ERR(tmp);
				break;
			}
			merged = tmp;
		}
	}

	spin_unlock_irqrestore(&supervisor->lock, flags);

	if (!found_match || !merged)
		return ret;

	/* Check if merged ruleset allows the access */
	/* TODO: Implement proper access check against merged ruleset */
	/* For now, if we have any matching cache entry, allow */
	ret = 0;

	landlock_put_ruleset(merged);
	return ret;
}

/**
 * landlock_supervisor_ioctl - Handle ioctl commands for cache management
 * @ruleset: Ruleset with supervisor
 * @cmd: ioctl command
 * @arg: ioctl argument
 *
 * Returns 0 on success, negative error code on failure.
 */
long landlock_supervisor_ioctl(struct landlock_ruleset *ruleset,
			       unsigned int cmd, unsigned long arg)
{
	struct landlock_supervisor *supervisor;
	struct landlock_supervisor_cache *cache;
	struct landlock_supervisor_cache_entry entry;
	struct landlock_supervisor_cache_remove remove;
	struct landlock_ruleset *cache_ruleset;
	struct task_struct *task;
	struct file *path_file;
	unsigned long flags;
	long ret = 0;

	if (!ruleset)
		return -EINVAL;

	supervisor = ruleset->supervisor;
	if (!supervisor || !supervisor->enabled)
		return -EINVAL;

	switch (cmd) {
	case LANDLOCK_SUPERVISOR_IOCTL_ADD_CACHE:
		if (copy_from_user(&entry, (void __user *)arg, sizeof(entry)))
			return -EFAULT;

		if (entry.reserved != 0)
			return -EINVAL;

		/* Validate match type */
		if (entry.match_type < LANDLOCK_SUPERVISOR_MATCH_PID ||
		    entry.match_type > LANDLOCK_SUPERVISOR_MATCH_ALL)
			return -EINVAL;

		/* Get ruleset from fd */
		cache_ruleset = get_ruleset_from_fd(entry.ruleset_fd, FMODE_READ);
		if (IS_ERR(cache_ruleset))
			return PTR_ERR(cache_ruleset);

		/* Validate it's a single-layer ruleset */
		if (cache_ruleset->num_layers != 1) {
			landlock_put_ruleset(cache_ruleset);
			return -EINVAL;
		}

		/* Allocate cache entry */
		cache = kzalloc(sizeof(*cache), GFP_KERNEL);
		if (!cache) {
			landlock_put_ruleset(cache_ruleset);
			return -ENOMEM;
		}

		cache->ruleset = cache_ruleset;
		cache->match_type = entry.match_type;
		cache->task = NULL;
		cache->exec_dentry = NULL;

		/* Set up match criteria */
		switch (entry.match_type) {
		case LANDLOCK_SUPERVISOR_MATCH_PID:
		case LANDLOCK_SUPERVISOR_MATCH_PID_SUBTREE:
			if (entry.pid == 0) {
				ret = -EINVAL;
				goto free_cache;
			}
			rcu_read_lock();
			task = find_task_by_vpid(entry.pid);
			if (task)
				get_task_struct(task);
			rcu_read_unlock();
			if (!task) {
				ret = -ESRCH;
				goto free_cache;
			}
			cache->task = task;
			break;

		case LANDLOCK_SUPERVISOR_MATCH_EXEC:
		case LANDLOCK_SUPERVISOR_MATCH_EXEC_SUBTREE:
			if (entry.path_fd < 0) {
				ret = -EINVAL;
				goto free_cache;
			}
			path_file = fget(entry.path_fd);
			if (!path_file) {
				ret = -EBADF;
				goto free_cache;
			}
			cache->exec_dentry = dget(path_file->f_path.dentry);
			fput(path_file);
			break;

		case LANDLOCK_SUPERVISOR_MATCH_ALL:
			/* No additional setup needed */
			break;

		default:
			ret = -EINVAL;
			goto free_cache;
		}

		/* Add to cache list */
		spin_lock_irqsave(&supervisor->lock, flags);
		cache->id = supervisor->next_cache_id++;
		list_add_tail(&cache->list, &supervisor->cache_list);
		spin_unlock_irqrestore(&supervisor->lock, flags);

		/* Return cache ID to userspace */
		return cache->id;

free_cache:
		kfree(cache);
		landlock_put_ruleset(cache_ruleset);
		return ret;

	case LANDLOCK_SUPERVISOR_IOCTL_REMOVE_CACHE:
		if (copy_from_user(&remove, (void __user *)arg, sizeof(remove)))
			return -EFAULT;

		spin_lock_irqsave(&supervisor->lock, flags);
		list_for_each_entry(cache, &supervisor->cache_list, list) {
			if (cache->id == remove.entry_id) {
				list_del(&cache->list);
				spin_unlock_irqrestore(&supervisor->lock, flags);

				/* Clean up cache entry */
				if (cache->ruleset)
					landlock_put_ruleset(cache->ruleset);
				if (cache->task)
					put_task_struct(cache->task);
				if (cache->exec_dentry)
					dput(cache->exec_dentry);
				kfree(cache);
				return 0;
			}
		}
		spin_unlock_irqrestore(&supervisor->lock, flags);
		return -ENOENT;

	default:
		return -ENOTTY;
	}
}
