// SPDX-License-Identifier: GPL-2.0
/* Provide mount topology/attribute change notifications.
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/security.h>
#include "mount.h"

/*
 * Post mount notifications to all watches going rootwards along the tree.
 *
 * Must be called with the mount_lock held.
 */
static void post_mount_notification(struct mount *changed,
				    struct mount_notification *notify)
{
	const struct cred *cred = current_cred();
	struct path cursor;
	struct mount *mnt;
	unsigned seq;

	seq = 0;
	rcu_read_lock();
restart:
	cursor.mnt = &changed->mnt;
	cursor.dentry = changed->mnt.mnt_root;
	mnt = real_mount(cursor.mnt);
	notify->watch.info &= ~NOTIFY_MOUNT_IN_SUBTREE;

	read_seqbegin_or_lock(&rename_lock, &seq);
	for (;;) {
		if (mnt->mnt_watchers &&
		    !hlist_empty(&mnt->mnt_watchers->watchers)) {
			if (cursor.dentry->d_flags & DCACHE_MOUNT_WATCH)
				post_watch_notification(mnt->mnt_watchers,
							&notify->watch, cred,
							(unsigned long)cursor.dentry);
		} else {
			cursor.dentry = mnt->mnt.mnt_root;
		}
		notify->watch.info |= NOTIFY_MOUNT_IN_SUBTREE;

		if (cursor.dentry == cursor.mnt->mnt_root ||
		    IS_ROOT(cursor.dentry)) {
			struct mount *parent = READ_ONCE(mnt->mnt_parent);

			/* Escaped? */
			if (cursor.dentry != cursor.mnt->mnt_root)
				break;

			/* Global root? */
			if (mnt == parent)
				break;

			cursor.dentry = READ_ONCE(mnt->mnt_mountpoint);
			mnt = parent;
			cursor.mnt = &mnt->mnt;
		} else {
			cursor.dentry = cursor.dentry->d_parent;
		}
	}

	if (need_seqretry(&rename_lock, seq)) {
		seq = 1;
		goto restart;
	}

	done_seqretry(&rename_lock, seq);
	rcu_read_unlock();
}

/*
 * Generate a mount notification.
 */
void notify_mount(struct mount *trigger,
		  struct mount *aux,
		  enum mount_notification_subtype subtype,
		  u32 info_flags)
{

	struct mount_notification n;

	memset(&n, 0, sizeof(n));
	n.watch.type	= WATCH_TYPE_MOUNT_NOTIFY;
	n.watch.subtype	= subtype;
	n.watch.info	= info_flags | watch_sizeof(n);
	n.triggered_on	= trigger->mnt_id;

	switch (subtype) {
	case NOTIFY_MOUNT_EXPIRY:
	case NOTIFY_MOUNT_READONLY:
	case NOTIFY_MOUNT_SETATTR:
		break;

	case NOTIFY_MOUNT_NEW_MOUNT:
	case NOTIFY_MOUNT_UNMOUNT:
	case NOTIFY_MOUNT_MOVE_FROM:
	case NOTIFY_MOUNT_MOVE_TO:
		n.auxiliary_mount	= aux->mnt_id;
		break;

	default:
		BUG();
	}

	post_mount_notification(trigger, &n);
}

static void release_mount_watch(struct watch *watch)
{
	struct dentry *dentry = (struct dentry *)(unsigned long)watch->id;

	dput(dentry);
}

/**
 * sys_watch_mount - Watch for mount topology/attribute changes
 * @dfd: Base directory to pathwalk from or fd referring to mount.
 * @filename: Path to mount to place the watch upon
 * @at_flags: Pathwalk control flags
 * @watch_fd: The watch queue to send notifications to.
 * @watch_id: The watch ID to be placed in the notification (-1 to remove watch)
 */
SYSCALL_DEFINE5(watch_mount,
		int, dfd,
		const char __user *, filename,
		unsigned int, at_flags,
		int, watch_fd,
		int, watch_id)
{
	struct watch_queue *wqueue;
	struct watch_list *wlist = NULL;
	struct watch *watch = NULL;
	struct mount *m;
	struct path path;
	unsigned int lookup_flags =
		LOOKUP_DIRECTORY | LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;
	int ret;

	if (watch_id < -1 || watch_id > 0xff)
		return -EINVAL;
	if ((at_flags & ~(AT_NO_AUTOMOUNT | AT_EMPTY_PATH)) != 0)
		return -EINVAL;
	if (at_flags & AT_NO_AUTOMOUNT)
		lookup_flags &= ~LOOKUP_AUTOMOUNT;
	if (at_flags & AT_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;

	ret = user_path_at(dfd, filename, lookup_flags, &path);
	if (ret)
		return ret;

	ret = inode_permission(path.dentry->d_inode, MAY_EXEC);
	if (ret)
		goto err_path;

	wqueue = get_watch_queue(watch_fd);
	if (IS_ERR(wqueue))
		goto err_path;

	m = real_mount(path.mnt);

	if (watch_id >= 0) {
		ret = -ENOMEM;
		if (!READ_ONCE(m->mnt_watchers)) {
			wlist = kzalloc(sizeof(*wlist), GFP_KERNEL);
			if (!wlist)
				goto err_wqueue;
			init_watch_list(wlist, release_mount_watch);
		}

		watch = kzalloc(sizeof(*watch), GFP_KERNEL);
		if (!watch)
			goto err_wlist;

		init_watch(watch, wqueue);
		watch->id	= (unsigned long)path.dentry;
		watch->info_id	= (u32)watch_id << WATCH_INFO_ID__SHIFT;

		ret = security_watch_mount(watch, &path);
		if (ret < 0)
			goto err_watch;

		down_write(&m->mnt.mnt_sb->s_umount);
		if (!m->mnt_watchers) {
			m->mnt_watchers = wlist;
			wlist = NULL;
		}

		ret = add_watch_to_object(watch, m->mnt_watchers);
		if (ret == 0) {
			spin_lock(&path.dentry->d_lock);
			path.dentry->d_flags |= DCACHE_MOUNT_WATCH;
			spin_unlock(&path.dentry->d_lock);
			dget(path.dentry);
			watch = NULL;
		}
		up_write(&m->mnt.mnt_sb->s_umount);
	} else {
		down_write(&m->mnt.mnt_sb->s_umount);
		ret = remove_watch_from_object(m->mnt_watchers, wqueue,
					       (unsigned long)path.dentry,
					       false);
		up_write(&m->mnt.mnt_sb->s_umount);
	}

err_watch:
	kfree(watch);
err_wlist:
	kfree(wlist);
err_wqueue:
	put_watch_queue(wqueue);
err_path:
	path_put(&path);
	return ret;
}
