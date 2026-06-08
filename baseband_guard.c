#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/namei.h>
#include <linux/blk_types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/dcache.h>
#include <linux/spinlock.h>

/*
 * Explicitly NOT including <linux/lsm_hooks.h> here to avoid redefinition of
 * security_add_hooks on some Android kernels where it's already in security.h
 */

#include "kernel_compat.h"
#include "baseband_guard.h"

/* -------------------------------------------------------------------------
 * 1. Global Identity & Security Cache
 * ------------------------------------------------------------------------- */
static dev_t bbg_boot_dev = 0, bbg_rec_dev = 0, bbg_vboot_dev = 0, bbg_persist_dev = 0;
static unsigned long bbg_recovery_ino = 0, bbg_reboot_ino = 0;
static dev_t bbg_byname_dev = 0;
static unsigned long bbg_byname_ino = 0;

#define BBG_MAX_UNTRUSTED_SIDS 64
static u32 bbg_untrusted_sids[BBG_MAX_UNTRUSTED_SIDS];
static int bbg_untrusted_sid_cnt = 0;
static DEFINE_SPINLOCK(bbg_sid_lock);

/* -------------------------------------------------------------------------
 * 2. SID Management (Blob-less Tracking)
 * ------------------------------------------------------------------------- */

static bool is_sid_untrusted(u32 sid) {
    int i;
    bool found = false;
    unsigned long flags;

    if (sid == 0) return false;

    spin_lock_irqsave(&bbg_sid_lock, flags);
    for (i = 0; i < bbg_untrusted_sid_cnt; i++) {
        if (bbg_untrusted_sids[i] == sid) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&bbg_sid_lock, flags);
    return found;
}

static void add_untrusted_sid(u32 sid) {
    unsigned long flags;
    int i;

    if (sid == 0) return;

    spin_lock_irqsave(&bbg_sid_lock, flags);
    for (i = 0; i < bbg_untrusted_sid_cnt; i++) {
        if (bbg_untrusted_sids[i] == sid) {
            spin_unlock_irqrestore(&bbg_sid_lock, flags);
            return;
        }
    }

    if (bbg_untrusted_sid_cnt < BBG_MAX_UNTRUSTED_SIDS) {
        bbg_untrusted_sids[bbg_untrusted_sid_cnt++] = sid;
    }
    spin_unlock_irqrestore(&bbg_sid_lock, flags);
}

/* -------------------------------------------------------------------------
 * 3. Internal Helpers
 * ------------------------------------------------------------------------- */

static bool inline resolve_byname_dev(const char *name, dev_t *out) {
    char *path;
    dev_t dev;
    int ret;
    if (!name || !out) return false;
    path = kasprintf(GFP_KERNEL, "%s/%s", BB_BYNAME_DIR, name);
    if (!path) return false;
    ret = lookup_bdev_compat(path, &dev);
    kfree(path);
    if (ret) return false;
    *out = dev;
    return true;
}

static void bbg_resolve_identities(void) {
    struct path path;
    const char *bins[] = {"/system/bin/recovery", "/system/bin/reboot"};
    unsigned long *inos[] = {&bbg_recovery_ino, &bbg_reboot_ino};
    int i;

    for (i = 0; i < 2; i++) {
        if (*inos[i] == 0 && kern_path(bins[i], LOOKUP_FOLLOW, &path) == 0) {
            struct inode *inode = d_backing_inode(path.dentry);
            if (inode) *inos[i] = inode->i_ino;
            path_put(&path);
        }
    }

#ifdef CONFIG_BBG_BLOCK_BOOT
    if (!bbg_boot_dev) resolve_byname_dev("boot", &bbg_boot_dev);
    if (!bbg_vboot_dev) resolve_byname_dev("vendor_boot", &bbg_vboot_dev);
#endif
#ifdef CONFIG_BBG_BLOCK_RECOVERY
    if (!bbg_rec_dev) resolve_byname_dev("recovery", &bbg_rec_dev);
#endif
#ifdef CONFIG_BBG_BLOCK_PERSIST
    if (!bbg_persist_dev) resolve_byname_dev("persist", &bbg_persist_dev);
#endif

    if (bbg_byname_ino == 0 && kern_path(BB_BYNAME_DIR, LOOKUP_FOLLOW, &path) == 0) {
        struct inode *inode = d_backing_inode(path.dentry);
        if (inode) {
            bbg_byname_dev = inode->i_sb->s_dev;
            bbg_byname_ino = inode->i_ino;
        }
        path_put(&path);
    }
}

static int deny(const char *why, struct file *file, struct inode *inode, unsigned int cmd_opt) {
    bb_pr_rl("baseband_guard: deny %s (pid=%d, comm=%s)\n", why, current->pid, current->comm);
    return -EPERM;
}

/* -------------------------------------------------------------------------
 * 4. Atomic-Safe Hooks
 * ------------------------------------------------------------------------- */

static int bb_file_permission(struct file *file, int mask) {
    struct inode *inode;
    dev_t rdev;
    u32 sid;

    if (!(mask & (MAY_WRITE | MAY_APPEND | MAY_READ))) return 0;
    if (unlikely(!file)) return 0;

    inode = file_inode(file);
    if (likely(!S_ISBLK(inode->i_mode))) return 0;

    security_cred_getsecid(current_cred(), &sid);

    if (unlikely(is_sid_untrusted(sid))) {
        rdev = inode->i_rdev;

        if (mask & (MAY_WRITE | MAY_APPEND)) {
            return deny("write to block device", file, inode, 0);
        }

        if (mask & MAY_READ) {
            if ((bbg_boot_dev && rdev == bbg_boot_dev) || (bbg_rec_dev && rdev == bbg_rec_dev) ||
                (bbg_vboot_dev && rdev == bbg_vboot_dev) || (bbg_persist_dev && rdev == bbg_persist_dev)) {
                return deny("read of sensitive partition raw data", file, inode, 0);
            }
        }
    }

    return 0;
}

static int bb_bprm_check_security(struct linux_binprm *bprm) {
    struct inode *inode;
    u32 sid;
    char *secdata = NULL;
    u32 seclen = 0;

    if (unlikely(!bprm || !bprm->file)) return 0;

    security_cred_getsecid(bprm->cred, &sid);

    if (sid != 0 && !is_sid_untrusted(sid)) {
        if (security_secid_to_secctx(sid, &secdata, &seclen) == 0) {
            if (secdata) {
                if (strstr(secdata, ":su") || strstr(secdata, "magisk") ||
                    strstr(secdata, "ksu") || strstr(secdata, "apatch")) {
                    add_untrusted_sid(sid);
                    pr_info("baseband_guard: domain %s marked as untrusted\n", secdata);
                }
                security_release_secctx(secdata, seclen);
            }
        }
    }

    if (is_sid_untrusted(sid)) {
        inode = file_inode(bprm->file);

        if (unlikely(bbg_recovery_ino && inode->i_ino == bbg_recovery_ino))
            return deny("execution of recovery binary", NULL, NULL, 0);

        if (unlikely(bbg_reboot_ino && inode->i_ino == bbg_reboot_ino))
            return deny("execution of reboot binary by untrusted process", NULL, NULL, 0);

        if (strstr(bprm->filename, "wipe") || strstr(bprm->filename, "erase") ||
            strstr(bprm->filename, "fdisk") || strstr(bprm->filename, "sgdisk") ||
            strstr(bprm->filename, "kpatch") || strstr(bprm->filename, "insmod")) {
            return deny("execution of restricted tool", NULL, NULL, 0);
        }
    }

    return 0;
}

static int bb_inode_unlink(struct inode *dir, struct dentry *dentry) {
    u32 sid;
    security_cred_getsecid(current_cred(), &sid);
    if (likely(!is_sid_untrusted(sid))) return 0;

    if (unlikely(is_bb_byname_dir(dir)) || is_protected_blkdev_node(dentry))
        return deny("unlink of protected block node", 0, d_inode(dentry), 0);
    return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && defined(CONFIG_ANDROID)) || (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0))
static int bb_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                           struct inode *new_dir, struct dentry *new_dentry,
                           unsigned int flags)
#else
static int bb_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                           struct inode *new_dir, struct dentry *new_dentry)
#endif
{
    u32 sid;
    security_cred_getsecid(current_cred(), &sid);
    if (likely(!is_sid_untrusted(sid))) return 0;

    if (is_protected_blkdev_node(old_dentry))
        return deny("rename of protected block node", 0, d_inode(old_dentry), 0);
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static int bb_inode_setattr(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *iattr)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0) && !defined(CONFIG_ANDROID)
static int bb_inode_setattr(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *iattr)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0) && !defined(CONFIG_ANDROID)
static int bb_inode_setattr(struct user_namespace *mnt_userns, struct dentry *dentry, struct iattr *iattr)
#else
static int bb_inode_setattr(struct dentry *dentry, struct iattr *iattr)
#endif
{
    u32 sid;
    security_cred_getsecid(current_cred(), &sid);
    if (likely(!is_sid_untrusted(sid))) return 0;

    if (is_protected_blkdev_node(dentry))
        return deny("modification of partition attributes", 0, d_inode(dentry), 0);
    return 0;
}

static int bb_ptrace_access_check(struct task_struct *child, unsigned int mode) {
    u32 sid;
    security_cred_getsecid(current_cred(), &sid);
    if (likely(!is_sid_untrusted(sid))) return 0;
    return deny("ptrace access check", NULL, NULL, 0);
}

static int bb_ptrace_traceme(struct task_struct *parent) {
    u32 sid;
    security_cred_getsecid(current_cred(), &sid);
    if (likely(!is_sid_untrusted(sid))) return 0;
    return deny("ptrace traceme", NULL, NULL, 0);
}

/* -------------------------------------------------------------------------
 * 5. Structural Protection Logic
 * ------------------------------------------------------------------------- */

static int is_bb_byname_dir(struct inode *dir) {
    if (bbg_byname_ino == 0) return 0;
    return (dir->i_ino == bbg_byname_ino && dir->i_sb->s_dev == bbg_byname_dev);
}

static inline int is_protected_blkdev_node(struct dentry *dentry) {
    struct inode *inode;
    if (!dentry) return 0;
    inode = d_backing_inode(dentry);
    if (!inode) return 0;
    if (S_ISBLK(inode->i_mode)) return 1;
    if (S_ISLNK(inode->i_mode) && dentry->d_name.name && strstr(dentry->d_name.name, "sd")) return 1;
    return 0;
}

/* -------------------------------------------------------------------------
 * 6. Lifecycle Management
 * ------------------------------------------------------------------------- */

static struct security_hook_list bb_hooks[] = {
    { .hook = { .file_permission = bb_file_permission }, .head = &security_hook_heads.file_permission },
    { .hook = { .inode_setattr = bb_inode_setattr }, .head = &security_hook_heads.inode_setattr },
    { .hook = { .inode_rename = bb_inode_rename }, .head = &security_hook_heads.inode_rename },
    { .hook = { .inode_unlink = bb_inode_unlink }, .head = &security_hook_heads.inode_unlink },
    { .hook = { .ptrace_access_check = bb_ptrace_access_check }, .head = &security_hook_heads.ptrace_access_check },
    { .hook = { .ptrace_traceme = bb_ptrace_traceme }, .head = &security_hook_heads.ptrace_traceme },
    { .hook = { .bprm_check_security = bb_bprm_check_security }, .head = &security_hook_heads.bprm_check_security },
};

static int __init bbg_init(void) {
    bbg_resolve_identities();
    security_add_hooks_compat(bb_hooks, ARRAY_SIZE(bb_hooks));
    pr_info("baseband_guard: Iron Fortress (Blob-less) active\n");
    return 0;
}

#ifndef BBG_USE_DEFINE_LSM
late_initcall(bbg_init);
#else
DEFINE_LSM(baseband_guard) = { .name = "baseband_guard", .init = bbg_init };

static int __init bbg_late_init(void) {
    bbg_resolve_identities();
    return 0;
}
late_initcall(bbg_late_init);
#endif

MODULE_DESCRIPTION("Baseband-guard: Kernel-Integrated Blob-less Protection");
MODULE_AUTHOR("Baseband-guard Team");
MODULE_LICENSE("GPL v2");
