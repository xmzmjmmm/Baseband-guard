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
#include <linux/dcache.h>
#include <linux/hashtable.h>

#include "kernel_compat.h"
#include "baseband_guard.h"
#include "tracing/tracing.h"

extern char *saved_command_line;

/* -------------------------------------------------------------------------
 * 1. Global Identity Cache (Path-Independent)
 * ------------------------------------------------------------------------- */
static dev_t bbg_boot_dev = 0, bbg_rec_dev = 0, bbg_vboot_dev = 0, bbg_persist_dev = 0;
static unsigned long bbg_recovery_ino = 0, bbg_reboot_ino = 0;

/* -------------------------------------------------------------------------
 * 2. Helper Functions
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
        if (kern_path(bins[i], LOOKUP_FOLLOW, &path) == 0) {
            struct inode *inode = d_backing_inode(path.dentry);
            if (inode) *inos[i] = inode->i_ino;
            path_put(&path);
        }
    }

    resolve_byname_dev("boot", &bbg_boot_dev);
    resolve_byname_dev("recovery", &bbg_rec_dev);
    resolve_byname_dev("vendor_boot", &bbg_vboot_dev);
    resolve_byname_dev("persist", &bbg_persist_dev);
}

static bool is_zram_device(dev_t dev) {
    return bbg_is_named_device(dev, "zram");
}

static int bbg_get_cmdline(char *buf, int buflen) {
    int n, i;
    if (!buf || buflen <= 0) return 0;
    n = get_cmdline(current, buf, buflen);
    if (n <= 0) return 0;
    for (i = 0; i < n - 1; i++) if (buf[i] == '\0') buf[i] = ' ';
    if (n < buflen) buf[n] = '\0';
    else buf[buflen - 1] = '\0';
    return n;
}

static const char *bbg_file_path(struct file *file, char *buf, int buflen) {
    char *p;
    if (!file || !buf || buflen <= 0) return NULL;
    buf[0] = '\0';
    p = d_path(&file->f_path, buf, buflen);
    return IS_ERR(p) ? NULL : p;
}

static int deny(const char *why, struct file *file, struct inode *inode, unsigned int cmd_opt) {
    bb_pr_rl("baseband_guard: deny %s (pid=%d, comm=%s)\n", why, current->pid, current->comm);
    return -EPERM;
}

/* -------------------------------------------------------------------------
 * 3. Core Protection Hooks
 * ------------------------------------------------------------------------- */

static int bb_file_permission(struct file *file, int mask) {
    struct inode *inode;
    dev_t rdev;

    if (!(mask & (MAY_WRITE | MAY_APPEND | MAY_READ))) return 0;
    if (!file) return 0;

    inode = file_inode(file);

    if (!current_process_trusted()) {
        if (!S_ISBLK(inode->i_mode)) {
            char *pathbuf = kmalloc(256, GFP_ATOMIC);
            if (pathbuf) {
                const char *path = bbg_file_path(file, pathbuf, 256);
                if (path) {
                    if ((mask & MAY_WRITE) && strstr(path, "/data/adb")) {
                        kfree(pathbuf);
                        return deny("write to root manager directory", file, inode, 0);
                    }
                    if ((mask & MAY_READ) && strstr(path, "/proc/kallsyms")) {
                        kfree(pathbuf);
                        return deny("read of kernel symbols", file, inode, 0);
                    }
                    if ((mask & MAY_WRITE) && (strstr(path, "/sys/class/backlight") || strstr(path, "/dev/snd"))) {
                        kfree(pathbuf);
                        return deny("sensory harassment attempt", file, inode, 0);
                    }
                }
                kfree(pathbuf);
            }
            return 0;
        }

        rdev = inode->i_rdev;

        if (mask & (MAY_WRITE | MAY_APPEND)) {
            if (is_zram_device(rdev)) return 0;
            return deny("write to block device (sdc/mmc/etc)", file, inode, 0);
        }

        if (mask & MAY_READ) {
            if (unlikely(!bbg_boot_dev)) bbg_resolve_identities();
            if ((bbg_boot_dev && rdev == bbg_boot_dev) || (bbg_rec_dev && rdev == bbg_rec_dev) ||
                (bbg_vboot_dev && rdev == bbg_vboot_dev) || (bbg_persist_dev && rdev == bbg_persist_dev)) {
                return deny("read of sensitive partition raw data", file, inode, 0);
            }
        }
    }

    return 0;
}

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct inode *inode;
    if (!file) return 0;
    inode = file_inode(file);
    if (likely(!S_ISBLK(inode->i_mode))) return 0;

    if (current_process_trusted()) return 0;

    switch (cmd) {
        case BLKDISCARD:
        case BLKSECDISCARD:
        case BLKZEROOUT:
        case BLKROSET:
        case BLKFLSBUF:
#ifdef BLKPG
        case BLKPG:
#endif
#ifdef BLKTRIM
        case BLKTRIM:
#endif
#ifdef BLKRRPART
        case BLKRRPART:
#endif
#ifdef BLKSETRO
        case BLKSETRO:
#endif
            return deny("destructive block ioctl", file, inode, cmd);
        default:
            break;
    }
    return 0;
}

static int bb_bprm_check_security(struct linux_binprm *bprm) {
    struct inode *inode;
    char *cmdbuf;
    bool is_destructive = false;

    if (likely(current_process_trusted())) return 0;

    inode = file_inode(bprm->file);

    if (unlikely(bbg_recovery_ino && inode->i_ino == bbg_recovery_ino))
        return deny("execution of recovery binary", NULL, NULL, 0);

    if (unlikely(bbg_reboot_ino && inode->i_ino == bbg_reboot_ino)) {
        cmdbuf = kmalloc(256, GFP_ATOMIC);
        if (cmdbuf) {
            if (bbg_get_cmdline(cmdbuf, 256) > 0) {
                if (strstr(cmdbuf, "recovery") || strstr(cmdbuf, "wipe") ||
                    strstr(cmdbuf, "erase") || strstr(cmdbuf, "bootloader")) {
                    is_destructive = true;
                }
            }
            kfree(cmdbuf);
        }
        if (is_destructive) return deny("destructive reboot parameters", NULL, NULL, 0);
    }

    if (strstr(bprm->filename, "wipe") || strstr(bprm->filename, "erase") ||
        strstr(bprm->filename, "format") || strstr(bprm->filename, "mkfs") ||
        strstr(bprm->filename, "fdisk") || strstr(bprm->filename, "sgdisk") ||
        strstr(bprm->filename, "kptools") || strstr(bprm->filename, "kpatch") ||
        strstr(bprm->filename, "insmod") || strstr(bprm->filename, "rmmod") ||
        strstr(bprm->filename, "modprobe")) {
        return deny("execution of restricted/hijacking tool", NULL, NULL, 0);
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * 4. Structural Protection (Prevent modification of /dev/block)
 * ------------------------------------------------------------------------- */
static dev_t bbg_byname_dev = 0;
static unsigned long bbg_byname_ino = 0;

static int is_bb_byname_dir(struct inode *dir) {
    if (unlikely(bbg_byname_ino == 0)) {
        struct path path;
        if (kern_path(BB_BYNAME_DIR, LOOKUP_FOLLOW, &path) == 0) {
            struct inode *inode = d_backing_inode(path.dentry);
            if (inode) {
                bbg_byname_dev = inode->i_sb->s_dev;
                bbg_byname_ino = inode->i_ino;
            }
            path_put(&path);
        }
    }
    return (dir->i_ino == bbg_byname_ino && dir->i_sb->s_dev == bbg_byname_dev);
}

static inline int is_protected_blkdev_node(struct dentry *dentry) {
    struct inode *inode = d_backing_inode(dentry);
    if (!inode) return 0;
    if (S_ISBLK(inode->i_mode)) return 1;
    if (S_ISLNK(inode->i_mode) && dentry->d_name.name && strstr(dentry->d_name.name, "sd")) return 1;
    return 0;
}

static int bb_inode_unlink(struct inode *dir, struct dentry *dentry) {
    if (likely(current_process_trusted())) return 0;
    if (unlikely(is_bb_byname_dir(dir)) || is_protected_blkdev_node(dentry))
        return deny("unlink of protected block node", 0, d_inode(dentry), 0);
    return 0;
}

static int bb_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                           struct inode *new_dir, struct dentry *new_dentry) {
    if (likely(current_process_trusted())) return 0;
    if (is_protected_blkdev_node(old_dentry))
        return deny("rename of protected block node", 0, d_inode(old_dentry), 0);
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
static int bb_inode_setattr(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *iattr)
#else
static int bb_inode_setattr(struct dentry *dentry, struct iattr *iattr)
#endif
{
    if (current_process_trusted()) return 0;
    if (is_protected_blkdev_node(dentry))
        return deny("modification of partition attributes", 0, d_inode(dentry), 0);
    return 0;
}

/* -------------------------------------------------------------------------
 * 5. Anti-Debugging & Lifecycle
 * ------------------------------------------------------------------------- */
static int bb_ptrace_access_check(struct task_struct *child, unsigned int mode) {
    if (likely(current_process_trusted())) return 0;
    return deny("ptrace access check", NULL, NULL, 0);
}

static int bb_ptrace_traceme(struct task_struct *parent) {
    if (likely(current_process_trusted())) return 0;
    return deny("ptrace traceme", NULL, NULL, 0);
}

extern int bb_bprm_set_creds(struct linux_binprm *bprm);
extern void bb_cred_transfer(struct cred *new, const struct cred *old);
extern int bb_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);

#ifdef BB_HAS_IOCTL_COMPAT
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg) {
    return bb_file_ioctl(file, cmd, arg);
}
#endif

static struct security_hook_list bb_hooks[] = {
    LSM_HOOK_INIT(file_permission,      bb_file_permission),
    LSM_HOOK_INIT(file_ioctl,           bb_file_ioctl),
    LSM_HOOK_INIT(inode_setattr,        bb_inode_setattr),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    LSM_HOOK_INIT(bprm_creds_for_exec,  bb_bprm_set_creds),
#else
    LSM_HOOK_INIT(bprm_set_creds,       bb_bprm_set_creds),
#endif
    LSM_HOOK_INIT(cred_transfer,        bb_cred_transfer),
    LSM_HOOK_INIT(cred_prepare,         bb_cred_prepare),
#ifdef BB_HAS_IOCTL_COMPAT
    LSM_HOOK_INIT(file_ioctl_compat,    bb_file_ioctl_compat),
#endif
    LSM_HOOK_INIT(inode_rename,         bb_inode_rename),
    LSM_HOOK_INIT(inode_unlink,         bb_inode_unlink),
    LSM_HOOK_INIT(ptrace_access_check,  bb_ptrace_access_check),
    LSM_HOOK_INIT(ptrace_traceme,       bb_ptrace_traceme),
    LSM_HOOK_INIT(bprm_check_security,  bb_bprm_check_security),
};

static int __init bbg_init(void) {
    bbg_resolve_identities();
    security_add_hooks_compat(bb_hooks, ARRAY_SIZE(bb_hooks));
    pr_info("baseband_guard: Enhanced Edition by 致命编码者524 (v1.1-Ultra)\n");
    pr_info("baseband_guard: Global block protection enabled (Zero-Trust Mode)\n");
    return 0;
}

#ifndef BBG_USE_DEFINE_LSM
security_initcall(bbg_init);
#else
extern struct lsm_blob_sizes bbg_blob_sizes;
DEFINE_LSM(baseband_guard) = { .name = "baseband_guard", .init = bbg_init, .blobs = &bbg_blob_sizes };
#endif

MODULE_DESCRIPTION("Baseband-guard: Ultimate Partition & Kernel Protection");
MODULE_AUTHOR("致命编码者524 & Github@showdo");
MODULE_LICENSE("GPL v2");
