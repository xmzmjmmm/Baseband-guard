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

#include "kernel_compat.h"
#include "baseband_guard.h"
#include "tracing/tracing.h"

/* -------------------------------------------------------------------------
 * 1. Global Identity Cache (Pre-resolved for Atomic Performance)
 * ------------------------------------------------------------------------- */
static dev_t bbg_boot_dev = 0, bbg_rec_dev = 0, bbg_vboot_dev = 0, bbg_persist_dev = 0;
static unsigned long bbg_recovery_ino = 0, bbg_reboot_ino = 0;
static dev_t bbg_byname_dev = 0;
static unsigned long bbg_byname_ino = 0;

/* -------------------------------------------------------------------------
 * 2. Internal Helpers
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

    /* 1. Resolve binary inodes if not already resolved */
    for (i = 0; i < 2; i++) {
        if (*inos[i] == 0 && kern_path(bins[i], LOOKUP_FOLLOW, &path) == 0) {
            struct inode *inode = d_backing_inode(path.dentry);
            if (inode) *inos[i] = inode->i_ino;
            path_put(&path);
        }
    }

    /* 2. Resolve partitions via by-name */
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

    /* 3. Resolve by-name directory for structure protection */
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
 * 3. Atomic-Safe Hooks
 * ------------------------------------------------------------------------- */

static int bb_file_permission(struct file *file, int mask) {
    struct inode *inode;
    dev_t rdev;

    if (!(mask & (MAY_WRITE | MAY_APPEND | MAY_READ))) return 0;
    if (unlikely(!file)) return 0;

    inode = file_inode(file);
    /* 核心优化：只在块设备上进行匹配，这是纳秒级的对比 */
    if (likely(!S_ISBLK(inode->i_mode))) return 0;

    if (unlikely(!current_process_trusted())) {
        rdev = inode->i_rdev;

        /* 写操作拦截：禁止非信任进程修改任何块设备 */
        if (mask & (MAY_WRITE | MAY_APPEND)) {
            return deny("write to block device", file, inode, 0);
        }

        /* 读操作拦截：根据 Kconfig 配置拦截对敏感分区的原始数据读取 */
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

    if (likely(current_process_trusted())) return 0;

    inode = file_inode(bprm->file);

    /* 拦截破坏性二进制执行 */
    if (unlikely(bbg_recovery_ino && inode->i_ino == bbg_recovery_ino))
        return deny("execution of recovery binary", NULL, NULL, 0);

    /* 拦截直接执行重启二进制。不再依赖 get_cmdline 以确保链接稳定性 */
    if (unlikely(bbg_reboot_ino && inode->i_ino == bbg_reboot_ino))
        return deny("execution of reboot binary by untrusted process", NULL, NULL, 0);

    /* 对工具集进行字符串过滤 */
    if (strstr(bprm->filename, "wipe") || strstr(bprm->filename, "erase") ||
        strstr(bprm->filename, "fdisk") || strstr(bprm->filename, "sgdisk") ||
        strstr(bprm->filename, "kpatch") || strstr(bprm->filename, "insmod")) {
        return deny("execution of restricted/hijacking tool", NULL, NULL, 0);
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * 4. Structural Protection
 * ------------------------------------------------------------------------- */

static int is_bb_byname_dir(struct inode *dir) {
    if (bbg_byname_ino == 0) return 0;
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
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
static int bb_inode_setattr(struct user_namespace *mnt_userns, struct dentry *dentry, struct iattr *iattr)
#else
static int bb_inode_setattr(struct dentry *dentry, struct iattr *iattr)
#endif
{
    if (current_process_trusted()) return 0;
    if (is_protected_blkdev_node(dentry))
        return deny("modification of partition attributes", 0, d_inode(dentry), 0);
    return 0;
}

static int bb_ptrace_access_check(struct task_struct *child, unsigned int mode) {
    if (likely(current_process_trusted())) return 0;
    return deny("ptrace access check", NULL, NULL, 0);
}

static int bb_ptrace_traceme(struct task_struct *parent) {
    if (likely(current_process_trusted())) return 0;
    return deny("ptrace traceme", NULL, NULL, 0);
}

/* -------------------------------------------------------------------------
 * 5. Lifecycle Management
 * ------------------------------------------------------------------------- */

extern int bb_bprm_set_creds(struct linux_binprm *bprm);
extern void bb_cred_transfer(struct cred *new, const struct cred *old);
extern int bb_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);

static struct security_hook_list bb_hooks[] = {
    LSM_HOOK_INIT(file_permission,      bb_file_permission),
    LSM_HOOK_INIT(inode_setattr,        bb_inode_setattr),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    LSM_HOOK_INIT(bprm_creds_for_exec,  bb_bprm_set_creds),
#else
    LSM_HOOK_INIT(bprm_set_creds,       bb_bprm_set_creds),
#endif
    LSM_HOOK_INIT(cred_transfer,        bb_cred_transfer),
    LSM_HOOK_INIT(cred_prepare,         bb_cred_prepare),
    LSM_HOOK_INIT(inode_rename,         bb_inode_rename),
    LSM_HOOK_INIT(inode_unlink,         bb_inode_unlink),
    LSM_HOOK_INIT(ptrace_access_check,  bb_ptrace_access_check),
    LSM_HOOK_INIT(ptrace_traceme,       bb_ptrace_traceme),
    LSM_HOOK_INIT(bprm_check_security,  bb_bprm_check_security),
};

static int __init bbg_init(void) {
    /* 初始解析（可能部分由于太早而失败） */
    bbg_resolve_identities();
    security_add_hooks_compat(bb_hooks, ARRAY_SIZE(bb_hooks));
    pr_info("baseband_guard: Iron Fortress protections active by default\n");
    return 0;
}

#ifndef BBG_USE_DEFINE_LSM
/* 非 LSM 堆叠模式，使用 late_initcall 确保路径可用 */
late_initcall(bbg_init);
#else
/* LSM 模式，定义框架 */
extern struct lsm_blob_sizes bbg_blob_sizes;
DEFINE_LSM(baseband_guard) = { .name = "baseband_guard", .init = bbg_init, .blobs = &bbg_blob_sizes };

/* 专门的延迟解析器，处理挂载后的硬件 ID 绑定 */
static int __init bbg_late_init(void) {
    bbg_resolve_identities();
    return 0;
}
late_initcall(bbg_late_init);
#endif

MODULE_DESCRIPTION("Baseband-guard: Kernel-Integrated Block Protection");
MODULE_AUTHOR("Baseband-guard Team");
MODULE_LICENSE("GPL v2");
