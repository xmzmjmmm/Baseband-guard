#include "kernel_compat.h"
#include <linux/security.h>
#include <linux/errno.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include "tracing.h"

/* SELinux internal headers are provided by Makefile include paths */
#include "objsec.h"

#ifdef BBG_USE_DEFINE_LSM
struct lsm_blob_sizes bbg_blob_sizes __ro_after_init = {
    .lbs_cred = sizeof(struct bbg_cred_security_struct),
};
#endif

/* Standard SELinux cred accessor usually provided by objsec.h */
#ifndef selinux_cred
static inline struct task_security_struct *bbg_selinux_cred(const struct cred *cred) {
    if (!cred) return NULL;
    return cred->security;
}
#define selinux_cred bbg_selinux_cred
#endif

int bb_cred_prepare(struct cred *new, const struct cred *old,
                    gfp_t gfp) {
    const struct bbg_cred_security_struct *old_tsec = bbg_cred(old);
    struct bbg_cred_security_struct *tsec = bbg_cred(new);

    if (tsec && old_tsec)
        *tsec = *old_tsec;
    return 0;
}

void bb_cred_transfer(struct cred *new, const struct cred *old) {
    const struct bbg_cred_security_struct *old_tsec = bbg_cred(old);
    struct bbg_cred_security_struct *tsec = bbg_cred(new);

    if (tsec && old_tsec)
        *tsec = *old_tsec;
}

int bb_bprm_set_creds(struct linux_binprm *bprm) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    struct task_security_struct *new_selinux_tsec;
    const struct task_security_struct *old_selinux_tsec;
#else
    struct cred_security_struct *new_selinux_tsec;
    const struct cred_security_struct *old_selinux_tsec;
#endif
    const struct bbg_cred_security_struct *old_bbg_tsec;
    struct bbg_cred_security_struct *new_bbg_tsec;

    old_bbg_tsec = bbg_cred(current_cred());
    new_bbg_tsec = bbg_cred(bprm->cred);

    if (unlikely(!new_bbg_tsec || !old_bbg_tsec))
        return 0;

    new_bbg_tsec->is_untrusted_process = old_bbg_tsec->is_untrusted_process;

    if (new_bbg_tsec->is_untrusted_process) {
        return 0; // already flag as untrusted_process
    }

    if (unlikely(!selinux_initialized_compat()))
        return 0;

    old_selinux_tsec = selinux_cred(current_cred());
    new_selinux_tsec = selinux_cred(bprm->cred);

    if (unlikely(!old_selinux_tsec || !new_selinux_tsec))
        return 0;

    /* 1. Universal Elevation Check: If a non-root process becomes root via execve */
    if (current_cred()->uid.val != 0 && bprm->cred->uid.val == 0) {
        new_bbg_tsec->is_untrusted_process = 1;
    }

    /* 2. Universal SELinux Keyword Signature Audit */
    if (!new_bbg_tsec->is_untrusted_process) {
        char *secdata = NULL;
        u32 seclen = 0;
        if (security_secid_to_secctx(new_selinux_tsec->sid, &secdata, &seclen) == 0) {
            if (secdata) {
                if (strstr(secdata, ":su") || strstr(secdata, "magisk") ||
                    strstr(secdata, "ksu") || strstr(secdata, "apatch")) {
                    new_bbg_tsec->is_untrusted_process = 1;
                }
                security_release_secctx(secdata, seclen);
            }
        }
    }

    if (new_bbg_tsec->is_untrusted_process) {
        pr_info("baseband_guard: pid %d (%s) marked as untrusted root process via universal signature\n",
                current->pid, current->comm);
    }

    return 0;
}

int __maybe_unused bbg_process_setpermissive(void) {
    return 0;
}

int __maybe_unused bbg_test_domain_transition(u32 target_secid) {
    return 0;
}

#ifndef BBG_USE_DEFINE_LSM

struct bbg_cred_security_struct *bbg_cred(const struct cred *cred) {
    if (!cred || !cred->security) return NULL;
    return &((struct task_security_struct *) cred->security)->bbg_cred;
}

#endif
