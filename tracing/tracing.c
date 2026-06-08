#include <linux/security.h>
#include <linux/errno.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "kernel_compat.h"
#include "tracing.h"

#ifdef BBG_USE_DEFINE_LSM
struct lsm_blob_sizes bbg_blob_sizes __ro_after_init = {
    .lbs_cred = sizeof(struct bbg_cred_security_struct),
};
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
    const struct bbg_cred_security_struct *old_bbg_tsec;
    struct bbg_cred_security_struct *new_bbg_tsec;
    u32 old_sid, new_sid;

    old_bbg_tsec = bbg_cred(current_cred());
    new_bbg_tsec = bbg_cred(bprm->cred);

    if (unlikely(!new_bbg_tsec || !old_bbg_tsec))
        return 0;

    new_bbg_tsec->is_untrusted_process = old_bbg_tsec->is_untrusted_process;

    if (new_bbg_tsec->is_untrusted_process) {
        return 0; // already flag as untrusted_process
    }

    /* Standard public API to get SID */
    security_cred_getsecid(current_cred(), &old_sid);
    security_cred_getsecid(bprm->cred, &new_sid);

    /* Use our robust public-API based check */
    if (unlikely(!bbg_lsm_initialized()))
        return 0;

    /* 1. Universal Elevation Check: If a non-root process becomes root via execve */
    if (current_cred()->uid.val != 0 && bprm->cred->uid.val == 0) {
        new_bbg_tsec->is_untrusted_process = 1;
    }

    /* 2. Universal SELinux Keyword Signature Audit */
    if (!new_bbg_tsec->is_untrusted_process) {
        char *secdata = NULL;
        u32 seclen = 0;

        /* security_secid_to_secctx is a stable public LSM API */
        if (security_secid_to_secctx(new_sid, &secdata, &seclen) == 0) {
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
    /* Manual integration fallback */
    return (struct bbg_cred_security_struct *)cred->security;
}

#endif
