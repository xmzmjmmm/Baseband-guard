#ifndef _BBG_TRACING_H_
#define _BBG_TRACING_H_

#include <linux/cred.h>
#include <linux/security.h>
#include <linux/version.h>
#include <linux/lsm_hooks.h>

struct bbg_cred_security_struct {
    unsigned is_untrusted_process: 1;    /* execve from su */
};

#ifdef BBG_USE_DEFINE_LSM
/*
 * Ensure lsm_hooks.h is included for lsm_blob_sizes definition.
 * On some 5.10 kernels, this might be in security.h or lsm_hooks.h
 */
extern struct lsm_blob_sizes bbg_blob_sizes;

static __maybe_unused inline struct bbg_cred_security_struct* bbg_cred(const struct cred *cred) {
    if (unlikely(!cred || !cred->security)) return NULL;
    return (struct bbg_cred_security_struct *)((char *)cred->security + bbg_blob_sizes.lbs_cred);
}

#else

struct bbg_cred_security_struct *bbg_cred(const struct cred *cred);

#endif

static __maybe_unused inline int current_process_trusted(void) {
    struct bbg_cred_security_struct *bbg_tsec;
    const struct cred *cred = current_cred();

    if (unlikely(!cred || !cred->security)) return 1;

    bbg_tsec = bbg_cred(cred);
    if (unlikely(!bbg_tsec)) return 1;

    return !bbg_tsec->is_untrusted_process;
}

#endif /* _BBG_TRACING_H_ */
