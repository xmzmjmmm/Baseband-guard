#ifndef _BBG_TRACING_H_
#define _BBG_TRACING_H_

#include <linux/cred.h>
#include <linux/security.h>
#include <linux/version.h>

struct bbg_cred_security_struct {
    unsigned is_untrusted_process: 1;    /* execve from su */
};

#ifdef BBG_USE_DEFINE_LSM
extern struct lsm_blob_sizes bbg_blob_sizes;

static __maybe_unused inline struct bbg_cred_security_struct* bbg_cred(const struct cred *cred) {
    if (unlikely(!cred || !cred->security)) return NULL;
    /* Explicit cast for safer pointer arithmetic across different compilers */
    return (struct bbg_cred_security_struct *)((char *)cred->security + bbg_blob_sizes.lbs_cred);
}

#else

struct bbg_cred_security_struct *bbg_cred(const struct cred *cred);

#endif

static __maybe_unused inline int current_process_trusted(void) {
    struct bbg_cred_security_struct *bbg_tsec;
    const struct cred *cred = current_cred();

    /* Safety check for early boot or NULL credentials */
    if (unlikely(!cred || !cred->security)) return 1; /* Default to trusted */

    bbg_tsec = bbg_cred(cred);
    if (unlikely(!bbg_tsec)) return 1;

    return !bbg_tsec->is_untrusted_process;
}

#endif /* _BBG_TRACING_H_ */
