#ifndef _BBG_TRACING_KERNEL_COMPAT_H_
#define _BBG_TRACING_KERNEL_COMPAT_H_

#include <linux/version.h>
#include <linux/cred.h>
#include <linux/security.h>

/*
 * Standard LSM SID initialization check.
 * Instead of reaching into SELinux internals (selinux_state),
 * we check if the system can provide a security context for a known SID.
 * If security_secid_to_secctx returns -EOPNOTSUPP, LSM is likely not active.
 */
static __maybe_unused inline bool bbg_lsm_initialized(void) {
    char *ctx = NULL;
    u32 len = 0;
    int ret;

    /* 1 is a safe starting SID for SELinux (initial_sid_kernel) */
    ret = security_secid_to_secctx(1, &ctx, &len);
    if (ret == 0) {
        security_release_secctx(ctx, len);
        return true;
    }

    return (ret != -EOPNOTSUPP);
}

#endif /* _BBG_TRACING_KERNEL_COMPAT_H_ */
