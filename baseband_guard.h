#define BB_ENFORCING 1

#ifdef CONFIG_BBG_DEBUG
#define BB_DEBUG 1
#else
#define BB_DEBUG 0
#endif

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

#define BB_BYNAME_DIR "/dev/block/by-name"

static const char *const allowlist_names[] = {
#ifndef CONFIG_BBG_BLOCK_BOOT
        "boot", "init_boot",
#endif
        "dtbo", "vendor_boot",
#ifndef CONFIG_BBG_BLOCK_RECOVERY
        "recovery",
#endif
#ifndef CONFIG_BBG_BLOCK_SYSTEM
        "system", "vendor", "product", "system_ext", "odm",
#endif
#ifndef CONFIG_BBG_BLOCK_USERDATA
        "userdata", "cache", "metadata",
#endif
#ifndef CONFIG_BBG_BLOCK_PERSIST
        "persist", "persist_lg", "frp", "seccfg", "keystore", "sec1",
#endif
        "vbmeta", "vbmeta_system", "vbmeta_vendor",
        "misc",
};
static const size_t allowlist_cnt = ARRAY_SIZE(allowlist_names);
