#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(GUEST_VM, LOG_LEVEL_DBG);

#include <stdio.h>
#include "crosscon_hv_config.h"
#include <zephyr/kernel.h>

#define IS_WRITE_TO_FLASH_ENABLED 1

#define PUF_TA_INIT_FUNC_ID            0x00112233
#define PUF_TA_GET_COMMITMENT_FUNC_ID  0x11223344
#define PUF_TA_GET_ZK_PROOFS_FUNC_ID   0x22334455

#define CHALLENGE_1   0x3CA1F49257B80E6D1FA9C3E7749012AD

#define CHALLENGE_2   0xFF00FF00FF00FF0000FF00FF00FF00FF

#define NONCE         0xAABBCCDDEEFFAABBCCDDEEFF00112233

int main(void)
{
    /* Hardcoded session */
    int session_id = 0;

    LOG_INF("VM Initialized");
    const struct device *tee_dev = device_get_binding("crosscon_hv_tee");
    if (tee_dev == NULL) {
        LOG_ERR("Failed to bind device 'crosscon_hv_tee'");
        return -1;
    }
    struct tee_version_info info;
    int res;
    res = tee_get_version(tee_dev, &info);
    if (res == 0) {
        LOG_INF("TEE version info:");
        LOG_INF("impl_id   = %u", info.impl_id);
        LOG_INF("impl_caps = 0x%08x", info.impl_caps);
        LOG_INF("gen_caps  = 0x%08x", info.gen_caps);
    } else {
        LOG_ERR("tee_get_version() failed: %d", res);
    }

    struct tee_shm ipc_shm = {
        .dev   = tee_dev,         // from device_get_binding()
        .addr  = VMS_IPC_BASE,    // static shared memory base
        .size  = VMS_IPC_SIZE,    // total available size
        .flags = 0,               // no special flags needed
    };

    LOG_INF("TEE Initialized");

    /* PUF_TA_init */
    unsigned int num_param;

    struct tee_param param[4] = {0};
    for (int i = 0; i < 4; i++) {
        param[i].attr = TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
        param[i].a    = (uint64_t)(i * 256);           // offsets: 0, 256, 512, 768
        param[i].b    = (uint64_t)32;                  // length: 32 bytes
        param[i].c    = (uint64_t)(uintptr_t)&ipc_shm; // shared-memory ID (handle)
    }

    struct tee_invoke_func_arg arg = {0};
    arg.func      = PUF_TA_INIT_FUNC_ID;
    arg.session   = session_id;
    arg.cancel_id = 0;
    arg.ret       = 0;
    arg.ret_origin= 0;

    res = tee_invoke_func(tee_dev, &arg, 4, &param);

    // Wait for interrupts and handle them according to function_table
    while(1);
}
