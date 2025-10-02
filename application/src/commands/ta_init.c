#include <zephyr/shell/shell.h>
#include "crosscon_hv_config.h"
#include "globals.h"

#define PUF_TA_INIT_FUNC_ID                 0x00112233

static int cmd_ta_init(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 1) {
        shell_error(shell, "Wrong amount of parameters.\nUsage: ta_init");
        return -EINVAL;
    }

    uint8_t g_x[32], g_y[32], h_x[32], h_y[32];

    shell_print(shell, "Calling PUF_TA_init");

    int res = call_puf_ta_init(tee_dev, session_id, (uint8_t *)shm_ptr, g_x, g_y, h_x, h_y);
    if (res) {
        shell_error(shell, "PUF_TA_init failed: %d", res);
        return res;
    }

    shell_print(shell, "g_x (hex): ");
    shell_hexdump(shell, g_x, sizeof(g_x));
    shell_print(shell, "g_y (hex): ");
    shell_hexdump(shell, g_y, sizeof(g_y));
    shell_print(shell, "h_x (hex): ");
    shell_hexdump(shell, h_x, sizeof(h_x));
    shell_print(shell, "h_y (hex): ");
    shell_hexdump(shell, h_y, sizeof(h_y));
    hex_to_decimal(shell, g_x, sizeof(g_x), "g_x (decimal): ");
    hex_to_decimal(shell, g_y, sizeof(g_y), "g_y (decimal): ");
    hex_to_decimal(shell, h_x, sizeof(h_x), "h_x (decimal): ");
    hex_to_decimal(shell, h_y, sizeof(h_y), "h_y (decimal): ");

    shell_print(shell, "PUF_TA_init success");
    return 0;
}

SHELL_CMD_REGISTER(ta_init, NULL, "Call PUF_TA_init", cmd_ta_init);

int call_puf_ta_init(const struct device *tee_dev, int session_id, uint8_t *shm_ptr,
                     uint8_t g_x[32], uint8_t g_y[32], uint8_t h_x[32], uint8_t h_y[32])
{
    int ret;

    param[0].attr = TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
    param[0].a    = (uint64_t)(VMS_MEMREF0_OFFSET); // offsets
    param[0].b    = (uint64_t)32;                   // length: 32 bytes
    param[0].c    = (uint64_t)(uintptr_t)&ipc_shm;  // shared-memory ID (handle)

    param[1].attr = TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
    param[1].a    = (uint64_t)(VMS_MEMREF1_OFFSET); // offsets
    param[1].b    = (uint64_t)32;                   // length: 32 bytes
    param[1].c    = (uint64_t)(uintptr_t)&ipc_shm;  // shared-memory ID (handle)

    param[2].attr = TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
    param[2].a    = (uint64_t)(VMS_MEMREF2_OFFSET); // offsets
    param[2].b    = (uint64_t)32;                   // length: 32 bytes
    param[2].c    = (uint64_t)(uintptr_t)&ipc_shm;  // shared-memory ID (handle)

    param[3].attr = TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
    param[3].a    = (uint64_t)(VMS_MEMREF3_OFFSET); // offsets
    param[3].b    = (uint64_t)32;                   // length: 32 bytes
    param[3].c    = (uint64_t)(uintptr_t)&ipc_shm;  // shared-memory ID (handle)

    invoke_func_arg.func      = PUF_TA_INIT_FUNC_ID;
    invoke_func_arg.session   = session_id;
    invoke_func_arg.cancel_id = 0;
    invoke_func_arg.ret       = 0;
    invoke_func_arg.ret_origin= 0;

    ret = tee_invoke_func(tee_dev, &invoke_func_arg, 4, &param);
    if (ret == 0){
        memcpy(g_x, (void *)(shm_ptr + param[0].a), param[0].b);
        memcpy(g_y, (void *)(shm_ptr + param[1].a), param[1].b);
        memcpy(h_x, (void *)(shm_ptr + param[2].a), param[2].b);
        memcpy(h_y, (void *)(shm_ptr + param[3].a), param[3].b);
    }

    return ret;
}
