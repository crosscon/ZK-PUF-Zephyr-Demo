#include <zephyr/shell/shell.h>
#include "crosscon_hv_config.h"
#include "globals.h"
#include "helpers.h"

#define PUF_TA_GET_ZK_PROOFS_FUNC_ID        0x22334455

struct ta_zk_get_proofs_ctx {
    bool challenge1_set;
    bool challenge2_set;
    bool nonce_set;
    uint8_t challenge1[32];
    uint8_t challenge2[32];
    uint8_t nonce[64];
};

static struct ta_zk_get_proofs_ctx zk_get_proofs_ctx;

static int cmd_ta_zk_get_proofs_set_challenge1(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_zk_get_proofs_set_challenge1 <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           zk_get_proofs_ctx.challenge1,
                                           sizeof(zk_get_proofs_ctx.challenge1));
    if (rc) {
        shell_error(shell, "Failed to parse challenge1 (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed challenge1 (32 bytes, big-endian):");
    shell_hexdump(shell, zk_get_proofs_ctx.challenge1, sizeof(zk_get_proofs_ctx.challenge1));

    zk_get_proofs_ctx.challenge1_set = true;
    shell_print(shell, "challenge1 set successfully");
    return 0;
}

static int cmd_ta_zk_get_proofs_set_challenge2(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_zk_get_proofs_set_challenge2 <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           zk_get_proofs_ctx.challenge2,
                                           sizeof(zk_get_proofs_ctx.challenge2));
    if (rc) {
        shell_error(shell, "Failed to parse challenge2 (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed challenge2 (32 bytes, big-endian):");
    shell_hexdump(shell, zk_get_proofs_ctx.challenge2, sizeof(zk_get_proofs_ctx.challenge2));

    zk_get_proofs_ctx.challenge2_set = true;
    shell_print(shell, "challenge2 set successfully");
    return 0;
}

static int cmd_ta_zk_get_proofs_set_nonce(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_zk_get_proofs_set_nonce <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           zk_get_proofs_ctx.nonce,
                                           sizeof(zk_get_proofs_ctx.nonce));
    if (rc) {
        shell_error(shell, "Failed to parse nonce (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed nonce (64 bytes, big-endian):");
    shell_hexdump(shell, zk_get_proofs_ctx.nonce, sizeof(zk_get_proofs_ctx.nonce));

    zk_get_proofs_ctx.nonce_set = true;
    shell_print(shell, "nonce set successfully");
    return 0;
}

static int cmd_ta_zk_get_proofs(const struct shell *shell, size_t argc, char **argv)
{
    if (!zk_get_proofs_ctx.challenge1_set || !zk_get_proofs_ctx.challenge2_set || !zk_get_proofs_ctx.nonce_set) {
        shell_error(shell, "Missing required arguments. Set them first.");
        return -EINVAL;
    }

    uint8_t P_x[32], P_y[32], v[64], w[64];
    int rc;

    int res = call_puf_ta_get_zk_proofs(tee_dev, session_id, (uint8_t *)shm_ptr,
                                        zk_get_proofs_ctx.challenge1, zk_get_proofs_ctx.challenge2, zk_get_proofs_ctx.nonce,
                                        P_x, P_y, v, w);
    if (res) {
        shell_error(shell, "PUF_TA_get_ZK_proofs failed: %d", res);
        shell_error(shell, "Have you ran PUF_TA_init first?");
        return res;
    }

    shell_print(shell, "P_x (hex): ");
    shell_hexdump(shell, P_x, sizeof(P_x));
    shell_print(shell, "P_y (hex): ");
    shell_hexdump(shell, P_y, sizeof(P_y));
    shell_print(shell, "v (hex): ");
    shell_hexdump(shell, v, sizeof(v));
    shell_print(shell, "w (hex): ");
    shell_hexdump(shell, w, sizeof(w));
    hex_to_decimal(shell, P_x, sizeof(P_x), "P_x (decimal): ");
    hex_to_decimal(shell, P_y, sizeof(P_y), "P_y (decimal): ");
    hex_to_decimal(shell, v, sizeof(v), "v (decimal): ");
    hex_to_decimal(shell, w, sizeof(w), "w (decimal): ");

    shell_print(shell, "PUF_TA_get_ZK_proofs success");
    return 0;
}

SHELL_CMD_REGISTER(ta_zk_get_proofs_set_challenge1, NULL,
                   "Set challenge1 for ta_zk_get_proofs_invoke", cmd_ta_zk_get_proofs_set_challenge1);
SHELL_CMD_REGISTER(ta_zk_get_proofs_set_challenge2, NULL,
                   "Set challenge2 for ta_zk_get_proofs_invoke", cmd_ta_zk_get_proofs_set_challenge2);
SHELL_CMD_REGISTER(ta_zk_get_proofs_set_nonce, NULL,
                   "Set nonce for ta_zk_get_proofs_invoke", cmd_ta_zk_get_proofs_set_nonce);
SHELL_CMD_REGISTER(ta_zk_get_proofs_invoke, NULL, "Call PUF_TA_get_ZK_proofs", cmd_ta_zk_get_proofs);

int call_puf_ta_get_zk_proofs(const struct device *tee_dev, int session_id, uint8_t *shm_ptr,
                              uint8_t challenge1[32], uint8_t challenge2[32], uint8_t nonce[64],
                              uint8_t P_x[32], uint8_t P_y[32], uint8_t v[64], uint8_t w[64])
{
    int ret;
    param[0].attr = TEE_PARAM_ATTR_TYPE_MEMREF_INOUT;
    param[0].a    = (uint64_t)(VMS_MEMREF0_OFFSET);
    param[0].b    = (uint64_t)32;
    param[0].c    = (uint64_t)(uintptr_t)&ipc_shm;

    param[1].attr = TEE_PARAM_ATTR_TYPE_MEMREF_INOUT;
    param[1].a    = (uint64_t)(VMS_MEMREF1_OFFSET);
    param[1].b    = (uint64_t)32;
    param[1].c    = (uint64_t)(uintptr_t)&ipc_shm;

    param[2].attr = TEE_PARAM_ATTR_TYPE_MEMREF_INOUT;
    param[2].a    = (uint64_t)(VMS_MEMREF2_OFFSET);
    param[2].b    = (uint64_t)64;
    param[2].c    = (uint64_t)(uintptr_t)&ipc_shm;

    param[3].attr = TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
    param[3].a    = (uint64_t)(VMS_MEMREF3_OFFSET);
    param[3].b    = (uint64_t)64;
    param[3].c    = (uint64_t)(uintptr_t)&ipc_shm;

    invoke_func_arg.func      = PUF_TA_GET_ZK_PROOFS_FUNC_ID;
    invoke_func_arg.session   = session_id;
    invoke_func_arg.cancel_id = 0;
    invoke_func_arg.ret       = 0;
    invoke_func_arg.ret_origin= 0;

    memset(shm_ptr, 0, VMS_USABLE_PAYLOAD_SIZE);
    memcpy((void *)(shm_ptr + param[0].a), challenge1, param[0].b);
    memcpy((void *)(shm_ptr + param[1].a), challenge2, param[1].b);
    memcpy((void *)(shm_ptr + param[2].a), nonce, param[2].b);

    ret = tee_invoke_func(tee_dev, &invoke_func_arg, 4, &param);
    if (ret == 0){
        memcpy(P_x, (void *)(shm_ptr + param[0].a), param[0].b);
        memcpy(P_y, (void *)(shm_ptr + param[1].a), param[1].b);
        memcpy(v,   (void *)(shm_ptr + param[2].a), param[2].b);
        memcpy(w,   (void *)(shm_ptr + param[3].a), param[3].b);
    }

    return ret;
}
