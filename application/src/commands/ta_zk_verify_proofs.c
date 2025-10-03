#include <zephyr/shell/shell.h>
#include "crosscon_hv_config.h"
#include "globals.h"
#include "helpers.h"

#define PUF_TA_VERIFY_ZK_PROOFS_FUNC_ID     0x33445566

struct ta_zk_verify_proofs_ctx {
    bool g_x_set;
    bool g_y_set;
    bool h_x_set;
    bool h_y_set;
    bool COM_x_set;
    bool COM_y_set;
    bool P_x_set;
    bool P_y_set;
    bool v_set;
    bool w_set;
    bool nonce_set;
    uint8_t g_x[32];
    uint8_t g_y[32];
    uint8_t h_x[32];
    uint8_t h_y[32];
    uint8_t COM_x[32];
    uint8_t COM_y[32];
    uint8_t P_x[32];
    uint8_t P_y[32];
    uint8_t v[64];
    uint8_t w[64];
    uint8_t nonce[64];
};

static struct ta_zk_verify_proofs_ctx zk_verify_proofs_ctx;

static int cmd_ta_zk_verify_proofs_set_g_x(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_zk_verify_proofs_set_g_x <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           zk_verify_proofs_ctx.g_x,
                                           sizeof(zk_verify_proofs_ctx.g_x));
    if (rc) {
        shell_error(shell, "Failed to parse g_x (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed g_x (32 bytes, big-endian):");
    shell_hexdump(shell, zk_verify_proofs_ctx.g_x, sizeof(zk_verify_proofs_ctx.g_x));

    zk_verify_proofs_ctx.g_x_set = true;
    shell_print(shell, "g_x set successfully");
    return 0;
}

static int cmd_ta_zk_verify_proofs_set_g_y(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_zk_verify_proofs_set_g_y <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           zk_verify_proofs_ctx.g_y,
                                           sizeof(zk_verify_proofs_ctx.g_y));
    if (rc) {
        shell_error(shell, "Failed to parse g_y (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed g_y (32 bytes, big-endian):");
    shell_hexdump(shell, zk_verify_proofs_ctx.g_y, sizeof(zk_verify_proofs_ctx.g_y));

    zk_verify_proofs_ctx.g_y_set = true;
    shell_print(shell, "g_y set successfully");
    return 0;
}

static int cmd_ta_zk_verify_proofs_set_h_x(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_zk_verify_proofs_set_h_x <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           zk_verify_proofs_ctx.h_x,
                                           sizeof(zk_verify_proofs_ctx.h_x));
    if (rc) {
        shell_error(shell, "Failed to parse h_x (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed h_x (32 bytes, big-endian):");
    shell_hexdump(shell, zk_verify_proofs_ctx.h_x, sizeof(zk_verify_proofs_ctx.h_x));

    zk_verify_proofs_ctx.h_x_set = true;
    shell_print(shell, "h_x set successfully");
    return 0;
}

static int cmd_ta_zk_verify_proofs_set_h_y(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_zk_verify_proofs_set_h_y <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           zk_verify_proofs_ctx.h_y,
                                           sizeof(zk_verify_proofs_ctx.h_y));
    if (rc) {
        shell_error(shell, "Failed to parse h_y (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed h_y (32 bytes, big-endian):");
    shell_hexdump(shell, zk_verify_proofs_ctx.h_y, sizeof(zk_verify_proofs_ctx.h_y));

    zk_verify_proofs_ctx.h_y_set = true;
    shell_print(shell, "h_y set successfully");
    return 0;
}

static int cmd_ta_zk_verify_proofs_set_COM_x(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_zk_verify_proofs_set_COM_x <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           zk_verify_proofs_ctx.COM_x,
                                           sizeof(zk_verify_proofs_ctx.COM_x));
    if (rc) {
        shell_error(shell, "Failed to parse COM_x (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed COM_x (32 bytes, big-endian):");
    shell_hexdump(shell, zk_verify_proofs_ctx.COM_x, sizeof(zk_verify_proofs_ctx.COM_x));

    zk_verify_proofs_ctx.COM_x_set = true;
    shell_print(shell, "COM_x set successfully");
    return 0;
}

static int cmd_ta_zk_verify_proofs_set_COM_y(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_zk_verify_proofs_set_COM_y <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           zk_verify_proofs_ctx.COM_y,
                                           sizeof(zk_verify_proofs_ctx.COM_y));
    if (rc) {
        shell_error(shell, "Failed to parse COM_y (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed COM_y (32 bytes, big-endian):");
    shell_hexdump(shell, zk_verify_proofs_ctx.COM_y, sizeof(zk_verify_proofs_ctx.COM_y));

    zk_verify_proofs_ctx.COM_y_set = true;
    shell_print(shell, "COM_y set successfully");
    return 0;
}

static int cmd_ta_zk_verify_proofs_set_P_x(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_zk_verify_proofs_set_P_x <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           zk_verify_proofs_ctx.P_x,
                                           sizeof(zk_verify_proofs_ctx.P_x));
    if (rc) {
        shell_error(shell, "Failed to parse P_x (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed P_x (32 bytes, big-endian):");
    shell_hexdump(shell, zk_verify_proofs_ctx.P_x, sizeof(zk_verify_proofs_ctx.P_x));

    zk_verify_proofs_ctx.P_x_set = true;
    shell_print(shell, "P_x set successfully");
    return 0;
}

static int cmd_ta_zk_verify_proofs_set_P_y(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_zk_verify_proofs_set_P_y <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           zk_verify_proofs_ctx.P_y,
                                           sizeof(zk_verify_proofs_ctx.P_y));
    if (rc) {
        shell_error(shell, "Failed to parse P_y (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed P_y (32 bytes, big-endian):");
    shell_hexdump(shell, zk_verify_proofs_ctx.P_y, sizeof(zk_verify_proofs_ctx.P_y));

    zk_verify_proofs_ctx.P_y_set = true;
    shell_print(shell, "P_y set successfully");
    return 0;
}

static int cmd_ta_zk_verify_proofs_set_v(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_zk_verify_proofs_set_v <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           zk_verify_proofs_ctx.v,
                                           sizeof(zk_verify_proofs_ctx.v));
    if (rc) {
        shell_error(shell, "Failed to parse v (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed v (32 bytes, big-endian):");
    shell_hexdump(shell, zk_verify_proofs_ctx.v, sizeof(zk_verify_proofs_ctx.v));

    zk_verify_proofs_ctx.v_set = true;
    shell_print(shell, "v set successfully");
    return 0;
}

static int cmd_ta_zk_verify_proofs_set_w(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_zk_verify_proofs_set_w <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           zk_verify_proofs_ctx.w,
                                           sizeof(zk_verify_proofs_ctx.w));
    if (rc) {
        shell_error(shell, "Failed to parse w (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed w (32 bytes, big-endian):");
    shell_hexdump(shell, zk_verify_proofs_ctx.w, sizeof(zk_verify_proofs_ctx.w));

    zk_verify_proofs_ctx.w_set = true;
    shell_print(shell, "w set successfully");
    return 0;
}

static int cmd_ta_zk_verify_proofs_set_nonce(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_zk_verify_proofs_set_nonce <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           zk_verify_proofs_ctx.nonce,
                                           sizeof(zk_verify_proofs_ctx.nonce));
    if (rc) {
        shell_error(shell, "Failed to parse nonce (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed nonce (32 bytes, big-endian):");
    shell_hexdump(shell, zk_verify_proofs_ctx.nonce, sizeof(zk_verify_proofs_ctx.nonce));

    zk_verify_proofs_ctx.nonce_set = true;
    shell_print(shell, "nonce set successfully");
    return 0;
}

static int cmd_ta_zk_verify_proofs(const struct shell *shell, size_t argc, char **argv)
{
    if (
        !zk_verify_proofs_ctx.g_x_set ||
        !zk_verify_proofs_ctx.g_y_set ||
        !zk_verify_proofs_ctx.h_x_set ||
        !zk_verify_proofs_ctx.h_y_set ||
        !zk_verify_proofs_ctx.COM_x_set ||
        !zk_verify_proofs_ctx.COM_y_set ||
        !zk_verify_proofs_ctx.P_x_set ||
        !zk_verify_proofs_ctx.P_y_set ||
        !zk_verify_proofs_ctx.v_set ||
        !zk_verify_proofs_ctx.w_set ||
        !zk_verify_proofs_ctx.nonce_set
    ) {
        shell_error(shell, "Missing required arguments. Set them first.");
        return -EINVAL;
    }

    int rc;

    int res = call_puf_ta_zk_verify(tee_dev, session_id, (uint8_t *)shm_ptr,
                                        zk_verify_proofs_ctx.g_x, zk_verify_proofs_ctx.g_y, zk_verify_proofs_ctx.h_x, zk_verify_proofs_ctx.h_y,
                                        zk_verify_proofs_ctx.COM_x, zk_verify_proofs_ctx.COM_y, zk_verify_proofs_ctx.P_x, zk_verify_proofs_ctx.P_y,
                                        zk_verify_proofs_ctx.v, zk_verify_proofs_ctx.w, zk_verify_proofs_ctx.nonce);
    if (res) {
        shell_error(shell, "PUF_TA_verify_ZK_proofs failed: %d", res);
        if (res == TEE_ERROR_SECURITY)
        {
            shell_error(shell, "❌ Proof FAILED: g^v*h^w != P*COM^α");
        }
        else {
            shell_error(shell, "Have you ran PUF_TA_init first?");
        }
        return res;
    }

    shell_print(shell, "✅ Proof verifies: g^v*h^w = P*COM^α");
    return 0;
}

SHELL_CMD_REGISTER(ta_zk_verify_proofs_set_g_x, NULL,
                   "Set g_x for ta_zk_verify_proofs_invoke", cmd_ta_zk_verify_proofs_set_g_x);
SHELL_CMD_REGISTER(ta_zk_verify_proofs_set_g_y, NULL,
                   "Set g_y for ta_zk_verify_proofs_invoke", cmd_ta_zk_verify_proofs_set_g_y);
SHELL_CMD_REGISTER(ta_zk_verify_proofs_set_h_x, NULL,
                   "Set h_x for ta_zk_verify_proofs_invoke", cmd_ta_zk_verify_proofs_set_h_x);
SHELL_CMD_REGISTER(ta_zk_verify_proofs_set_h_y, NULL,
                   "Set h_y for ta_zk_verify_proofs_invoke", cmd_ta_zk_verify_proofs_set_h_y);
SHELL_CMD_REGISTER(ta_zk_verify_proofs_set_COM_x, NULL,
                   "Set COM_x for ta_zk_verify_proofs_invoke", cmd_ta_zk_verify_proofs_set_COM_x);
SHELL_CMD_REGISTER(ta_zk_verify_proofs_set_COM_y, NULL,
                   "Set COM_y for ta_zk_verify_proofs_invoke", cmd_ta_zk_verify_proofs_set_COM_y);
SHELL_CMD_REGISTER(ta_zk_verify_proofs_set_P_x, NULL,
                   "Set P_x for ta_zk_verify_proofs_invoke", cmd_ta_zk_verify_proofs_set_P_x);
SHELL_CMD_REGISTER(ta_zk_verify_proofs_set_P_y, NULL,
                   "Set P_y for ta_zk_verify_proofs_invoke", cmd_ta_zk_verify_proofs_set_P_y);
SHELL_CMD_REGISTER(ta_zk_verify_proofs_set_v, NULL,
                   "Set v for ta_zk_verify_proofs_invoke", cmd_ta_zk_verify_proofs_set_v);
SHELL_CMD_REGISTER(ta_zk_verify_proofs_set_w, NULL,
                   "Set w for ta_zk_verify_proofs_invoke", cmd_ta_zk_verify_proofs_set_w);
SHELL_CMD_REGISTER(ta_zk_verify_proofs_set_nonce, NULL,
                   "Set nonce for ta_zk_verify_proofs_invoke", cmd_ta_zk_verify_proofs_set_nonce);

SHELL_CMD_REGISTER(ta_zk_verify_proofs_invoke, NULL, "Call PUF_TA_get_ZK_proofs", cmd_ta_zk_verify_proofs);

int call_puf_ta_zk_verify(const struct device *tee_dev, int session_id, uint8_t *shm_ptr,
                                       uint8_t g_x[32], uint8_t g_y[32], uint8_t h_x[32], uint8_t h_y[32],
                                       uint8_t COM_x[32], uint8_t COM_y[32], uint8_t P_x[32], uint8_t P_y[32],
                                       uint8_t  v[64], uint8_t w[64], uint8_t nonce[64])
{

    typedef struct {
        uint8_t g_x[32];
        uint8_t g_y[32];
        uint8_t h_x[32];
        uint8_t h_y[32];
        uint8_t COM_x[32];
        uint8_t COM_y[32];
        uint8_t P_x[32];
        uint8_t P_y[32];
        uint8_t v[64];
        uint8_t w[64];
        uint8_t n[64];
    } zk_proofs_mem_struct;

    int ret;
    zk_proofs_mem_struct proof_mem_struct;

    memcpy(proof_mem_struct.g_x,   g_x,   32);
    memcpy(proof_mem_struct.g_y,   g_y,   32);
    memcpy(proof_mem_struct.h_x,   h_x,   32);
    memcpy(proof_mem_struct.h_y,   h_y,   32);
    memcpy(proof_mem_struct.COM_x, COM_x, 32);
    memcpy(proof_mem_struct.COM_y, COM_y, 32);
    memcpy(proof_mem_struct.P_x,   P_x,   32);
    memcpy(proof_mem_struct.P_y,   P_y,   32);
    memcpy(proof_mem_struct.v,     v,     64);
    memcpy(proof_mem_struct.w,     w,     64);
    memcpy(proof_mem_struct.n,     nonce, 64);

    param[0].attr = TEE_PARAM_ATTR_TYPE_MEMREF_INPUT;
    param[0].a    = (uint64_t)(VMS_MEMREF0_OFFSET); // offsets
    param[0].b    = (uint64_t)448;                  // length: 448 bytes
    param[0].c    = (uint64_t)(uintptr_t)&ipc_shm;  // shared-memory ID (handle)

    param[1].attr = TEE_PARAM_ATTR_TYPE_NONE;
    param[1].a    = (uint64_t)(VMS_MEMREF1_OFFSET); // offsets
    param[1].b    = (uint64_t)0;                    // length: 0 bytes
    param[1].c    = (uint64_t)(uintptr_t)&ipc_shm;  // shared-memory ID (handle)

    param[2].attr = TEE_PARAM_ATTR_TYPE_NONE;
    param[2].a    = (uint64_t)(VMS_MEMREF2_OFFSET); // offsets
    param[2].b    = (uint64_t)0;                    // length: 0 bytes
    param[2].c    = (uint64_t)(uintptr_t)&ipc_shm;  // shared-memory ID (handle)

    param[3].attr = TEE_PARAM_ATTR_TYPE_NONE;
    param[3].a    = (uint64_t)(VMS_MEMREF3_OFFSET); // offsets
    param[3].b    = (uint64_t)0;                    // length: 0 bytes
    param[3].c    = (uint64_t)(uintptr_t)&ipc_shm;  // shared-memory ID (handle)

    invoke_func_arg.func      = PUF_TA_VERIFY_ZK_PROOFS_FUNC_ID;
    invoke_func_arg.session   = session_id;
    invoke_func_arg.cancel_id = 0;
    invoke_func_arg.ret       = 0;
    invoke_func_arg.ret_origin= 0;

    memset(shm_ptr, 0, VMS_USABLE_PAYLOAD_SIZE);
    memcpy((void *)(shm_ptr + param[0].a), &proof_mem_struct, param[0].b);

    ret = tee_invoke_func(tee_dev, &invoke_func_arg, 4, &param);

    return ret;
}
