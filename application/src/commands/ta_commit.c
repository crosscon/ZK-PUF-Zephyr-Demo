#include <zephyr/shell/shell.h>
#include "crosscon_hv_config.h"
#include "globals.h"
#include "helpers.h"

#define PUF_TA_GET_COMMITMENT_FUNC_ID       0x11223344

struct ta_commit_ctx {
    bool challenge1_set;
    bool challenge2_set;
    uint8_t challenge1[32];
    uint8_t challenge2[32];
};

static struct ta_commit_ctx commit_ctx;

static int cmd_ta_commit_set_challenge1(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_commit_set_challenge1 <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           commit_ctx.challenge1,
                                           sizeof(commit_ctx.challenge1));
    if (rc) {
        shell_error(shell, "Failed to parse challenge1 (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed challenge1 (32 bytes, big-endian):");
    shell_hexdump(shell, commit_ctx.challenge1, sizeof(commit_ctx.challenge1));

    commit_ctx.challenge1_set = true;
    shell_print(shell, "challenge1 set successfully");
    return 0;
}

static int cmd_ta_commit_set_challenge2(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: ta_commit_set_challenge2 <value>");
        return -EINVAL;
    }

    int rc = parse_numeric_string_to_fixed(argv[1],
                                           commit_ctx.challenge2,
                                           sizeof(commit_ctx.challenge2));
    if (rc) {
        shell_error(shell, "Failed to parse challenge2 (rc=%d)", rc);
        return rc;
    }

    shell_print(shell, "Parsed challenge2 (32 bytes, big-endian):");
    shell_hexdump(shell, commit_ctx.challenge2, sizeof(commit_ctx.challenge2));

    commit_ctx.challenge2_set = true;
    shell_print(shell, "challenge2 set successfully");
    return 0;
}

static int cmd_ta_commit(const struct shell *shell, size_t argc, char **argv)
{
    if (!commit_ctx.challenge1_set || !commit_ctx.challenge2_set) {
        shell_error(shell, "Missing required arguments. Set them first.");
        return -EINVAL;
    }

    uint8_t COM_x[32], COM_y[32];
    int rc;

    shell_print(shell, "Calling PUF_TA_get_commitment");

    int res = call_puf_ta_get_commitment(tee_dev, session_id, (uint8_t *)shm_ptr,
                                         commit_ctx.challenge1, commit_ctx.challenge2, COM_x, COM_y);
    if (res) {
        shell_error(shell, "PUF_TA_get_commitment failed: %d", res);
        shell_error(shell, "Have you ran PUF_TA_init first?");
        return res;
    }

    shell_print(shell, "COM_x (hex): ");
    shell_hexdump(shell, COM_x, sizeof(COM_x));
    shell_print(shell, "COM_y (hex): ");
    shell_hexdump(shell, COM_y, sizeof(COM_y));
    hex_to_decimal(shell, COM_x, sizeof(COM_x), "COM_x (decimal): ");
    hex_to_decimal(shell, COM_y, sizeof(COM_y), "COM_y (decimal): ");

    shell_print(shell, "PUF_TA_get_commitment success");
    return 0;
}

SHELL_CMD_REGISTER(ta_commit_set_challenge1, NULL,
                   "Set challenge1 for ta_commit_invoke", cmd_ta_commit_set_challenge1);
SHELL_CMD_REGISTER(ta_commit_set_challenge2, NULL,
                   "Set challenge2 for ta_commit_invoke", cmd_ta_commit_set_challenge2);
SHELL_CMD_REGISTER(ta_commit_invoke, NULL,
                   "Invoke PUF_TA_get_commitment with arguments set by `ta_commit_set*`", cmd_ta_commit);

int call_puf_ta_get_commitment(const struct device *tee_dev, int session_id, uint8_t *shm_ptr,
                               uint8_t challenge1[32], uint8_t challenge2[32], uint8_t COM_x[32], uint8_t COM_y[32])
{
    int ret;

    param[0].attr = TEE_PARAM_ATTR_TYPE_MEMREF_INPUT;
    param[0].a    = (uint64_t)(VMS_MEMREF0_OFFSET); // offsets
    param[0].b    = (uint64_t)32;                   // length: 32 bytes
    param[0].c    = (uint64_t)(uintptr_t)&ipc_shm;  // shared-memory ID (handle)

    param[1].attr = TEE_PARAM_ATTR_TYPE_MEMREF_INPUT;
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

    invoke_func_arg.func      = PUF_TA_GET_COMMITMENT_FUNC_ID;
    invoke_func_arg.session   = session_id;
    invoke_func_arg.cancel_id = 0;
    invoke_func_arg.ret       = 0;
    invoke_func_arg.ret_origin= 0;

    memset(shm_ptr, 0, VMS_USABLE_PAYLOAD_SIZE);
    memcpy((void *)(shm_ptr + param[0].a), challenge1, param[0].b);
    memcpy((void *)(shm_ptr + param[1].a), challenge2, param[1].b);

    ret = tee_invoke_func(tee_dev, &invoke_func_arg, 4, &param);
    if (ret == 0){
        memcpy(COM_x, (void *)(shm_ptr + param[2].a), param[2].b);
        memcpy(COM_y, (void *)(shm_ptr + param[3].a), param[3].b);
    }

    return ret;
}
