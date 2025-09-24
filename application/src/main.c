#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(GUEST_VM);

#include <stdio.h>
#include "crosscon_hv_config.h"
#include <zephyr/kernel.h>
#include <mbedtls/bignum.h>
#include <zephyr/shell/shell.h>

#define CLIENT_UUID_BYTES { \
    0x10, 0x20, 0x30, 0x40, \
    0x50, 0x60, \
    0x70, 0x80, \
    0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00 \
}

#define PUF_TA_UUID_BYTES { \
    0x00, 0x11, 0x22, 0x33, \
    0x44, 0x55, \
    0x66, 0x77, \
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF \
}

#define PUF_TA_INIT_FUNC_ID                 0x00112233
#define PUF_TA_GET_COMMITMENT_FUNC_ID       0x11223344
#define PUF_TA_GET_ZK_PROOFS_FUNC_ID        0x22334455

static const uint8_t PUF_TA_UUID[TEE_UUID_LEN] = PUF_TA_UUID_BYTES;

static const uint8_t CLIENT_UUID[TEE_UUID_LEN] = CLIENT_UUID_BYTES;

/* Global vars or context for TEE session */
static const struct device *tee_dev;
static volatile uint8_t *shm_ptr;

/* Parses a numeric string into a fixed-length big-endian byte buffer.
 * - If `str` starts with "0x" or "0X" it is parsed as hex (base 16).
 * - Otherwise it is parsed as decimal (base 10).
 * - The resulting value is written as big-endian into `out` of length out_len.
 * - If the value needs more than out_len bytes -> returns -EOVERFLOW.
 * - Returns 0 on success or negative errno on error.
 */
static int parse_numeric_string_to_fixed(const char *str, uint8_t *out, size_t out_len)
{
    int ret;
    mbedtls_mpi mpi;
    const char *p = str;
    int base = 10;

    if (!str || !out || out_len == 0) {
        return -EINVAL;
    }

    if ((str[0] == '0') && (str[1] == 'x' || str[1] == 'X')) {
        base = 16;
        p = str + 2; /* skip 0x prefix */
        if (*p == '\0') {
            return -EINVAL; /* only "0x" provided */
        }
    }

    mbedtls_mpi_init(&mpi);

    /* read string into mpi (handles arbitrary length decimal/hex) */
    ret = mbedtls_mpi_read_string(&mpi, base, p);
    if (ret != 0) {
        mbedtls_mpi_free(&mpi);
        return -EINVAL;
    }

    /* check required bytes */
    size_t bits = mbedtls_mpi_bitlen(&mpi); /* 0 if value == 0 */
    size_t needed_bytes = (bits + 7) / 8;
    if (needed_bytes == 0) {
        needed_bytes = 1; /* represent zero as one zero byte, but we'll still write full out_len */
    }

    if (needed_bytes > out_len) {
        mbedtls_mpi_free(&mpi);
        return -EOVERFLOW;
    }

    /* zero entire output buffer and write big-endian representation into it */
    memset(out, 0, out_len);
    ret = mbedtls_mpi_write_binary(&mpi, out, out_len); /* writes exactly out_len bytes, MSB first */
    if (ret != 0) {
        mbedtls_mpi_free(&mpi);
        return -EIO;
    }

    mbedtls_mpi_free(&mpi);
    return 0;
}

/* Shell commands */
static int cmd_ta_init(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 1) {
        shell_error(shell, "Wrong amount of parameters.\nUsage: ta_init");
        return -EINVAL;
    }

    uint8_t g_x[32], g_y[32], h_x[32], h_y[32];
    int res = call_puf_ta_init(tee_dev, session_id, (uint8_t *)shm_ptr, g_x, g_y, h_x, h_y);
    if (res) {
        shell_error(shell, "PUF_TA_init failed: %d", res);
        return res;
    }
    shell_print(shell, "PUF_TA_init success");
    return 0;
}

static int cmd_ta_commit(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 3) {
        shell_error(shell, "Usage: ta_commit <challenge1> <challenge2>");
        shell_print(shell, "challenge may be decimal or hex prefixed with 0x (fits in 32 bytes)");
        return -EINVAL;
    }

    uint8_t challenge1[32], challenge2[32], COM_x[32], COM_y[32];
    int rc;

    /* Debug: show raw input strings */
    shell_print(shell, "Raw challenge1 string (len=%zu):", strlen(argv[1]));
    shell_hexdump(shell, (const uint8_t *)argv[1], strlen(argv[1]));

    shell_print(shell, "Raw challenge2 string (len=%zu):", strlen(argv[2]));
    shell_hexdump(shell, (const uint8_t *)argv[2], strlen(argv[2]));

    /* Parse either decimal or 0x-hex into 32-byte big-endian buffers */
    rc = parse_numeric_string_to_fixed(argv[1], challenge1, sizeof(challenge1));
    if (rc == -EOVERFLOW) {
        shell_error(shell, "challenge1 too large to fit in 32 bytes");
        return rc;
    } else if (rc != 0) {
        shell_error(shell, "Invalid challenge1 (not a decimal or 0x-hex number)");
        return rc;
    }

    rc = parse_numeric_string_to_fixed(argv[2], challenge2, sizeof(challenge2));
    if (rc == -EOVERFLOW) {
        shell_error(shell, "challenge2 too large to fit in 32 bytes");
        return rc;
    } else if (rc != 0) {
        shell_error(shell, "Invalid challenge2 (not a decimal or 0x-hex number)");
        return rc;
    }

    /* Debug: show parsed fixed-size big-endian buffers */
    shell_print(shell, "Parsed challenge1 (32 bytes, big-endian):");
    shell_hexdump(shell, challenge1, sizeof(challenge1));

    shell_print(shell, "Parsed challenge2 (32 bytes, big-endian):");
    shell_hexdump(shell, challenge2, sizeof(challenge2));

    int res = call_puf_ta_get_commitment(tee_dev, session_id, (uint8_t *)shm_ptr,
                                         challenge1, challenge2, COM_x, COM_y);
    if (res) {
        shell_error(shell, "PUF_TA_get_commitment failed: %d", res);
        return res;
    }
    shell_print(shell, "PUF_TA_get_commitment success");
    return 0;
}

static int cmd_ta_zk(const struct shell *shell, size_t argc, char **argv)
{

    if (argc != 4) {
        shell_error(shell, "Usage: ta_zk <challenge1> <challenge2> <nonce>");
        shell_print(shell, "values may be decimal or hex prefixed with 0x (challenge - 32 bytes, nonce - 64 bytes)");
        return -EINVAL;
    }

    uint8_t challenge1[32], challenge2[32], nonce[64];
    uint8_t P_x[32], P_y[32], v[64], w[64];
    int rc;

    shell_print(shell, "Raw challenge1 string (len=%zu):", strlen(argv[1]));
    shell_hexdump(shell, (const uint8_t *)argv[1], strlen(argv[1]));

    shell_print(shell, "Raw challenge2 string (len=%zu):", strlen(argv[2]));
    shell_hexdump(shell, (const uint8_t *)argv[2], strlen(argv[2]));

    shell_print(shell, "Raw nonce string (len=%zu):", strlen(argv[3]));
    shell_hexdump(shell, (const uint8_t *)argv[3], strlen(argv[3]));

    /* Parse either decimal or 0x-hex into 32-byte big-endian buffers */
    rc = parse_numeric_string_to_fixed(argv[1], challenge1, sizeof(challenge1));
    if (rc == -EOVERFLOW) {
        shell_error(shell, "challenge1 too large to fit in 32 bytes");
        return rc;
    } else if (rc != 0) {
        shell_error(shell, "Invalid challenge1 (not a decimal or 0x-hex number)");
        return rc;
    }

    rc = parse_numeric_string_to_fixed(argv[2], challenge2, sizeof(challenge2));
    if (rc == -EOVERFLOW) {
        shell_error(shell, "challenge2 too large to fit in 32 bytes");
        return rc;
    } else if (rc != 0) {
        shell_error(shell, "Invalid challenge2 (not a decimal or 0x-hex number)");
        return rc;
    }

    rc = parse_numeric_string_to_fixed(argv[3], nonce, sizeof(nonce));
    if (rc == -EOVERFLOW) {
        shell_error(shell, "nonce too large to fit in 64 bytes");
        return rc;
    } else if (rc != 0) {
        shell_error(shell, "Invalid nonce (not a decimal or 0x-hex number)");
        return rc;
    }

    /* Debug: show parsed fixed-size big-endian buffers */
    shell_print(shell, "Parsed challenge1 (32 bytes, big-endian):");
    shell_hexdump(shell, challenge1, sizeof(challenge1));

    shell_print(shell, "Parsed challenge2 (32 bytes, big-endian):");
    shell_hexdump(shell, challenge2, sizeof(challenge2));

    shell_print(shell, "Parsed nonce (64 bytes, big-endian):");
    shell_hexdump(shell, nonce, sizeof(nonce));

    int res = call_puf_ta_get_zk_proofs(tee_dev, session_id, (uint8_t *)shm_ptr,
                                        challenge1, challenge2, nonce,
                                        P_x, P_y, v, w);
    if (res) {
        shell_error(shell, "PUF_TA_get_ZK_proofs failed: %d", res);
        return res;
    }
    shell_print(shell, "PUF_TA_get_ZK_proofs success");
    return 0;
}

/* Register commands under one root (e.g., `tee`) */
SHELL_CMD_REGISTER(ta_init, NULL, "Call PUF_TA_init", cmd_ta_init);
SHELL_CMD_REGISTER(ta_commit, NULL, "Call PUF_TA_get_commitment", cmd_ta_commit);
SHELL_CMD_REGISTER(ta_zk, NULL, "Call PUF_TA_get_ZK_proofs", cmd_ta_zk);

// Helper functions to make the calling function logic easier to read
int call_puf_ta_init(const struct device *tee_dev, int session_id, uint8_t *shm_ptr,
                     uint8_t g_x[32], uint8_t g_y[32], uint8_t h_x[32], uint8_t h_y[32])
{
    int ret;

    LOG_INF("Calling PUF_TA_init");

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

        LOG_HEXDUMP_DBG(g_x, 32, "g_x (hex): ");
        LOG_HEXDUMP_DBG(g_y, 32, "g_y (hex): ");
        LOG_HEXDUMP_DBG(h_x, 32, "h_x (hex): ");
        LOG_HEXDUMP_DBG(h_y, 32, "h_y (hex): ");

        hex_to_decimal(g_x, 32, "g_x (decimal): ");
        hex_to_decimal(g_y, 32, "g_y (decimal): ");
        hex_to_decimal(h_x, 32, "h_x (decimal): ");
        hex_to_decimal(h_y, 32, "h_y (decimal): ");
    }

    return ret;
}

int call_puf_ta_get_commitment(const struct device *tee_dev, int session_id, uint8_t *shm_ptr,
                               uint8_t challenge1[32], uint8_t challenge2[32], uint8_t COM_x[32], uint8_t COM_y[32])
{
    int ret;

    LOG_INF("Calling PUF_TA_get_commitment");

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

    memset(shm_ptr, 0, 1024);
    memcpy((void *)(shm_ptr + param[0].a), challenge1, param[0].b);
    memcpy((void *)(shm_ptr + param[1].a), challenge2, param[1].b);

    ret = tee_invoke_func(tee_dev, &invoke_func_arg, 4, &param);
    if (ret == 0){
        memcpy(COM_x, (void *)(shm_ptr + param[2].a), param[2].b);
        memcpy(COM_y, (void *)(shm_ptr + param[3].a), param[3].b);

        LOG_HEXDUMP_DBG(COM_x, 32, "COM_x (hex): ");
        LOG_HEXDUMP_DBG(COM_y, 32, "COM_y (hex): ");

        hex_to_decimal(COM_x, 32, "COM_x (decimal): ");
        hex_to_decimal(COM_y, 32, "COM_y (decimal): ");
    }

    return ret;
}


int call_puf_ta_get_zk_proofs(const struct device *tee_dev, int session_id, uint8_t *shm_ptr,
                              uint8_t challenge1[32], uint8_t challenge2[32], uint8_t nonce[64],
                              uint8_t P_x[32], uint8_t P_y[32], uint8_t v[64], uint8_t w[64])
{
    int ret;

    LOG_INF("Calling PUF_TA_get_ZK_proofs");

    LOG_HEXDUMP_INF(nonce, 64, "used nonce (hex): ");

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

    memset(shm_ptr, 0, 1024);
    memcpy((void *)(shm_ptr + param[0].a), challenge1, param[0].b);
    memcpy((void *)(shm_ptr + param[1].a), challenge2, param[1].b);
    memcpy((void *)(shm_ptr + param[2].a), nonce, param[2].b);

    ret = tee_invoke_func(tee_dev, &invoke_func_arg, 4, &param);
    if (ret == 0){
        memcpy(P_x, (void *)(shm_ptr + param[0].a), param[0].b);
        memcpy(P_y, (void *)(shm_ptr + param[1].a), param[1].b);
        memcpy(v,   (void *)(shm_ptr + param[2].a), param[2].b);
        memcpy(w,   (void *)(shm_ptr + param[3].a), param[3].b);

        LOG_HEXDUMP_DBG(P_x, 32, "P_x (hex): ");
        LOG_HEXDUMP_DBG(P_y, 32, "P_y (hex): ");
        LOG_HEXDUMP_DBG(v,   64, "v (hex): ");
        LOG_HEXDUMP_DBG(w,   64, "w (hex): ");

        hex_to_decimal(P_x, 32, "P_x (decimal): ");
        hex_to_decimal(P_y, 32, "P_y (decimal): ");
        hex_to_decimal(v,   64, "v (decimal): ");
        hex_to_decimal(w,   64, "w (decimal): ");
    }

    return ret;
}

void hex_to_decimal(uint8_t *array, size_t len, const char *label)
{
    int ret;
    mbedtls_mpi mpi;
    mbedtls_mpi_init(&mpi);

    // Convert raw bytes into an MPI
    ret = mbedtls_mpi_read_binary(&mpi, array, len);
    if (ret != 0) {
        LOG_ERR("Failed to read binary into MPI: -0x%04X", -ret);
        mbedtls_mpi_free(&mpi);
        return;
    }

    // Determine how much space is needed
    size_t required_len = 0;
    ret = mbedtls_mpi_write_string(&mpi, 10, NULL, 0, &required_len);
    if (ret != MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL) {
        LOG_ERR("Failed to calculate string length: -0x%04X", -ret);
        mbedtls_mpi_free(&mpi);
        return;
    }

    // Allocate the buffer
    char *decimal_str = malloc(required_len);
    if (!decimal_str) {
        LOG_ERR("Failed to allocate memory for decimal string");
        mbedtls_mpi_free(&mpi);
        return;
    }

    // Write the string for real
    ret = mbedtls_mpi_write_string(&mpi, 10, decimal_str, required_len, &required_len);
    if (ret != 0) {
        LOG_ERR("Failed to convert MPI to string: -0x%04X", -ret);
        free(decimal_str);
        mbedtls_mpi_free(&mpi);
        return;
    }

    LOG_INF("%s%s", label, decimal_str);

    free(decimal_str);
    mbedtls_mpi_free(&mpi);
}

int main(void)
{
    LOG_INF("Initializing TEE");

    tee_dev = device_get_binding("crosscon_hv_tee");
    if (!tee_dev) {
        LOG_ERR("Failed to bind device 'crosscon_hv_tee'");
        return -1;
    }

    ipc_shm.dev   = tee_dev;
    ipc_shm.addr  = (void *)(uintptr_t)VMS_PAYLOAD_PTR;
    ipc_shm.size  = (uint64_t)VMS_USABLE_PAYLOAD_SIZE;
    ipc_shm.flags = 0;
    shm_ptr = (volatile uint8_t *)ipc_shm.addr;

    memcpy(session_arg.uuid, PUF_TA_UUID, TEE_UUID_LEN);
    memcpy(session_arg.clnt_uuid, CLIENT_UUID, TEE_UUID_LEN);
    session_arg.clnt_login = TEE_IOCTL_LOGIN_USER;
    session_arg.cancel_id  = 0;

    int res = tee_open_session(tee_dev, &session_arg, 0, NULL, &session_id);
    if (res || session_arg.ret) {
        LOG_ERR("tee_open_session() failed: res=%d, TEE_ret=0x%08x", res, session_arg.ret);
        return -1;
    }

    LOG_INF("TEE Session opened: ID = %u", session_id);
    LOG_INF("Shell ready. Try `ta_init`, `ta_commit`, `ta_zk`");

    return 0;
}
