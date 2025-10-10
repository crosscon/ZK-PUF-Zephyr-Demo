#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(PUF_VM);

#include "hv_functions.h"
#include "puf_prover.h"
#include "crypto.h"
#include "tee_core_compat.h"
#include "crosscon_hv_config.h"

bool has_been_initialized = false;

const func_id_map_t function_table[FUNCTION_TABLE_SIZE] = {
    {
        .func_id = PUF_TA_INIT_FUNC_ID,
        .expected_param_types = CROSSCON_PARAM_TYPES(TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT,
                                                     TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT,
                                                     TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT,
                                                     TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT),
        .expected_param_lengths = {32, 32, 32, 32},
        .handler = PUF_TA_init
    },
    {
        .func_id = PUF_TA_GET_COMMITMENT_FUNC_ID,
        .expected_param_types = CROSSCON_PARAM_TYPES(TEE_PARAM_ATTR_TYPE_MEMREF_INPUT,
                                                     TEE_PARAM_ATTR_TYPE_MEMREF_INPUT,
                                                     TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT,
                                                     TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT),
        .expected_param_lengths = {32, 32, 32, 32},
        .handler = PUF_TA_get_commitment
    },
    {
        .func_id = PUF_TA_GET_ZK_PROOFS_FUNC_ID,
        .expected_param_types = CROSSCON_PARAM_TYPES(TEE_PARAM_ATTR_TYPE_MEMREF_INOUT,
                                                     TEE_PARAM_ATTR_TYPE_MEMREF_INOUT,
                                                     TEE_PARAM_ATTR_TYPE_MEMREF_INOUT,
                                                     TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT),
        .expected_param_lengths = {32, 32, 64, 64},
        .handler = PUF_TA_get_ZK_proofs
    },
    {
        .func_id = PUF_TA_VERIFY_ZK_PROOFS_FUNC_ID,
        .expected_param_types = CROSSCON_PARAM_TYPES(TEE_PARAM_ATTR_TYPE_MEMREF_INPUT,
                                                     TEE_PARAM_ATTR_TYPE_NONE,
                                                     TEE_PARAM_ATTR_TYPE_NONE,
                                                     TEE_PARAM_ATTR_TYPE_NONE),
        .expected_param_lengths = {448, 0, 0, 0},
        .handler = PUF_TA_verify_ZK_proofs
    }
};

TEE_Result PUF_TA_init(void)
{
    volatile uint8_t *payload_base = VMS_PAYLOAD_PTR;
    volatile GP_Param *params = GP_PARAMS_PTR;

    uint8_t raw_g[64];
    uint8_t raw_h[64];
    int ret;
    TEE_Result result;

    if(!has_been_initialized){
        ret = init_puf();
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = init_crypto();
        if (ret != 0) return TEE_ERROR_GENERIC;

        has_been_initialized = true;
    }

    result = TEE_SUCCESS;

    log_ecp_point("g", g);
    log_ecp_point("h", h);

    ret = extract_raw_commitment(g, &raw_g);
    if (ret != 0) return TEE_ERROR_GENERIC;
    ret = extract_raw_commitment(h, &raw_h);
    if (ret != 0) return TEE_ERROR_GENERIC;

    // TODO Fix esoteric bug
    // For some reason these lines started giving a fault exception
    // on the CROSSCON HV randomly when adding Session Handling logic
    // LOG_HEXDUMP_DBG(raw_g, 64, "Raw g");
    // LOG_HEXDUMP_DBG(raw_h, 64, "Raw h");

    LOG_INF("Writing g and h to Shared Memory");

    memcpy((void *)(payload_base + params[0].a), raw_g + 0,  params[0].b);
    memcpy((void *)(payload_base + params[1].a), raw_g + 32, params[1].b);
    memcpy((void *)(payload_base + params[2].a), raw_h + 0,  params[2].b);
    memcpy((void *)(payload_base + params[3].a), raw_h + 32, params[3].b);

    return result;
}

TEE_Result PUF_TA_get_commitment(void)
{
    if(!has_been_initialized){
        return TEE_ERROR_GENERIC;
    } else {
        volatile uint8_t *payload_base = (volatile uint8_t *)VMS_PAYLOAD_PTR;
        volatile GP_Param *params = GP_PARAMS_PTR;

        int ret;

        TEE_BigInt *response_0 = TEE_BigIntAlloc();
        TEE_BigInt *response_1 = TEE_BigIntAlloc();
        TEE_ECPoint *commitment = TEE_ECPointAlloc();

        uint8_t raw_commitment[64];
        uint8_t challenge_0[params[0].b];
        uint8_t challenge_1[params[1].b];

        LOG_INF("Reading Challenges");
        memcpy(&challenge_0, (const void *)(payload_base + params[0].a), params[0].b);
        memcpy(&challenge_1, (const void *)(payload_base + params[1].a), params[1].b);
        LOG_HEXDUMP_DBG(challenge_0, params[0].b, "C1");
        LOG_HEXDUMP_DBG(challenge_1, params[1].b, "C2");

        LOG_INF("Getting Responses and Calculating Commitment");
        ret = get_response_to_challenge(&challenge_0, response_0);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = get_response_to_challenge(&challenge_1, response_1);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = get_commited_value(response_0, response_1, commitment);

        /* Those are secrets that shouldn't be logged outside
         * of development purposes and should be immediately
         * flushed from memory */

        // log_bigint_hex("R1", &response_0);
        // log_bigint_hex("R2", &response_1);

        TEE_BigIntFree(response_0);
        TEE_BigIntFree(response_1);
        if (ret != 0) return TEE_ERROR_GENERIC;

        log_ecp_point("COM = (R1*g)+(R2*h)", commitment);

        LOG_INF("Writing Commitment to Shared Memory");
        ret = extract_raw_commitment(commitment, &raw_commitment);

        LOG_HEXDUMP_DBG(raw_commitment, 64, "Raw COM to be written");

        if (ret != 0) return TEE_ERROR_GENERIC;

        memcpy((void *)(payload_base + params[2].a), raw_commitment + 0,  params[2].b);
        memcpy((void *)(payload_base + params[3].a), raw_commitment + 32, params[3].b);

        return TEE_SUCCESS;
    }
}

TEE_Result PUF_TA_get_ZK_proofs(void)
{
    if(!has_been_initialized){
        return TEE_ERROR_GENERIC;
    } else {
        volatile uint8_t *payload_base = (volatile uint8_t *)VMS_PAYLOAD_PTR;
        volatile GP_Param *params = GP_PARAMS_PTR;

        int ret;

        TEE_ECPoint *proof_commitment = TEE_ECPointAlloc();

        uint8_t raw_proof_commitment[64];
        uint8_t combined_raw_proof_nonce[64+params[2].b];
        uint8_t hash[32];
        size_t hash_len = sizeof(hash);

        TEE_BigInt *alpha = TEE_BigIntAlloc();

        TEE_BigInt *mult_0 = TEE_BigIntAlloc();
        TEE_BigInt *mult_1 = TEE_BigIntAlloc();

        TEE_BigInt *result_0 = TEE_BigIntAlloc();
        TEE_BigInt *result_1 = TEE_BigIntAlloc();

        uint8_t raw_result0[64];
        uint8_t raw_result1[64];

        TEE_BigInt *response_0 = TEE_BigIntAlloc();
        TEE_BigInt *response_1 = TEE_BigIntAlloc();

        TEE_BigInt *random_val_0 = TEE_BigIntAlloc(); // r
        TEE_BigInt *random_val_1 = TEE_BigIntAlloc(); // u

        TEE_DigestOperation *digest = TEE_AllocateDigestOperation();

        uint8_t challenge_0[params[0].b];
        uint8_t challenge_1[params[1].b];
        uint8_t nonce[params[2].b];

        LOG_INF("Reading Challenges and Nonce");

        memcpy(&challenge_0, (const void *)(payload_base + params[0].a), params[0].b);
        memcpy(&challenge_1, (const void *)(payload_base + params[1].a), params[1].b);
        memcpy(&nonce,       (const void *)(payload_base + params[2].a), params[2].b);

        LOG_HEXDUMP_DBG(challenge_0, params[0].b, "C1");
        LOG_HEXDUMP_DBG(challenge_1, params[1].b, "C2");
        LOG_HEXDUMP_DBG(nonce, params[2].b, "n");

        LOG_INF("Getting random values r and u");

        ret = TEE_BigIntGenerateRandom(random_val_0, 32, NULL, NULL);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = TEE_BigIntGenerateRandom(random_val_1, 32, NULL, NULL);
        if (ret != 0) return TEE_ERROR_GENERIC;

        /* Those are secrets that shouldn't be logged outside
         * of development purposes and should be immediately
         * flushed from memory */

        // log_bigint_hex("r", random_val_0);
        // log_bigint_hex("u", random_val_1);

        LOG_INF("Calculating P");

        ret = get_commited_value(random_val_0, random_val_1, proof_commitment);
        log_ecp_point("P = (r*g)+(u*h)", proof_commitment);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = extract_raw_commitment(proof_commitment, &raw_proof_commitment);
        if (ret != 0) return TEE_ERROR_GENERIC;

        memcpy(combined_raw_proof_nonce, raw_proof_commitment, 64);
        memcpy(combined_raw_proof_nonce + 64, nonce, params[2].b);

        LOG_HEXDUMP_DBG(combined_raw_proof_nonce, (64 + params[2].b), "P||n to be hashed");

        LOG_INF("Calculating α");

        ret = TEE_DigestUpdate(digest, combined_raw_proof_nonce, 64 + params[2].b);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = TEE_DigestDoFinal(digest, NULL, 0, hash, &hash_len);
        if (ret != 0) return TEE_ERROR_GENERIC;
        TEE_FreeDigestOperation(digest);

        ret = TEE_BigIntConvertFromBytes(alpha, hash, hash_len);
        if (ret != 0) return TEE_ERROR_GENERIC;

        log_bigint_hex("α = H(P,n)", alpha);

        LOG_INF("Calculating v, w");

        ret = get_response_to_challenge(&challenge_0, response_0);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = get_response_to_challenge(&challenge_1, response_1);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = TEE_BigIntMul(mult_0, alpha, response_0);
        ret = TEE_BigIntMul(mult_1, alpha, response_1);

        /* Those are secrets that shouldn't be logged outside
         * of development purposes and should be immediately
         * flushed from memory */

        // log_bigint_hex("R1", response_0);
        // log_bigint_hex("R2", response_1);

        // log_bigint_hex("αR1", mult_0);
        // log_bigint_hex("αR2", mult_1);

        ret = TEE_BigIntAdd(result_0, random_val_0, mult_0);
        ret = TEE_BigIntAdd(result_1, random_val_1, mult_1);

        TEE_BigIntFree(response_0);
        TEE_BigIntFree(response_1);

        TEE_BigIntFree(mult_0);
        TEE_BigIntFree(mult_1);

        log_bigint_hex("v = r+αR1", result_0);
        log_bigint_hex("w = u+αR2", result_1);

        TEE_BigIntConvertToBytes(result_0, raw_result0, 64);
        TEE_BigIntConvertToBytes(result_1, raw_result1, 64);

        LOG_HEXDUMP_DBG(raw_proof_commitment, 64, "Raw P to be written");

        LOG_HEXDUMP_DBG(raw_result0, 64, "Raw v to be written");
        LOG_HEXDUMP_DBG(raw_result1, 64, "Raw w to be written");

        LOG_INF("Writing P, v, w to Shared Memory");

        memcpy((void *)(payload_base + params[0].a), raw_proof_commitment + 0,  params[0].b);
        memcpy((void *)(payload_base + params[1].a), raw_proof_commitment + 32, params[1].b);
        memcpy((void *)(payload_base + params[2].a), raw_result0,               params[2].b);
        memcpy((void *)(payload_base + params[3].a), raw_result1,               params[3].b);

        return TEE_SUCCESS;
    }
}


TEE_Result PUF_TA_verify_ZK_proofs(void)
{
    if (!has_been_initialized) {
        return TEE_ERROR_GENERIC;
    } else {
        volatile uint8_t *payload_base = (volatile uint8_t *)VMS_PAYLOAD_PTR;
        volatile GP_Param *params = GP_PARAMS_PTR;

        int ret;

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

        uint8_t combined_raw_proof_nonce[128];
        TEE_DigestOperation *digest = TEE_AllocateDigestOperation();
        uint8_t hash[32];
        size_t hash_len = sizeof(hash);

        TEE_BigInt *alpha = TEE_BigIntAlloc();

        TEE_ECPoint *g_pt = TEE_ECPointAlloc();
        TEE_ECPoint *h_pt = TEE_ECPointAlloc();
        TEE_ECPoint *COM_pt = TEE_ECPointAlloc();
        TEE_ECPoint *P_pt = TEE_ECPointAlloc();

        TEE_BigInt *order = TEE_BigIntAlloc();
        TEE_BigInt *v_bigint = TEE_BigIntAlloc();
        TEE_BigInt *w_bigint = TEE_BigIntAlloc();

        TEE_BigInt  *one = TEE_BigIntAlloc();

        TEE_ECPoint *proof_left = TEE_ECPointAlloc();
        TEE_ECPoint *proof_right = TEE_ECPointAlloc();

        /* sanity: ensure param[0] contains at least the whole struct */
        if (params[0].b < (uint64_t)sizeof(zk_proofs_mem_struct)) {
            LOG_ERR("Shared-memory region too small: %llu < %zu", params[0].b, sizeof(zk_proofs_mem_struct));
            return TEE_ERROR_BAD_PARAMETERS;
        }

        /* pointer to the shared-memory payload (offset already provided in params[0].a) */
        uint8_t *shm_ptr = (uint8_t *)(payload_base + params[0].a);
        zk_proofs_mem_struct *m = (zk_proofs_mem_struct *)shm_ptr;

        /* copy each field into local buffers */
        memcpy(g_x,  m->g_x,  32);
        memcpy(g_y,  m->g_y,  32);
        memcpy(h_x,  m->h_x,  32);
        memcpy(h_y,  m->h_y,  32);
        memcpy(COM_x,m->COM_x,32);
        memcpy(COM_y,m->COM_y,32);
        memcpy(P_x,  m->P_x,  32);
        memcpy(P_y,  m->P_y,  32);
        memcpy(v,    m->v,    64);
        memcpy(w,    m->w,    64);
        memcpy(nonce,    m->nonce,    64);

        LOG_HEXDUMP_DBG(g_x, sizeof(g_x), "g_x");
        LOG_HEXDUMP_DBG(g_y, sizeof(g_y), "g_y");
        LOG_HEXDUMP_DBG(h_x, sizeof(h_x), "h_x");
        LOG_HEXDUMP_DBG(h_y, sizeof(h_y), "h_y");
        LOG_HEXDUMP_DBG(COM_x, sizeof(COM_x), "COM_x");
        LOG_HEXDUMP_DBG(COM_y, sizeof(COM_y), "COM_y");
        LOG_HEXDUMP_DBG(P_x, sizeof(P_x), "P_x");
        LOG_HEXDUMP_DBG(P_y, sizeof(P_y), "P_y");
        LOG_HEXDUMP_DBG(v, sizeof(v), "v");
        LOG_HEXDUMP_DBG(w, sizeof(w), "w");
        LOG_HEXDUMP_DBG(nonce, sizeof(nonce), "nonce");

        memcpy(combined_raw_proof_nonce, P_x, 32);
        memcpy(combined_raw_proof_nonce + 32, P_y, 32);
        memcpy(combined_raw_proof_nonce + 64, nonce, 64);

        LOG_HEXDUMP_DBG(combined_raw_proof_nonce, 128, "P||n to be hashed");

        LOG_INF("Calculating α");

        ret = TEE_DigestUpdate(digest, combined_raw_proof_nonce, 128);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = TEE_DigestDoFinal(digest, NULL, 0, hash, &hash_len);
        if (ret != 0) return TEE_ERROR_GENERIC;
        TEE_FreeDigestOperation(digest);

        ret = TEE_BigIntConvertFromBytes(alpha, hash, hash_len);
        if (ret != 0) return TEE_ERROR_GENERIC;

        log_bigint_hex("α = H(P,n)", alpha);

        ret = TEE_ECPointConvertFromXYBytes(g_pt, grp, g_x, 32, g_y, 32);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = TEE_ECPointConvertFromXYBytes(h_pt, grp, h_x, 32, h_y, 32);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = TEE_ECPointConvertFromXYBytes(COM_pt, grp, COM_x, 32, COM_y, 32);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = TEE_ECPointConvertFromXYBytes(P_pt, grp, P_x, 32, P_y, 32);
        if (ret != 0) return TEE_ERROR_GENERIC;

        log_ecp_point("g",   g_pt);
        log_ecp_point("h",   h_pt);
        log_ecp_point("COM", COM_pt);
        log_ecp_point("P",   P_pt);

        ret = TEE_BigIntConvertFromBytes(v_bigint, v, 64);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = TEE_BigIntConvertFromBytes(w_bigint, w, 64);
        if (ret != 0) return TEE_ERROR_GENERIC;

        log_bigint_hex("v", v_bigint);
        log_bigint_hex("w", w_bigint);

        if (TEE_ECCurveGetOrder(grp, order) != TEE_SUCCESS) {
            LOG_ERR("TEE_ECCurveGetOrder failed");
            TEE_BigIntFree(order);
            return TEE_ERROR_GENERIC;
        }

        /* reduce v and w modulo order */
        if (TEE_BigIntMod(v_bigint, v_bigint, order) != TEE_SUCCESS) {
            LOG_ERR("Failed to reduce v mod order");
            TEE_BigIntFree(order);
            return TEE_ERROR_GENERIC;
        }
        if (TEE_BigIntMod(w_bigint, w_bigint, order) != TEE_SUCCESS) {
            LOG_ERR("Failed to reduce w mod order");
            TEE_BigIntFree(order);
            return TEE_ERROR_GENERIC;
        }

        ret = TEE_ECPointMulAdd(proof_left, grp, v_bigint, g_pt, w_bigint, h_pt);
        log_ecp_point("g^v*h^w", proof_left);
        if (ret != 0) return TEE_ERROR_GENERIC;

        TEE_BigIntSetWord(one, 1);

        // add P → proof_right = P + α*COM
        ret = TEE_ECPointMulAdd(proof_right, grp, one, P_pt, alpha, COM_pt);
        if (ret != TEE_SUCCESS) {
            LOG_ERR("Failed to compute P + α*COM");
            return TEE_ERROR_GENERIC;
        }

        log_ecp_point("P + α*COM", proof_right);

        // compare proof_left with proof_right
        uint8_t buf_left[65], buf_right[65];
        size_t len_left = sizeof(buf_left), len_right = sizeof(buf_right);

        ret = TEE_ECPointExportBytes(proof_left, grp, buf_left, &len_left);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = TEE_ECPointExportBytes(proof_right, grp, buf_right, &len_right);
        if (ret != 0) return TEE_ERROR_GENERIC;

        if (len_left == len_right && memcmp(buf_left, buf_right, len_left) == 0) {
            LOG_INF("✅ Proof verifies: g^v*h^w = P*COM^α");
            return TEE_SUCCESS;
        } else {
            LOG_INF("❌ Proof FAILED");
            return TEE_ERROR_SECURITY;
        }
    }
}
