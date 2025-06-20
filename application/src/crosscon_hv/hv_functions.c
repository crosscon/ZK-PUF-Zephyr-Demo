#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(PUF_VM);

#include "hv_functions.h"
#include "puf_handler.h"
#include "puf_prover.h"
#include "crypto_handler.h"
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
        result = TEE_SUCCESS;
    } else {
        result = TEE_ERROR_BAD_STATE;
    }
    log_ecp_point("g", &g);
    log_ecp_point("h", &h);
    ret = extract_raw_commitment(&g, &raw_g);
    if (ret != 0) return TEE_ERROR_GENERIC;
    ret = extract_raw_commitment(&h, &raw_h);
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

        mbedtls_mpi response_0;
        mbedtls_mpi response_1;
        mbedtls_ecp_point commitment;

        uint8_t raw_commitment[64];
        uint8_t challenge_0[params[0].b];
        uint8_t challenge_1[params[1].b];

        LOG_INF("Reading Challenges");
        memcpy(&challenge_0, (const void *)(payload_base + params[0].a), params[0].b);
        memcpy(&challenge_1, (const void *)(payload_base + params[1].a), params[1].b);
        LOG_HEXDUMP_DBG(challenge_0, params[0].b, "C1");
        LOG_HEXDUMP_DBG(challenge_1, params[1].b, "C2");

        mbedtls_mpi_init(&response_0);
        mbedtls_mpi_init(&response_1);
        mbedtls_ecp_point_init(&commitment);

        LOG_INF("Getting Responses and Calculating Commitment");
        ret = get_response_to_challenge(&challenge_0, &response_0);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = get_response_to_challenge(&challenge_1, &response_1);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = get_commited_value(&response_0, &response_1, &commitment);

        /* Those are secrets that shouldn't be logged outside
         * of development purposes and should be immediately
         * flushed from memory */

        // log_mpi_hex("R1", &response_0);
        // log_mpi_hex("R2", &response_1);

        mbedtls_mpi_free(&response_0);
        mbedtls_mpi_free(&response_1);
        if (ret != 0) return TEE_ERROR_GENERIC;

        log_ecp_point("COM = (R1*g)+(R2*h)", &commitment);

        LOG_INF("Writing Commitment to Shared Memory");
        ret = extract_raw_commitment(&commitment, &raw_commitment);

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

        mbedtls_ecp_point proof_commitment;
	mbedtls_ecp_point_init(&proof_commitment);

        uint8_t raw_proof_commitment[64];
        uint8_t combined_raw_proof_nonce[64+params[2].b];
        uint8_t hash[32];

        mbedtls_mpi alpha;
        mbedtls_mpi_init(&alpha);

        mbedtls_mpi mult_0;
        mbedtls_mpi mult_1;
        mbedtls_mpi_init(&mult_0);
        mbedtls_mpi_init(&mult_1);

        mbedtls_mpi result_0;
        mbedtls_mpi result_1;
        mbedtls_mpi_init(&result_0);
        mbedtls_mpi_init(&result_1);

        uint8_t raw_result0[64];
        uint8_t raw_result1[64];

        mbedtls_mpi response_0;
        mbedtls_mpi response_1;

        mbedtls_mpi random_val_0; // r
        mbedtls_mpi random_val_1; // u
        mbedtls_mpi_init(&random_val_0);
        mbedtls_mpi_init(&random_val_1);

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

        ret = get_random_mpi(&random_val_0);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = get_random_mpi(&random_val_1);
        if (ret != 0) return TEE_ERROR_GENERIC;

        /* Those are secrets that shouldn't be logged outside
         * of development purposes and should be immediately
         * flushed from memory */

        // log_mpi_hex("r", &random_val_0);
        // log_mpi_hex("u", &random_val_1);

        LOG_INF("Calculating P");

        ret = get_commited_value(&random_val_0, &random_val_1, &proof_commitment);
        log_ecp_point("P = (r*g)+(u*h)", &proof_commitment);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = extract_raw_commitment(&proof_commitment, &raw_proof_commitment);
        if (ret != 0) return TEE_ERROR_GENERIC;

        memcpy(combined_raw_proof_nonce, raw_proof_commitment, 64);
        memcpy(combined_raw_proof_nonce + 64, nonce, params[2].b);

        LOG_HEXDUMP_DBG(combined_raw_proof_nonce, (64 + params[2].b), "P||n to be hashed");

        LOG_INF("Calculating α");

        mbedtls_sha256(combined_raw_proof_nonce, 64 + params[2].b, hash, 0);
        ret = mbedtls_mpi_read_binary(&alpha, hash, sizeof(hash));
        if (ret != 0) return TEE_ERROR_GENERIC;

        log_mpi_hex("α = H(P,n)", &alpha);

        mbedtls_mpi_init(&response_0);
        mbedtls_mpi_init(&response_1);

        LOG_INF("Calculating v, w");

        ret = get_response_to_challenge(&challenge_0, &response_0);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = get_response_to_challenge(&challenge_1, &response_1);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = mbedtls_mpi_mul_mpi(&mult_0, &alpha, &response_0);
        ret = mbedtls_mpi_mul_mpi(&mult_1, &alpha, &response_1);


        /* Those are secrets that shouldn't be logged outside
         * of development purposes and should be immediately
         * flushed from memory */

        // log_mpi_hex("R1", &response_0);
        // log_mpi_hex("R2", &response_1);

        // log_mpi_hex("αR1", &mult_0);
        // log_mpi_hex("αR2", &mult_1);

        ret = mbedtls_mpi_add_mpi(&result_0, &random_val_0, &mult_0);
        ret = mbedtls_mpi_add_mpi(&result_1, &random_val_1, &mult_1);

        mbedtls_mpi_free(&response_0);
        mbedtls_mpi_free(&response_1);

        mbedtls_mpi_free(&mult_0);
        mbedtls_mpi_free(&mult_1);

        log_mpi_hex("v = r+αR1", &result_0);
        log_mpi_hex("w = u+αR2", &result_1);

        mbedtls_mpi_write_binary(&result_0, raw_result0, 64);
        mbedtls_mpi_write_binary(&result_1, raw_result1, 64);

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
