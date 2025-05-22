#include "hv_functions.h"
#include "puf_handler.h"
#include "puf_prover.h"
#include "crypto_handler.h"
#include "crosscon_hv_config.h"

bool has_been_initialized = false;

const uuid_func_map_t function_table[FUNCTION_TABLE_SIZE] = {
    {
        .uuid = {
            0x00, 0x11, 0x22, 0x33,   /* timeLow    */
            0x44, 0x55,               /* timeMid    */
            0x66, 0x77,               /* timeHi+ver */
            0x88, 0x99, 0xAA, 0xBB,   /* clockSeq   */
            0xCC, 0xDD, 0xEE, 0xFF    /* node       */
        },
        .handler = PUF_TA_init,
        .arg0    = message[2],
        .arg1    = message[3],
        .arg2    = message[4],
        .arg3    = message[5],
    },
    {
        .uuid = {
            0x11, 0x22, 0x33, 0x44,   /* timeLow    */
            0x55, 0x66,               /* timeMid    */
            0x77, 0x88,               /* timeHi+ver */
            0x99, 0xAA, 0xBB, 0xCC,   /* clockSeq   */
            0xDD, 0xEE, 0xFF, 0x00    /* node       */
        },
        .handler = PUF_TA_get_commitment,
        .arg0    = message[2],
        .arg1    = message[3],
        .arg2    = message[4],
        .arg3    = message[5],
    },
    {
        .uuid = {
            0x22, 0x33, 0x44, 0x55,   /* timeLow    */
            0x66, 0x77,               /* timeMid    */
            0x88, 0x99,               /* timeHi+ver */
            0xAA, 0xBB, 0xCC, 0xDD,   /* clockSeq   */
            0xEE, 0xFF, 0x00, 0x11    /* node       */
        },
        .handler = PUF_TA_get_ZK_proofs,
        .arg0    = message[2],
        .arg1    = message[3],
        .arg2    = message[4],
        .arg3    = message[5],
    }
};

TEE_Result PUF_TA_init(void* shared_mem0, void* shared_mem1, void* shared_mem2, void* shared_mem3)
{
    int ret;
    ret = init_puf();
    if (ret != 0) return TEE_ERROR_GENERIC;
    ret = init_crypto();
    if (ret != 0) return TEE_ERROR_GENERIC;
    /* For now hardcoding/testing shmem reading */
    memcpy(shared_mem0, &hardcoded_challenge_0, CHALLENGE_SIZE);
    memcpy(shared_mem1, &hardcoded_challenge_1, CHALLENGE_SIZE);
    has_been_initialized = true;
    return TEE_SUCCESS;
}

TEE_Result PUF_TA_get_commitment(void* shared_mem0, void* shared_mem1, void* shared_mem2, void* shared_mem3)
{
    if(!has_been_initialized){
        return TEE_ERROR_GENERIC;
    } else {
        int ret;
        mbedtls_mpi response_0;
        mbedtls_mpi response_1;
        mbedtls_ecp_point commitment;
        uint8_t raw_commitment[64];
        uint8_t challenge_0[CHALLENGE_SIZE];
        uint8_t challenge_1[CHALLENGE_SIZE];
        memcpy(&challenge_0, shared_mem0, CHALLENGE_SIZE);
        memcpy(&challenge_1, shared_mem1, CHALLENGE_SIZE);
        mbedtls_mpi_init(&response_0);
        mbedtls_mpi_init(&response_1);
	mbedtls_ecp_point_init(&commitment);
        ret = get_response_to_challenge(&challenge_0, &response_0);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = get_response_to_challenge(&challenge_1, &response_1);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = get_commited_value(&response_0, &response_1, &commitment);
        mbedtls_mpi_free(&response_0);
        mbedtls_mpi_free(&response_1);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = extract_raw_commitment(&commitment, &raw_commitment);
        if (ret != 0) return TEE_ERROR_GENERIC;
        memcpy(shared_mem0, raw_commitment +  0, 16);
        memcpy(shared_mem1, raw_commitment + 16, 16);
        memcpy(shared_mem2, raw_commitment + 32, 16);
        memcpy(shared_mem3, raw_commitment + 48, 16);
        return TEE_SUCCESS;
    }
}

TEE_Result PUF_TA_get_ZK_proofs(void* shared_mem0, void* shared_mem1, void* shared_mem2, void* shared_mem3)
{
    if(!has_been_initialized){
        return TEE_ERROR_GENERIC;
    } else {
        int ret;
        mbedtls_mpi response_0;
        mbedtls_mpi response_1;
        uint8_t challenge_0[CHALLENGE_SIZE];
        uint8_t challenge_1[CHALLENGE_SIZE];
        memcpy(&challenge_0, shared_mem0, CHALLENGE_SIZE);
        memcpy(&challenge_1, shared_mem1, CHALLENGE_SIZE);
        mbedtls_mpi_init(&response_0);
        mbedtls_mpi_init(&response_1);
        ret = get_response_to_challenge(&challenge_0, &response_0);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = get_response_to_challenge(&challenge_1, &response_1);
        if (ret != 0) return TEE_ERROR_GENERIC;
        /* ZK generation logic here */
        mbedtls_mpi_free(&response_0);
        mbedtls_mpi_free(&response_1);
    }
}
