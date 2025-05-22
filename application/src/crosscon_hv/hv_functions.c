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
        .handler = PUF_TA_Init,
    },
    {
        .uuid = {
            0x11, 0x22, 0x33, 0x44,   /* timeLow    */
            0x55, 0x66,               /* timeMid    */
            0x77, 0x88,               /* timeHi+ver */
            0x99, 0xAA, 0xBB, 0xCC,   /* clockSeq   */
            0xDD, 0xEE, 0xFF, 0x00    /* node       */
        },
        .handler = PUF_TA_GetCRP,
    },
    {
        .uuid = {
            0x22, 0x33, 0x44, 0x55,   /* timeLow    */
            0x66, 0x77,               /* timeMid    */
            0x88, 0x99,               /* timeHi+ver */
            0xAA, 0xBB, 0xCC, 0xDD,   /* clockSeq   */
            0xEE, 0xFF, 0x00, 0x11    /* node       */
        },
        .handler = dummy_function_3,
    }
};

TEE_Result PUF_TA_Init(void){
    int ret;
    ret = init_puf();
    if (ret != 0) return TEE_ERROR_GENERIC;
    ret = init_crypto();
    if (ret != 0) return TEE_ERROR_GENERIC;
    /* For now hardcoding/testing shmem reading */
    memcpy(message[2], &hardcoded_challenge_1, CHALLENGE_SIZE);
    memcpy(message[3], &hardcoded_challenge_2, CHALLENGE_SIZE);
    has_been_initialized = true;
    return TEE_SUCCESS;
}

TEE_Result PUF_TA_GetCRP(void){
    if(!has_been_initialized){
        return TEE_ERROR_GENERIC;
    } else {
        int ret;
        mbedtls_mpi response_1;
        mbedtls_mpi response_2;
        mbedtls_ecp_point commitment;
        uint8_t challenge_1[CHALLENGE_SIZE];
        uint8_t challenge_2[CHALLENGE_SIZE];
        memcpy(&challenge_1, message[2], CHALLENGE_SIZE);
        memcpy(&challenge_2, message[3], CHALLENGE_SIZE);
        mbedtls_mpi_init(&response_1);
        mbedtls_mpi_init(&response_2);
	mbedtls_ecp_point_init(&commitment);
        ret = get_response_to_challenge(&challenge_1, &response_1);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = get_response_to_challenge(&challenge_2, &response_2);
        if (ret != 0) return TEE_ERROR_GENERIC;
        ret = get_commited_value(&response_1, &response_2, &commitment);
        mbedtls_mpi_free(&response_1);
        mbedtls_mpi_free(&response_2);
        if (ret != 0) return TEE_ERROR_GENERIC;
        return TEE_SUCCESS;
    }
}

TEE_Result dummy_function_3(void){
    if(!has_been_initialized){
        return TEE_ERROR_GENERIC;
    } else {
        return TEE_SUCCESS;
    }
}
