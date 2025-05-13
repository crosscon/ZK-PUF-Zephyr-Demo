#include "bao_config.h"
#include <stdio.h>
#include <string.h>
#include "tee_internal_api.h"
#include "flash_handler.h"
#include "puf_prover.h"
#include "mbedtls/ecp.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "utils.h"
#include "config_data.h"

void (*bao_hypercall)(unsigned int, unsigned int, unsigned int) =
    (void (*)(unsigned int, unsigned int, unsigned int))BAO_HC_ADDR;

void ipc_notify(int ipc_id, int event_id)
{
    bao_hypercall(BAO_HC_IPC_ID, ipc_id, event_id);
}

typedef struct {
    uint8_t      uuid[TEE_UUID_LEN];
    TEE_Result (*handler)(void);
} uuid_func_map_t;



TEE_Result puf_enrollment_handler(void){
    __attribute__((aligned(16))) uint8_t activation_code[PUF_ACTIVATION_CODE_SIZE];
    const struct flash_area *flash_area;
    const struct device *flash_dev;
    int ret;
    puf_config_t pufConfig;

    mbedtls_ecp_group grp;
	mbedtls_ecp_point h, C;

    // Initialize flash area and device 
    ret = flash_initialize(FIXED_PARTITION_ID(STORAGE_PARTITION), &flash_area, &flash_dev);
    if (ret != 0) {
        printf("Flash Initialization failed!\r\n");
        return ret;
    }
    

    ret = perform_enrollment(&grp,&h,&C,c1,CHALLENGE_SIZE, c2, CHALLENGE_SIZE, 
        PUF,pufConfig,
        activation_code,
        PUF_ACTIVATION_CODE_SIZE,
        flash_area,
        flash_dev,
        ENROLLMENT_IS_UP);

    if(ret!=0){
        printf("Couldn't finish the enrollment\r\n");
        return TEE_ERROR_GENERIC;
    }
    else
    {
        printf("Enrollment was a success. Below you can find the commitment\r\n");

        uint8_t commitment_buffer[COMMITMENT_BUFFER_SIZE];

        size_t olen;
        olen = export_commitment(&grp,&C, commitment_buffer, sizeof(commitment_buffer));
        if (olen < 0) {
        printf("Error exporting commitment, error code: %d\n", olen);
        return 1;
        }


        printf("Commitment: ");
        for (size_t i = 0; i < COMMITMENT_BUFFER_SIZE; i++) {
        printf("%02X", commitment_buffer[i]);
        }
        printf("\n");
    }

    return TEE_SUCCESS;
}

TEE_Result puf_authentication_handler(void){
    __attribute__((aligned(16))) uint8_t activation_code[PUF_ACTIVATION_CODE_SIZE];

    const struct flash_area *flash_area;
    const struct device *flash_dev;
    int ret;
    puf_config_t pufConfig;

    mbedtls_ecp_group grp;
	mbedtls_ecp_point h, C;

    // Initialize flash area and device 
    ret = flash_initialize(FIXED_PARTITION_ID(STORAGE_PARTITION), &flash_area, &flash_dev);
    if (ret != 0) {
        printf("Flash Initialization failed!\r\n");
        return ret;
    }

    mbedtls_ecp_point proof;
    mbedtls_ecp_point_init(&proof);
    mbedtls_mpi result_v, result_w, nonce;
    mbedtls_mpi_init(&result_v);
    mbedtls_mpi_init(&result_w);
    mbedtls_mpi_init(&nonce);

    ret = perform_authentication(&grp, &grp.G, &h, &proof, &C, &result_v, &result_w, &nonce , c1, CHALLENGE_SIZE, c2, CHALLENGE_SIZE, 
                        PUF,pufConfig,
                        activation_code,
                        PUF_ACTIVATION_CODE_SIZE,
                        flash_area,
                        flash_dev,commitment_hex, COMMITMENT_BUFFER_SIZE);

    if(ret!=0){
        printf("Couldn't Authenticate the device\r\n");
        return TEE_ERROR_GENERIC;
    }
    else
    {
        printf("Authentication was a success. Below you can find the variables to return\r\n");
        print_mpi("v", &result_v);
        print_mpi("w", &result_w);
        print_mpi("nonce", &nonce);
        print_ecp_point("proof", &grp, &proof);
    }

    return TEE_SUCCESS;
}

TEE_Result dummy_function_3(void){
    return TEE_ERROR_CANCEL;
}


static const uuid_func_map_t function_table[] = {
    {
        .uuid = {
            0x00, 0x11, 0x22, 0x33,   /* timeLow    */
            0x44, 0x55,               /* timeMid    */
            0x66, 0x77,               /* timeHi+ver */
            0x88, 0x99, 0xAA, 0xBB,   /* clockSeq   */
            0xCC, 0xDD, 0xEE, 0xFF    /* node       */
        },
        .handler = puf_enrollment_handler,
    },
    {
        .uuid = {
            0x11, 0x22, 0x33, 0x44,   /* timeLow    */
            0x55, 0x66,               /* timeMid    */
            0x77, 0x88,               /* timeHi+ver */
            0x99, 0xAA, 0xBB, 0xCC,   /* clockSeq   */
            0xDD, 0xEE, 0xFF, 0x00    /* node       */
        },
        .handler = puf_authentication_handler,
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

void print_hex(const char* label, const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", bytes[i]);
        if (i < len - 1) printf(":");
    }
    printf("\r\n");
}

void ipc_irq_handler(void)
{
    uint8_t   received_uuid[TEE_UUID_LEN];
    TEE_Result result = TEE_ERROR_GENERIC;

    /* Copy the UUID from shared memory */
    memcpy(&received_uuid, message[0], sizeof(received_uuid));
    print_hex("Received UUID", &received_uuid, sizeof(received_uuid));

    /* Iterate and compare contents of each entry */
    for (int i = 0; i < ARRAY_SIZE(function_table); i++) {
        if (memcmp(&received_uuid,
                   function_table[i].uuid,
                   sizeof(received_uuid)) == 0) {
            /* Call handler and capture the result */
            printf("UUID matched entry %d; calling handler…\n", i);
            result = function_table[i].handler();
            /* Write the return code and inform that interrupt got handled */
            memcpy(message[1], &result, sizeof(result));
            ipc_notify(0,0);
        } else {
            printf("No matching UUID in table.\n");
        }
    }
}

