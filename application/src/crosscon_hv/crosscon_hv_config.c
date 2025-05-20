#include "crosscon_hv_config.h"
#include <stdio.h>
#include <string.h>
#include "tee_internal_api.h"

void (*crosscon_hv_hypercall)(unsigned int, unsigned int, unsigned int) =
    (void (*)(unsigned int, unsigned int, unsigned int))CROSSCON_HV_HC_ADDR;

void ipc_notify(int ipc_id, int event_id)
{
    crosscon_hv_hypercall(CROSSCON_HV_HC_IPC_ID, ipc_id, event_id);
}

typedef struct {
    uint8_t      uuid[TEE_UUID_LEN];
    TEE_Result (*handler)(void);
} uuid_func_map_t;


TEE_Result dummy_function_1(void){
    return TEE_SUCCESS;
}

TEE_Result dummy_function_2(void){
    return TEE_ERROR_GENERIC;
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
        .handler = dummy_function_1,
    },
    {
        .uuid = {
            0x11, 0x22, 0x33, 0x44,   /* timeLow    */
            0x55, 0x66,               /* timeMid    */
            0x77, 0x88,               /* timeHi+ver */
            0x99, 0xAA, 0xBB, 0xCC,   /* clockSeq   */
            0xDD, 0xEE, 0xFF, 0x00    /* node       */
        },
        .handler = dummy_function_2,
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
