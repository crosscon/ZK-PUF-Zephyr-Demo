#include "hv_functions.h"
#include "puf_handler.h"

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

TEE_Result PUF_TA_Init(void){
    uint8_t puf_key[PUF_KEY_SIZE];
    init_puf();
    has_been_initialized = true;
    return TEE_SUCCESS;
}

TEE_Result dummy_function_2(void){
    if(!has_been_initialized){
        return TEE_ERROR_GENERIC;
    } else {
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
