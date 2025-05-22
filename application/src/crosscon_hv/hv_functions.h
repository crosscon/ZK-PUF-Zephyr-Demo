#ifndef HV_FUNCTIONS_H
#define HV_FUNCTIONS_H

#include "tee_internal_api.h"

typedef struct {
    uint8_t      uuid[TEE_UUID_LEN];
    TEE_Result (*handler)(void* arg0,
                          void* arg1,
                          void* arg2,
                          void* arg3);
    void*      arg0;
    void*      arg1;
    void*      arg2;
    void*      arg3;
} uuid_func_map_t;

#define FUNCTION_TABLE_SIZE 3
extern const uuid_func_map_t function_table[FUNCTION_TABLE_SIZE];

TEE_Result PUF_TA_init(void* shared_mem0, void* shared_mem1, void* shared_mem2, void* shared_mem3);
TEE_Result PUF_TA_get_commitment(void* shared_mem0, void* shared_mem1, void* shared_mem2, void* shared_mem3);
TEE_Result dummy_function_3(void* shared_mem0, void* shared_mem1, void* shared_mem2, void* shared_mem3);

#endif // HV_FUNCTIONS_H
