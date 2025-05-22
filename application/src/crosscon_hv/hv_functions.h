#ifndef HV_FUNCTIONS_H
#define HV_FUNCTIONS_H

#include "tee_internal_api.h"

typedef struct {
    uint8_t      uuid[TEE_UUID_LEN];
    TEE_Result (*handler)(void* arg0,
                          void* arg1,
                          void* arg2,
                          void* arg3,
                          void* arg4,
                          void* arg5,
                          void* arg6,
                          void* arg7);
    void*      arg0;
    void*      arg1;
    void*      arg2;
    void*      arg3;
    void*      arg4;
    void*      arg5;
    void*      arg6;
    void*      arg7;
} uuid_func_map_t;

#define FUNCTION_TABLE_SIZE 3
extern const uuid_func_map_t function_table[FUNCTION_TABLE_SIZE];

TEE_Result PUF_TA_init(void* shared_mem0,
                       void* shared_mem1,
                       void* shared_mem2,
                       void* shared_mem3,
                       void* shared_mem4,
                       void* shared_mem5,
                       void* shared_mem6,
                       void* shared_mem7
                       );
TEE_Result PUF_TA_get_commitment(void* shared_mem0,
                                 void* shared_mem1,
                                 void* shared_mem2,
                                 void* shared_mem3,
                                 void* shared_mem4,
                                 void* shared_mem5,
                                 void* shared_mem6,
                                 void* shared_mem7
                                 );
TEE_Result PUF_TA_get_ZK_proofs(void* shared_mem0,
                                void* shared_mem1,
                                void* shared_mem2,
                                void* shared_mem3,
                                void* shared_mem4,
                                void* shared_mem5,
                                void* shared_mem6,
                                void* shared_mem7
                                );

#endif // HV_FUNCTIONS_H
