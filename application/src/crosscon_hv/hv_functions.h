#include "tee_internal_api.h"

typedef struct {
    uint8_t      uuid[TEE_UUID_LEN];
    TEE_Result (*handler)(void);
} uuid_func_map_t;

#define FUNCTION_TABLE_SIZE 3
extern const uuid_func_map_t function_table[FUNCTION_TABLE_SIZE];

TEE_Result PUF_TA_Init(void);
TEE_Result PUF_TA_GetCRP(void);
TEE_Result dummy_function_3(void);
