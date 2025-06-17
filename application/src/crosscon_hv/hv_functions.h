#ifndef HV_FUNCTIONS_H
#define HV_FUNCTIONS_H

#define PUF_TA_INIT_FUNC_ID            0x00112233
#define PUF_TA_GET_COMMITMENT_FUNC_ID  0x11223344
#define PUF_TA_GET_ZK_PROOFS_FUNC_ID   0x22334455

#include "tee_internal_api.h"
#include "crosscon_hv_config.h"

typedef struct {
    uint32_t func_id;
    uint32_t expected_param_types;
    uint64_t expected_param_lengths[VMS_MAX_PARAMS];
    TEE_Result (*handler)(void);
} func_id_map_t;

#define FUNCTION_TABLE_SIZE 3
extern const func_id_map_t function_table[FUNCTION_TABLE_SIZE];

TEE_Result PUF_TA_init(void);
TEE_Result PUF_TA_get_commitment(void);
TEE_Result PUF_TA_get_ZK_proofs(void);

#endif // HV_FUNCTIONS_H
