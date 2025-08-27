#ifndef HV_FUNCTIONS_H
#define HV_FUNCTIONS_H

#define PUF_TA_INIT_FUNC_ID                 0x00112233
#define PUF_TA_GET_COMMITMENT_FUNC_ID       0x11223344
#define PUF_TA_GET_ZK_PROOFS_FUNC_ID        0x22334455
#define PUF_TA_VERIFY_ZK_PROOFS_FUNC_ID     0x33445566

#include "tee_internal_api.h"
#include "crosscon_hv_config.h"

typedef struct {
    uint32_t func_id;
    uint32_t expected_param_types;
    uint64_t expected_param_lengths[VMS_MAX_PARAMS];
    TEE_Result (*handler)(void);
} func_id_map_t;

typedef struct {
    uint8_t g_x[32];
    uint8_t g_y[32];
    uint8_t h_x[32];
    uint8_t h_y[32];
    uint8_t COM_x[32];
    uint8_t COM_y[32];
    uint8_t P_x[32];
    uint8_t P_y[32];
    uint8_t v[64];
    uint8_t w[64];
    uint8_t n[64];
} verify_zk_proofs;

#define FUNCTION_TABLE_SIZE 4
extern const func_id_map_t function_table[FUNCTION_TABLE_SIZE];

TEE_Result PUF_TA_init(void);
TEE_Result PUF_TA_get_commitment(void);
TEE_Result PUF_TA_get_ZK_proofs(void);
TEE_Result PUF_TA_verify_ZK_proofs(void);

#endif // HV_FUNCTIONS_H
