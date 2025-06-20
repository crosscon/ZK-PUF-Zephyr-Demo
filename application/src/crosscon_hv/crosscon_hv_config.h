#ifndef CROSSCON_HV_CONFIG_H
#define CROSSCON_HV_CONFIG_H

#include <string.h>
#include <stdint.h>
#include <zephyr/irq.h>
#include <cmsis_core.h>
#include <zephyr/drivers/tee.h>
#include "tee_internal_api.h"

// ----------------------------------------
// Base Config
// ----------------------------------------

#define IPC_IRQ_ID                      63     //79 on Bao config
#define CROSSCON_HV_IMAGE_START         0x10000000UL
#define CROSSCON_HV_HC_OFF              0x41UL
#define CROSSCON_HV_HC_ADDR             ((uintptr_t)CROSSCON_HV_IMAGE_START + CROSSCON_HV_HC_OFF)
#define CROSSCON_HV_HC_IPC_ID           0x1

#define VMS_IPC_BASE                    0x20017000UL
#define VMS_MAX_PARAMS                  4
#define VMS_IPC_FULL_SIZE               0x1000
#define VMS_USABLE_PAYLOAD_SIZE         ((VMS_IPC_FULL_SIZE - VMS_HEADER_SIZE) & ~0x3UL)
#define VMS_MEMREF_SLOT_SIZE            (VMS_USABLE_PAYLOAD_SIZE / VMS_MAX_PARAMS)

// ----------------------------------------
// Struct sizes
// ----------------------------------------

#define VMS_CALL_TYPE_SIZE              sizeof(tee_call_type_t)
#define VMS_SESSION_ARGS_SIZE           sizeof(GP_OpenSessionArgs)
#define VMS_INVOKE_FUNC_ARGS_SIZE       sizeof(GP_InvokeArgs)
#define VMS_PARAM_SIZE                  (VMS_MAX_PARAMS * sizeof(GP_Param))
#define VMS_HEADER_SIZE                 (VMS_CALL_TYPE_SIZE + VMS_SESSION_ARGS_SIZE + VMS_INVOKE_FUNC_ARGS_SIZE + VMS_PARAM_SIZE)

// ----------------------------------------
// Offsets into Shared Memory
// ----------------------------------------

#define VMS_OFFSET_CALL_TYPE            0x0000
#define VMS_OFFSET_SESSION_ARGS         (VMS_OFFSET_CALL_TYPE + VMS_CALL_TYPE_SIZE)
#define VMS_OFFSET_INVOKE_FUNC_ARGS     (VMS_OFFSET_SESSION_ARGS + VMS_SESSION_ARGS_SIZE)
#define VMS_OFFSET_PARAMS               (VMS_OFFSET_INVOKE_FUNC_ARGS + VMS_INVOKE_FUNC_ARGS_SIZE)
#define VMS_OFFSET_PAYLOAD              (VMS_OFFSET_PARAMS + VMS_PARAM_SIZE)

#define VMS_MEMREF0_OFFSET              0
#define VMS_MEMREF1_OFFSET              (1 * VMS_MEMREF_SLOT_SIZE)
#define VMS_MEMREF2_OFFSET              (2 * VMS_MEMREF_SLOT_SIZE)
#define VMS_MEMREF3_OFFSET              (3 * VMS_MEMREF_SLOT_SIZE)

// ----------------------------------------
// Packed Structs
// ----------------------------------------

typedef enum {
    TEE_CALL_TYPE_INVOKE_FUNC,
    TEE_CALL_TYPE_OPEN_SESSION,
    TEE_CALL_TYPE_CLOSE_SESSION,
} tee_call_type_t;

typedef struct __packed {
    uint32_t func;
    uint32_t session;
    uint32_t cancel_id;
    uint32_t ret;
    uint32_t ret_origin;
    uint32_t paramTypes;
} GP_InvokeArgs;

typedef struct __packed {
    uint64_t attr;
    uint64_t a;
    uint64_t b;
    uint64_t c;
} GP_Param;

typedef struct __packed {
    uint8_t  uuid[TEE_UUID_LEN];
    uint8_t  clnt_uuid[TEE_UUID_LEN];
    uint32_t clnt_login;
    uint32_t cancel_id;
    uint32_t session;
    uint32_t ret;
    uint32_t ret_origin;
    uint32_t paramTypes;
} GP_OpenSessionArgs;

typedef struct __packed {
    tee_call_type_t    call_type;
    GP_OpenSessionArgs session_args;
    GP_InvokeArgs      invoke_args;
    GP_Param           params[VMS_MAX_PARAMS];
    uint8_t            payload[VMS_USABLE_PAYLOAD_SIZE];
} GP_SharedMessage;

/* Macro to encode paramTypes field */
#define CROSSCON_PARAM_TYPES(t0, t1, t2, t3) \
    (((uint32_t)(t0) & 0xF)       | \
    (((uint32_t)(t1) & 0xF) << 4) | \
    (((uint32_t)(t2) & 0xF) << 8) | \
    (((uint32_t)(t3) & 0xF) << 12))

// ----------------------------------------
// Direct Access Pointers
// ----------------------------------------

#define VMS_HEADER_PTR                  ((volatile uint8_t *)(VMS_IPC_BASE + VMS_OFFSET_SESSION_ARGS))
#define VMS_PAYLOAD_PTR                 ((volatile uint8_t *)(VMS_IPC_BASE + VMS_OFFSET_PAYLOAD))

#define GP_SHARED_MSG_PTR               ((volatile GP_SharedMessage *)(VMS_IPC_BASE))
#define GP_CALL_TYPE_PTR                ((volatile tee_call_type_t *)(VMS_IPC_BASE + VMS_OFFSET_CALL_TYPE))
#define GP_SESSION_ARGS_PTR             ((volatile GP_OpenSessionArgs *)(VMS_IPC_BASE + VMS_OFFSET_SESSION_ARGS))
#define GP_INVOKE_FUNC_ARGS_PTR         ((volatile GP_InvokeArgs *)(VMS_IPC_BASE + VMS_OFFSET_INVOKE_FUNC_ARGS))
#define GP_PARAMS_PTR                   ((volatile GP_Param *)(VMS_IPC_BASE + VMS_OFFSET_PARAMS))

// ----------------------------------------
// Global Declarations
// ----------------------------------------

extern volatile struct tee_shm ipc_shm;
extern volatile struct tee_param param[4];
extern volatile struct tee_invoke_func_arg arg;
extern volatile GP_SharedMessage *msg;

// ----------------------------------------
// Hypervisor Specific Functions
// ----------------------------------------

extern void (*crosscon_hv_hypercall)(unsigned int, unsigned int, unsigned int);
void ipc_notify(int ipc_id, int event_id);
void ipc_irq_handler(void);

// ----------------------------------------
// Checks
// ----------------------------------------

_Static_assert(VMS_HEADER_SIZE < VMS_IPC_FULL_SIZE, "Shared memory header exceeds total size");
_Static_assert((VMS_USABLE_PAYLOAD_SIZE % 4) == 0, "Payload size must be 4-byte aligned");
_Static_assert(VMS_USABLE_PAYLOAD_SIZE >= 4 * 256, "VMS_USABLE_PAYLOAD_SIZE must be at least 1024 bytes");

#endif // CROSSCON_HV_CONFIG_H
