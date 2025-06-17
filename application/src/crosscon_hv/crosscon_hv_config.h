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

#define IPC_IRQ_ID                 63     //79 on Bao config
#define CROSSCON_HV_IMAGE_START    0x10000000UL
#define CROSSCON_HV_HC_OFF         0x41UL
#define CROSSCON_HV_HC_ADDR        ((uintptr_t)CROSSCON_HV_IMAGE_START + CROSSCON_HV_HC_OFF)
#define CROSSCON_HV_HC_IPC_ID      0x1

#define VMS_IPC_BASE               0x20017000UL
#define VMS_MAX_PARAMS             4
#define VMS_IPC_PAYLOAD_SIZE       1024UL
#define VMS_MEMREF_SLOT_SIZE       (VMS_IPC_PAYLOAD_SIZE / VMS_MAX_PARAMS)
#define VMS_TOTAL_SIZE             (VMS_ARG_SIZE + VMS_PARAM_SIZE + VMS_IPC_PAYLOAD_SIZE)

// ----------------------------------------
// Struct sizes
// ----------------------------------------

#define VMS_PARAM_SIZE             (VMS_MAX_PARAMS * sizeof(GP_Param))
#define VMS_ARG_SIZE               sizeof(GP_InvokeArgs)

// ----------------------------------------
// Offsets into Shared Memory
// ----------------------------------------

#define VMS_OFFSET_INVOKE_ARGS     0x0000
#define VMS_OFFSET_PARAMS          (VMS_OFFSET_INVOKE_ARGS + VMS_ARG_SIZE)
#define VMS_OFFSET_PAYLOAD         (VMS_OFFSET_PARAMS + VMS_PARAM_SIZE)

#define VMS_MEMREF0_OFFSET         0
#define VMS_MEMREF1_OFFSET         (1 * VMS_MEMREF_SLOT_SIZE)
#define VMS_MEMREF2_OFFSET         (2 * VMS_MEMREF_SLOT_SIZE)
#define VMS_MEMREF3_OFFSET         (3 * VMS_MEMREF_SLOT_SIZE)

// ----------------------------------------
// Packed Structs
// ----------------------------------------

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
    GP_InvokeArgs invoke_args;
    GP_Param      params[VMS_MAX_PARAMS];
    uint8_t       payload[VMS_IPC_PAYLOAD_SIZE];
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

#define VMS_HEADER_PTR             ((volatile uint8_t *)VMS_IPC_BASE)
#define VMS_PAYLOAD_PTR            ((volatile uint8_t *)(VMS_IPC_BASE + VMS_OFFSET_PAYLOAD))
#define GP_SHARED_MSG_PTR          ((volatile GP_SharedMessage *)VMS_IPC_BASE)

#define GP_ARGS_PTR                ((volatile GP_InvokeArgs *)(VMS_IPC_BASE + VMS_OFFSET_INVOKE_ARGS))
#define GP_PARAMS_PTR              ((volatile GP_Param *)(VMS_IPC_BASE + VMS_OFFSET_PARAMS))

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

#endif // CROSSCON_HV_CONFIG_H
