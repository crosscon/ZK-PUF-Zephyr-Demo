#ifndef CROSSCON_HV_CONFIG_H
#define CROSSCON_HV_CONFIG_H

#include <string.h>
#include <stdint.h>
#include <zephyr/irq.h>
#include <cmsis_core.h>
#include <zephyr/drivers/tee.h>
#include "tee_internal_api.h"

#define IPC_IRQ_ID          62      //78 on Bao config
#define CROSSCON_HV_IMAGE_START     0x10000000UL
#define CROSSCON_HV_HC_OFF          0x41UL
#define CROSSCON_HV_HC_ADDR         ((uintptr_t)CROSSCON_HV_IMAGE_START + CROSSCON_HV_HC_OFF)
#define CROSSCON_HV_HC_IPC_ID       0x1
#define VMS_IPC_BASE        0x20017000UL
#define VMS_IPC_SIZE        0x1000

/* Offsets for each parameter's memref area within the shared buffer */
#define VMS_PARAM0_OFFSET   0U
#define VMS_PARAM1_OFFSET   256U
#define VMS_PARAM2_OFFSET   512U
#define VMS_PARAM3_OFFSET   768U

/* Macro to pack four 4-bit GP parameter type codes into a 32-bit word */
#define CROSSCON_PARAM_TYPES(t0, t1, t2, t3) \
    (((uint32_t)(t0) & 0xF)       | \
    (((uint32_t)(t1) & 0xF) << 4) | \
    (((uint32_t)(t2) & 0xF) << 8) | \
    (((uint32_t)(t3) & 0xF) << 12))

/* GlobalPlatform-style shared message structure */
typedef struct __aligned(4) {
    uint32_t paramTypes;  /* Encoded parameter types (see CROSSCON_PARAM_TYPES) */
    union {
        struct {
            uint32_t a;
            uint32_t b;
        } value[4];   /* For TEE_PARAM_ATTR_TYPE_VALUE_* */
        struct {
            uint32_t offset;
            uint32_t size;
        } memref[4];  /* For TEE_PARAM_ATTR_TYPE_MEMREF_* */
    } params;
    uint8_t payload[256]; /* 256-byte payload buffer */
} GP_SharedMessage;

extern void (*crosscon_hv_hypercall)(unsigned int, unsigned int, unsigned int);

void ipc_notify(int ipc_id, int event_id);
void ipc_irq_handler(void);

#endif // CROSSCON_HV_CONFIG_H
