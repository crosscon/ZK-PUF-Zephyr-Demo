#ifndef CROSSCON_HV_CONFIG_H
#define CROSSCON_HV_CONFIG_H

#include <string.h>
#include <stdint.h>
#include <zephyr/irq.h>
#include <cmsis_core.h>
#include "tee_internal_api.h"

#define IPC_IRQ_ID          62      //78 on Bao config
#define CROSSCON_HV_IMAGE_START     0x10000000UL
#define CROSSCON_HV_HC_OFF          0x41UL
#define CROSSCON_HV_HC_ADDR         ((uintptr_t)CROSSCON_HV_IMAGE_START + CROSSCON_HV_HC_OFF)
#define CROSSCON_HV_HC_IPC_ID       0x1
#define VMS_IPC_BASE        0x20017000UL
#define VMS_IPC_SIZE        0x1000

/* Define shared memory layout */
#define MESSAGE0_SIZE       ((const size_t)(0x10)) //128-bit/16-byte - place for TEE Calls UUID
#define MESSAGE0_OFFSET     VMS_IPC_BASE

#define MESSAGE1_SIZE       ((const size_t)(0x4))  //32-bit/4-byte - place for TEEC_Result
#define MESSAGE1_OFFSET     MESSAGE0_OFFSET + MESSAGE0_SIZE

#define MESSAGE2_SIZE       ((const size_t)(0x10))  //128-bit/16-byte - place for Argument 1
#define MESSAGE2_OFFSET     MESSAGE1_OFFSET + MESSAGE1_SIZE

#define MESSAGE3_SIZE       ((const size_t)(0x10))  //128-bit/16-byte - place for Argument 2
#define MESSAGE3_OFFSET     MESSAGE2_OFFSET + MESSAGE2_SIZE

#define MESSAGE4_SIZE       ((const size_t)(0x10))  //128-bit/16-byte - place for Argument 3
#define MESSAGE4_OFFSET     MESSAGE3_OFFSET + MESSAGE3_SIZE

#define MESSAGE5_SIZE       ((const size_t)(0x10))  //128-bit/16-byte - place for Argument 4
#define MESSAGE5_OFFSET     MESSAGE4_OFFSET + MESSAGE4_SIZE

#define MESSAGE6_SIZE       ((const size_t)(0x10))  //128-bit/16-byte - place for Argument 5
#define MESSAGE6_OFFSET     MESSAGE5_OFFSET + MESSAGE5_SIZE

#define MESSAGE7_SIZE       ((const size_t)(0x10))  //128-bit/16-byte - place for Argument 6
#define MESSAGE7_OFFSET     MESSAGE6_OFFSET + MESSAGE6_SIZE

#define MESSAGE8_SIZE       ((const size_t)(0x10))  //128-bit/16-byte - place for Argument 7
#define MESSAGE8_OFFSET     MESSAGE7_OFFSET + MESSAGE7_SIZE

#define MESSAGE9_SIZE       ((const size_t)(0x10))  //128-bit/16-byte - place for Argument 8
#define MESSAGE9_OFFSET     MESSAGE8_OFFSET + MESSAGE8_SIZE

#define MESSAGE10_SIZE       ((const size_t)(0x10))  //128-bit/16-byte - place for Argument 9
#define MESSAGE10_OFFSET     MESSAGE9_OFFSET + MESSAGE9_SIZE

#define MESSAGE11_SIZE       ((const size_t)(0x10))  //128-bit/16-byte - place for Argument 10
#define MESSAGE11_OFFSET     MESSAGE10_OFFSET + MESSAGE10_SIZE

#define MESSAGE12_SIZE       ((const size_t)(0x10))  //128-bit/16-byte - place for Argument 11
#define MESSAGE12_OFFSET     MESSAGE11_OFFSET + MESSAGE11_SIZE

#define MESSAGE13_SIZE       ((const size_t)(0x10))  //128-bit/16-byte - place for Argument 12
#define MESSAGE13_OFFSET     MESSAGE12_OFFSET + MESSAGE12_SIZE

static char* const message[14] = {
    (const char*)(MESSAGE0_OFFSET),
    (const char*)(MESSAGE1_OFFSET),
    (const char*)(MESSAGE2_OFFSET),
    (const char*)(MESSAGE3_OFFSET),
    (const char*)(MESSAGE4_OFFSET),
    (const char*)(MESSAGE5_OFFSET),
    (const char*)(MESSAGE6_OFFSET),
    (const char*)(MESSAGE7_OFFSET),
    (const char*)(MESSAGE8_OFFSET),
    (const char*)(MESSAGE9_OFFSET),
    (const char*)(MESSAGE10_OFFSET),
    (const char*)(MESSAGE11_OFFSET),
    (const char*)(MESSAGE12_OFFSET),
    (const char*)(MESSAGE13_OFFSET),
};

extern void (*crosscon_hv_hypercall)(unsigned int, unsigned int, unsigned int);

void ipc_notify(int ipc_id, int event_id);
void ipc_irq_handler(void);

#endif // CROSSCON_HV_CONFIG_H
