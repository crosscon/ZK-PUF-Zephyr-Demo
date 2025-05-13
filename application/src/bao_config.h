#include <string.h>
#include <stdint.h>
#include <zephyr/irq.h>
#include <cmsis_core.h>
#include "tee_internal_api.h"


#define VM                  "VM1"
#define IPC_IRQ_ID          63      //79 on Bao config
#define BAO_IMAGE_START     0x10000000UL
#define BAO_HC_OFF          0x41UL
#define BAO_HC_ADDR         ((uintptr_t)BAO_IMAGE_START + BAO_HC_OFF)
#define BAO_HC_IPC_ID       0x1
#define VMS_IPC_BASE        0x20017000UL
#define VMS_IPC_SIZE        0x1000

/* Define shared memory layout */
#define MESSAGE0_SIZE       ((const size_t)(0x10)) //128-bit/16-byte - place for TEE Calls UUID
#define MESSAGE0_OFFSET     VMS_IPC_BASE

#define MESSAGE1_SIZE       ((const size_t)(0x4))  //32-bit/4-byte - place for TEEC_Result
#define MESSAGE1_OFFSET     MESSAGE0_OFFSET + MESSAGE0_SIZE

#define MESSAGE2_SIZE       ((const size_t)(VMS_IPC_SIZE - MESSAGE0_SIZE - MESSAGE1_SIZE)) //Ugly, WIP
#define MESSAGE2_OFFSET     MESSAGE1_OFFSET + MESSAGE1_SIZE

static char* const message[3] = {
    (const char*)(MESSAGE0_OFFSET),
    (const char*)(MESSAGE1_OFFSET),
    (const char*)(MESSAGE2_OFFSET),
};

extern void (*bao_hypercall)(unsigned int, unsigned int, unsigned int);

void ipc_notify(int ipc_id, int event_id);
void ipc_irq_handler(void);

