#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(GUEST_VM);

#include "crosscon_hv_config.h"
#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>

#define PUF_TA_UUID_BYTES { \
    0x00, 0x11, 0x22, 0x33, \
    0x44, 0x55, \
    0x66, 0x77, \
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF \
}

static const uint8_t PUF_TA_UUID[TEE_UUID_LEN] = PUF_TA_UUID_BYTES;

volatile struct tee_shm ipc_shm;
volatile struct tee_param param[4] = {0};
volatile struct tee_invoke_func_arg arg = {0};
volatile struct tee_open_session_arg session_arg = {0};

// Init as NULL and when crosscon_hv_tee gets initialized assign value
volatile GP_SharedMessage *msg = NULL;

void (*crosscon_hv_hypercall)(unsigned int, unsigned int, unsigned int) =
    (void (*)(unsigned int, unsigned int, unsigned int))CROSSCON_HV_HC_ADDR;

void ipc_notify(int ipc_id, int event_id)
{
    crosscon_hv_hypercall(CROSSCON_HV_HC_IPC_ID, ipc_id, event_id);
}

void ipc_irq_client_handler(void)
{
    irq_disable(IPC_IRQ_ID);  // Prevent nested handling
    __DMB(); // Ensure memory read ordering before touching shared memory


    __DMB(); // Ensure all writes complete before notifying
    LOG_INF("IRQ Handled.");
    irq_enable(IPC_IRQ_ID);  // Re-enable interrupts
    ipc_notify(0, 0);
}
