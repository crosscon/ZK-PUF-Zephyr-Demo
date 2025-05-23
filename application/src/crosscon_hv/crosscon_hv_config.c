#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(GUEST_VM);

#include "crosscon_hv_config.h"
#include <stdio.h>
#include <string.h>

void (*crosscon_hv_hypercall)(unsigned int, unsigned int, unsigned int) =
    (void (*)(unsigned int, unsigned int, unsigned int))CROSSCON_HV_HC_ADDR;

void ipc_notify(int ipc_id, int event_id)
{
    crosscon_hv_hypercall(CROSSCON_HV_HC_IPC_ID, ipc_id, event_id);
}

void ipc_irq_handler(void)
{
}
