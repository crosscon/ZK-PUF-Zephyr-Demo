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
    LOG_INF("IPC Handler");
    LOG_HEXDUMP_INF(message[1], 0x4, "Return code");
    LOG_HEXDUMP_DBG(message[2], 0x10, "Argument 1");
    LOG_HEXDUMP_DBG(message[3], 0x10, "Argument 2");
    LOG_HEXDUMP_DBG(message[4], 0x10, "Argument 3");
    LOG_HEXDUMP_DBG(message[5], 0x10, "Argument 4");
    LOG_HEXDUMP_DBG(message[6], 0x10, "Argument 5");
    LOG_HEXDUMP_DBG(message[7], 0x10, "Argument 6");
    LOG_HEXDUMP_DBG(message[8], 0x10, "Argument 7");
    LOG_HEXDUMP_DBG(message[9], 0x10, "Argument 8");
    LOG_HEXDUMP_DBG(message[10], 0x10, "Argument 9");
    LOG_HEXDUMP_DBG(message[11], 0x10, "Argument 10");
    LOG_HEXDUMP_DBG(message[12], 0x10, "Argument 11");
    LOG_HEXDUMP_DBG(message[13], 0x10, "Argument 12");
}
