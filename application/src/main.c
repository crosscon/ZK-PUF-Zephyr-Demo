#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(PUF_VM);

#include <stdio.h>
#include "crosscon_hv_config.h"

void vm_init() {
    IRQ_CONNECT(IPC_IRQ_ID, 0, ipc_irq_ta_handler, NULL, 0);
    irq_enable(IPC_IRQ_ID);
    LOG_INF("VM Initialized");
}

int main(void)
{
    vm_init();

    // Wait for interrupts and handle them according to function_table
    while(1);
}
