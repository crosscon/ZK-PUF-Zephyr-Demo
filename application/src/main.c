#include <stdio.h>
#include "flash_handler.h"
#include "crosscon_hv_config.h"

#define IS_WRITE_TO_FLASH_ENABLED 1

void vm_init() {
    IRQ_CONNECT(IPC_IRQ_ID, 0, ipc_irq_handler, NULL, 0);
    irq_enable(IPC_IRQ_ID);
    printf(VM": PUF TA Initialized\r\n");
}

int main(void)
{
    vm_init();

    // Wait for interrupts and handle them according to function_table
    while(1);
}
