#include <stdio.h>
#include "flash_handler.h"
#include "puf_prover.h"
#include "bao_config.h"
#include "mbedtls/ecp.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "utils.h"


#define MEMORY_BUF_SIZE 16384
static unsigned char memory_buf[MEMORY_BUF_SIZE];

void vm_init() {
    IRQ_CONNECT(IPC_IRQ_ID, 0, ipc_irq_handler, NULL, 0);
    irq_enable(IPC_IRQ_ID);
    printf(VM": PUF TA Initialized\r\n");
}

int main(void)
{
    mbedtls_memory_buffer_alloc_init(memory_buf, sizeof(memory_buf));    
    vm_init();

    // Wait for interrupts and handle them according to function_table
    while(1);
}
