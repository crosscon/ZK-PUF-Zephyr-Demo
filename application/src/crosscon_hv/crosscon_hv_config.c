#include "crosscon_hv_config.h"
#include <stdio.h>
#include <string.h>

void (*crosscon_hv_hypercall)(unsigned int, unsigned int, unsigned int) =
    (void (*)(unsigned int, unsigned int, unsigned int))CROSSCON_HV_HC_ADDR;

void ipc_notify(int ipc_id, int event_id)
{
    crosscon_hv_hypercall(CROSSCON_HV_HC_IPC_ID, ipc_id, event_id);
}

void print_hex(const char* label, const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", bytes[i]);
        if (i < len - 1) printf(":");
    }
    printf("\r\n");
}

void ipc_irq_handler(void)
{
    uint8_t    received_uuid[TEE_UUID_LEN];
    TEE_Result result = TEE_ERROR_GENERIC;

    memcpy(received_uuid, message[0], sizeof(received_uuid));
    print_hex("Received UUID", received_uuid, sizeof(received_uuid));

    for (int i = 0; i < FUNCTION_TABLE_SIZE; i++) {
        if (memcmp(received_uuid,
                   function_table[i].uuid,
                   sizeof(received_uuid)) == 0) {
            printf("UUID matched entry %d; calling handler…\n", i);
            result = function_table[i].handler(
                         function_table[i].arg0,
                         function_table[i].arg1,
                         function_table[i].arg2,
                         function_table[i].arg3
                     );
            memcpy(message[1], &result, sizeof(result));
            ipc_notify(0, 0);
            return;  /* once handled, bail out */
        }
    }
    printf("No matching UUID in table.\n");
}
