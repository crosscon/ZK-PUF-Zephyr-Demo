#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(PUF_VM);

#include "crosscon_hv_config.h"
#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>

static uint64_t call_timestamps[MAX_CALLS_PER_WINDOW] = {0};
static int ts_index = 0;

void (*crosscon_hv_hypercall)(unsigned int, unsigned int, unsigned int) =
    (void (*)(unsigned int, unsigned int, unsigned int))CROSSCON_HV_HC_ADDR;

void ipc_notify(int ipc_id, int event_id)
{
    crosscon_hv_hypercall(CROSSCON_HV_HC_IPC_ID, ipc_id, event_id);
}

void ipc_irq_handler(void)
{
    uint8_t    received_uuid[TEE_UUID_LEN];
    TEE_Result result = TEE_ERROR_GENERIC;

    uint64_t now = k_uptime_get();

    // Count calls in the last minute
    int calls_in_window = 0;
    for (int i = 0; i < MAX_CALLS_PER_WINDOW; i++) {
        if (call_timestamps[i] != 0 && (now - call_timestamps[i]) < TIME_WINDOW_MS) {
            calls_in_window++;
        }
    }

    if (calls_in_window >= MAX_CALLS_PER_WINDOW) {
        LOG_WRN("Rate limit exceeded. Access denied.");
        result = TEE_ERROR_ACCESS_DENIED;
        memcpy(message[1], &result, sizeof(result));
        ipc_notify(0, 0);
        return;
    }

    // Store current timestamp
    call_timestamps[ts_index] = now;
    ts_index = (ts_index + 1) % MAX_CALLS_PER_WINDOW;

    memcpy(received_uuid, message[0], sizeof(received_uuid));
    LOG_HEXDUMP_INF(received_uuid, sizeof(received_uuid), "Received UUID");

    for (int i = 0; i < FUNCTION_TABLE_SIZE; i++) {
        if (memcmp(received_uuid,
                   function_table[i].uuid,
                   sizeof(received_uuid)) == 0) {
            LOG_INF("UUID matched entry %d; calling handler…", i);
            result = function_table[i].handler(
                         function_table[i].arg0,
                         function_table[i].arg1,
                         function_table[i].arg2,
                         function_table[i].arg3,
                         function_table[i].arg4,
                         function_table[i].arg5,
                         function_table[i].arg6,
                         function_table[i].arg7,
                         function_table[i].arg8,
                         function_table[i].arg9,
                         function_table[i].arg10,
                         function_table[i].arg11
                     );

            if (result != TEE_SUCCESS)
            {
                LOG_WRN("Non-success Error Code Returned");
            }
            else{
                LOG_INF("Interrupt Handled");
            }
            memcpy(message[1], &result, sizeof(result));
            ipc_notify(0, 0);
            return;  /* once handled, bail out */
        }
    }
    LOG_WRN("No matching UUID in table.");
}
