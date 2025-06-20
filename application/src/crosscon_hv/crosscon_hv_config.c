#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(PUF_VM);

#include "crosscon_hv_config.h"
#include "hv_functions.h"
#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>

#define MAX_CALLS_PER_WINDOW 5
#define TIME_WINDOW_MS (30 * 1000)  // 30 seconds

static uint64_t call_timestamps[MAX_CALLS_PER_WINDOW] = {0};
static int ts_index = 0;

volatile struct tee_shm ipc_shm;
volatile struct tee_param param[4] = {0};
volatile struct tee_invoke_func_arg arg = {0};

volatile GP_SharedMessage *msg = (volatile GP_SharedMessage *)VMS_HEADER_PTR;

void (*crosscon_hv_hypercall)(unsigned int, unsigned int, unsigned int) =
    (void (*)(unsigned int, unsigned int, unsigned int))CROSSCON_HV_HC_ADDR;

void ipc_notify(int ipc_id, int event_id)
{
    crosscon_hv_hypercall(CROSSCON_HV_HC_IPC_ID, ipc_id, event_id);
}

TEE_Result handle_invoke_func(volatile GP_InvokeArgs *args,
                              volatile GP_Param *params)
{
    TEE_Result result = TEE_ERROR_ITEM_NOT_FOUND;

    LOG_INF("Received TEE function call: func_id=0x%08X", args->func);

    // Enforce rate limiting
    uint64_t now = k_uptime_get();
    int calls_in_window = 0;

    for (int i = 0; i < MAX_CALLS_PER_WINDOW; i++) {
        if (call_timestamps[i] != 0 && (now - call_timestamps[i]) < TIME_WINDOW_MS) {
            calls_in_window++;
        }
    }

    if (calls_in_window >= MAX_CALLS_PER_WINDOW) {
        LOG_WRN("Rate limit exceeded. Access denied.");
        return TEE_ERROR_ACCESS_DENIED;
    }

    // Store timestamp
    call_timestamps[ts_index] = now;
    ts_index = (ts_index + 1) % MAX_CALLS_PER_WINDOW;

    // Match and invoke
    for (int i = 0; i < FUNCTION_TABLE_SIZE; ++i) {
        const func_id_map_t *entry = &function_table[i];

        if (entry->func_id != args->func)
            continue;

        LOG_INF("Function ID matched entry %d", i);

        if (args->paramTypes != entry->expected_param_types) {
            LOG_WRN("Bad paramTypes: got 0x%08X, expected 0x%08X",
                    args->paramTypes, entry->expected_param_types);
            return TEE_ERROR_BAD_FORMAT;
        }

        for (int j = 0; j < VMS_MAX_PARAMS; ++j) {
            uint64_t expected_len = entry->expected_param_lengths[j];
            if (expected_len > 0 && params[j].b != expected_len) {
                LOG_WRN("Param[%d] length mismatch: got %llu, expected %llu",
                        j, params[j].b, expected_len);
                return TEE_ERROR_BAD_FORMAT;
            }
        }

        result = entry->handler();
        if (result == TEE_SUCCESS) {
            LOG_INF("Handler executed successfully.");
        } else {
            LOG_WRN("Handler returned error: 0x%08X", result);
        }

        return result;
    }

    LOG_WRN("No matching function ID in table: 0x%08X", args->func);
    return result;
}

void ipc_irq_handler(void)
{
    irq_disable(IPC_IRQ_ID);  // Prevent nested handling
    __DMB(); // Ensure memory read ordering before touching shared memory

    tee_call_type_t call_type = GP_SHARED_MSG_PTR->call_type;

    volatile GP_InvokeArgs *args   = GP_INVOKE_FUNC_ARGS_PTR;
    volatile GP_Param      *params = GP_PARAMS_PTR;

    TEE_Result result = TEE_ERROR_GENERIC;

    switch (call_type) {
    case TEE_CALL_TYPE_INVOKE_FUNC:
        result = handle_invoke_func(args, params);
        args->ret = result;
        args->ret_origin = TEE_ORIGIN_TRUSTED_APP;
        break;

    case TEE_CALL_TYPE_OPEN_SESSION:
        LOG_WRN("Session open not yet handled");
        break;

    case TEE_CALL_TYPE_CLOSE_SESSION:
        LOG_WRN("Session close not yet handled");
        break;

    default:
        LOG_WRN("Unknown call type: %d", call_type);
        break;
    }

    __DMB(); // Ensure all writes complete before notifying
    LOG_INF("IRQ Handled.");
    irq_enable(IPC_IRQ_ID);  // Re-enable interrupts
    ipc_notify(0, 0);
}
