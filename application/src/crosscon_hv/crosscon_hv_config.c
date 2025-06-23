#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(GUEST_VM);

#include "crosscon_hv_config.h"
#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>

volatile struct tee_shm ipc_shm;
volatile struct tee_param param[4] = {0};
volatile struct tee_invoke_func_arg invoke_func_arg = {0};
volatile struct tee_open_session_arg session_arg = {0};
int session_id;

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
    __DMB(); // Ensure memory read ordering before touching shared memory

    tee_call_type_t call_type = GP_SHARED_MSG_PTR->call_type;

    switch (call_type) {
        case TEE_CALL_TYPE_INVOKE_FUNC:
            /* Copy back return values */
            invoke_func_arg.ret        = msg->invoke_args.ret;
            invoke_func_arg.ret_origin = msg->invoke_args.ret_origin;

            LOG_INF("TEE returned: ret = 0x%08X, origin = 0x%08X", invoke_func_arg.ret, invoke_func_arg.ret_origin);

            for (int i = 0; i < VMS_MAX_PARAMS; i++) {
                uint64_t attr = msg->params[i].attr;
                uint32_t type = attr & TEE_PARAM_ATTR_TYPE_MASK;

                /* Copy back param metadata */
                param[i].attr = msg->params[i].attr;
                param[i].a    = msg->params[i].a;
                param[i].b    = msg->params[i].b;
                param[i].c    = msg->params[i].c;

                const char *type_str = "UNKNOWN";

                switch (type) {
                case TEE_PARAM_ATTR_TYPE_NONE:
                    type_str = "NONE";
                    break;
                case TEE_PARAM_ATTR_TYPE_VALUE_INPUT:
                    type_str = "VALUE_INPUT";
                    break;
                case TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT:
                    type_str = "VALUE_OUTPUT";
                    break;
                case TEE_PARAM_ATTR_TYPE_VALUE_INOUT:
                    type_str = "VALUE_INOUT";
                    break;
                case TEE_PARAM_ATTR_TYPE_MEMREF_INPUT:
                    type_str = "MEMREF_INPUT";
                    break;
                case TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
                    type_str = "MEMREF_OUTPUT";
                    break;
                case TEE_PARAM_ATTR_TYPE_MEMREF_INOUT:
                    type_str = "MEMREF_INOUT";
                    break;
                }

                LOG_INF("Param[%d] type: %s", i, type_str);

                if (type == TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT ||
                    type == TEE_PARAM_ATTR_TYPE_MEMREF_INOUT) {

                    const volatile uint8_t *data = &msg->payload[param[i].a];
                    LOG_HEXDUMP_INF((const uint8_t *)data, param[i].b,
                                    "MEMREF Output data:");
                } else if (type == TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT ||
                           type == TEE_PARAM_ATTR_TYPE_VALUE_INOUT) {

                    LOG_INF("Value: a = 0x%08llX, b = 0x%08llX",
                            param[i].a, param[i].b);
                }
            }
            break;
        case TEE_CALL_TYPE_OPEN_SESSION:
            session_id = msg->session_args.session;
            break;
        case TEE_CALL_TYPE_CLOSE_SESSION:
            break;
    }

    __DMB(); // Ensure all writes complete before notifying
    LOG_INF("IRQ Handled.");
}
