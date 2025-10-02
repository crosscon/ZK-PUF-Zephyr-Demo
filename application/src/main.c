#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(GUEST_VM);

#include "crosscon_hv_config.h"
#include "globals.h"

/* Global vars or context for TEE session */
const struct device *tee_dev = NULL;
volatile uint8_t *shm_ptr = NULL;

#define CLIENT_UUID_BYTES { \
    0x10, 0x20, 0x30, 0x40, \
    0x50, 0x60, \
    0x70, 0x80, \
    0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00 \
}

#define PUF_TA_UUID_BYTES { \
    0x00, 0x11, 0x22, 0x33, \
    0x44, 0x55, \
    0x66, 0x77, \
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF \
}

static const uint8_t PUF_TA_UUID[TEE_UUID_LEN] = PUF_TA_UUID_BYTES;

static const uint8_t CLIENT_UUID[TEE_UUID_LEN] = CLIENT_UUID_BYTES;

int main(void)
{
    tee_dev = device_get_binding("crosscon_hv_tee");
    if (!tee_dev) {
        LOG_ERR("Failed to bind device 'crosscon_hv_tee'");
        return -1;
    }

    ipc_shm.dev   = tee_dev;
    ipc_shm.addr  = (void *)(uintptr_t)VMS_PAYLOAD_PTR;
    ipc_shm.size  = (uint64_t)VMS_USABLE_PAYLOAD_SIZE;
    ipc_shm.flags = 0;
    shm_ptr = (volatile uint8_t *)ipc_shm.addr;

    memcpy(session_arg.uuid, PUF_TA_UUID, TEE_UUID_LEN);
    memcpy(session_arg.clnt_uuid, CLIENT_UUID, TEE_UUID_LEN);
    session_arg.clnt_login = TEE_IOCTL_LOGIN_USER;
    session_arg.cancel_id  = 0;

    int res = tee_open_session(tee_dev, &session_arg, 0, NULL, &session_id);
    if (res || session_arg.ret) {
        LOG_ERR("tee_open_session() failed: res=%d, TEE_ret=0x%08x", res, session_arg.ret);
        return -1;
    }

    printk("TEE Session opened: ID = %u\n", session_id);
    printk("Shell ready. Type `help` for available commands\n");

    return 0;
}
