#include "crosscon_hv_config.h"

#define TEE_IMPL_ID 1

/* Non-supported, Shared memory is set statically at compile time by hypervisor */
int tee_add_shm(const struct device *dev, void *addr, size_t align, size_t size,
		uint32_t flags, struct tee_shm **shmp)
{
    return 0;
};

/* Non-supported, Shared memory is set statically at compile time by hypervisor */
int tee_rm_shm(const struct device *dev, struct tee_shm *shm)
{
    return 0;
};

static int crosscon_hv_tee_get_version(const struct device *dev, struct tee_version_info *info)
{
	if (!info) {
		return -EINVAL;
	}

	info->impl_id = TEE_IMPL_ID;
	info->impl_caps = NULL;

        /* Definitions in zephyr/drivers/tee.h
         *
         * TEE_GEN_CAP_GP - GlobalPlatform compliant TEE
         * Not supported yet
         *
         * TEE_GEN_CAP_PRIVILEGED - Privileged device
         * Not relevant as we dont use privileged/unprivileged context
         *
         * TEE_GEN_CAP_REG_MEM - Supports registering shared memory
         * Non-supported, Shared memory is set statically at compile time by hypervisor
         *
         * TEE_GEN_CAP_MEMREF_NULL - Support NULL MemRef
         * TBD
         * This flag declares that TEE supports “NULL MemRef” parameters—that is,
         * when a Trusted Application (TA) is invoked it may legitimately see a
         * memref parameter whose buffer pointer is NULL.
         * Not all TEE implementations honor this: some will reject any NULL buffer with an error.
         *
         * */
	info->gen_caps = NULL;

	return 0;
}

static int crosscon_hv_tee_open_session(const struct device *dev, struct tee_open_session_arg *arg,
				  unsigned int num_param, struct tee_param *param,
				  uint32_t *session_id)
{
    return 0;
};

static int crosscon_hv_tee_close_session(const struct device *dev, uint32_t session_id)
{
    return 0;
};

static int crosscon_hv_tee_cancel(const struct device *dev, uint32_t session_id, uint32_t cancel_id)
{
    return 0;
};

static int crosscon_hv_tee_invoke_func(const struct device *dev,
                                       struct tee_invoke_func_arg *arg,
                                       unsigned int num_param,
                                       struct tee_param *param)
{
    /* Pointer to the shared message at the fixed base address */
    GP_SharedMessage *msg = (GP_SharedMessage *)VMS_IPC_BASE;

    /* Prepare the 32-bit paramTypes field from each param's type */
    uint32_t t0 = (num_param > 0) ? (param[0].attr & TEE_PARAM_ATTR_TYPE_MASK)
                                 : TEE_PARAM_ATTR_TYPE_NONE;
    uint32_t t1 = (num_param > 1) ? (param[1].attr & TEE_PARAM_ATTR_TYPE_MASK)
                                 : TEE_PARAM_ATTR_TYPE_NONE;
    uint32_t t2 = (num_param > 2) ? (param[2].attr & TEE_PARAM_ATTR_TYPE_MASK)
                                 : TEE_PARAM_ATTR_TYPE_NONE;
    uint32_t t3 = (num_param > 3) ? (param[3].attr & TEE_PARAM_ATTR_TYPE_MASK)
                                 : TEE_PARAM_ATTR_TYPE_NONE;
    msg->paramTypes = CROSSCON_PARAM_TYPES(t0, t1, t2, t3);

    /* Copy each parameter into the shared message */
    for (unsigned int i = 0; i < num_param && i < 4; i++) {
        uint32_t type = param[i].attr & TEE_PARAM_ATTR_TYPE_MASK;
        if (type == TEE_PARAM_ATTR_TYPE_NONE) {
            continue;
        }
        if (type == TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
            type == TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT ||
            type == TEE_PARAM_ATTR_TYPE_VALUE_INOUT) {
            /* Value parameters: copy a,b fields */
            msg->params.value[i].a = param[i].a;
            msg->params.value[i].b = param[i].b;
        } else if (type == TEE_PARAM_ATTR_TYPE_MEMREF_INPUT ||
                   type == TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT ||
                   type == TEE_PARAM_ATTR_TYPE_MEMREF_INOUT) {
            /* Memref parameters: use static shared buffer offsets */
            msg->params.memref[i].offset = param[i].a;
            msg->params.memref[i].size   = param[i].b;
        }
    }

    /* Signal the remote TEE VM that the request is ready */
    ipc_notify(0,0);
    return 0;
}


static int crosscon_hv_tee_shm_register(const struct device *dev, struct tee_shm *shm)
{
    return 0;
};

static int crosscon_hv_tee_shm_unregister(const struct device *dev, struct tee_shm *shm)
{
    return 0;
};

static int crosscon_hv_tee_suppl_recv(const struct device *dev, uint32_t *func, unsigned int *num_params,
				struct tee_param *param)
{
    return 0;
};

static int crosscon_hv_tee_suppl_send(const struct device *dev, unsigned int ret, unsigned int num_params,
				struct tee_param *param)
{
    return 0;
};

/* Minimal initialization */
static int crosscon_hv_tee_init(const struct device *dev)
{
    // TODO Shared memory cleaning should be present here
    return 0;
}

static const struct tee_driver_api crosscon_hv_tee_api = {
    .get_version   = crosscon_hv_tee_get_version,
    .open_session  = crosscon_hv_tee_open_session,
    .close_session = crosscon_hv_tee_close_session,
    .cancel        = crosscon_hv_tee_cancel,
    .invoke_func   = crosscon_hv_tee_invoke_func,
    .shm_register  = crosscon_hv_tee_shm_register,
    .shm_unregister= crosscon_hv_tee_shm_unregister,
    .suppl_recv    = crosscon_hv_tee_suppl_recv,
    .suppl_send    = crosscon_hv_tee_suppl_send,
};

DEVICE_DEFINE(crosscon_hv_tee,                    /* C symbol for the device */
              "crosscon_hv_tee",                  /* the string name used by device_get_binding() */
              crosscon_hv_tee_init,               /* init function */
              NULL,                               /* pm_control (optional) */
              NULL,                               /* driver data (struct, if you need) */
              NULL,                               /* driver config (if any) */
              POST_KERNEL,                        /* init level: when in boot-up */
              CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
              &crosscon_hv_tee_api);              /* pointer to your tee_driver_api */
