#include "crosscon_hv_config.h"
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(CROSSCON_HV_TEE);

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
    msg->call_type                = TEE_CALL_TYPE_OPEN_SESSION;
    /* Write tee_open_session_arg fields into session_args */
    // uuid and clnt_uuid are arrays so we use memcpy
    memcpy(msg->session_args.uuid, arg->uuid, TEE_UUID_LEN);
    memcpy(msg->session_args.clnt_uuid, arg->clnt_uuid, TEE_UUID_LEN);
    msg->session_args.clnt_login  = arg->clnt_login;
    msg->session_args.cancel_id   = 0;  // Unsupported
    msg->session_args.session     = 0;  // Will be filled by TEE
    msg->session_args.ret         = 0;
    msg->session_args.ret_origin  = 0;

    /* Encode the paramTypes field */
    uint32_t t0 = (num_param > 0) ? (param[0].attr & TEE_PARAM_ATTR_TYPE_MASK)
                                 : TEE_PARAM_ATTR_TYPE_NONE;
    uint32_t t1 = (num_param > 1) ? (param[1].attr & TEE_PARAM_ATTR_TYPE_MASK)
                                 : TEE_PARAM_ATTR_TYPE_NONE;
    uint32_t t2 = (num_param > 2) ? (param[2].attr & TEE_PARAM_ATTR_TYPE_MASK)
                                 : TEE_PARAM_ATTR_TYPE_NONE;
    uint32_t t3 = (num_param > 3) ? (param[3].attr & TEE_PARAM_ATTR_TYPE_MASK)
                                 : TEE_PARAM_ATTR_TYPE_NONE;
    msg->session_args.paramTypes = CROSSCON_PARAM_TYPES(t0, t1, t2, t3);

    /* Fill each param entry in the shared header */
    for (unsigned int i = 0; i < num_param && i < 4; i++) {
        msg->params[i].attr = param[i].attr;
        msg->params[i].a    = param[i].a;
        msg->params[i].b    = param[i].b;
        msg->params[i].c    = param[i].c;
    }

    /* Signal the remote TEE to begin processing */
    ipc_notify(0, 0);

    return 0;
};

static int crosscon_hv_tee_close_session(const struct device *dev, uint32_t session_id)
{
    msg->call_type               = TEE_CALL_TYPE_CLOSE_SESSION;
    /* There's no tee_close_session_arg fields so we're using session_args */
    memset(&msg->session_args, 0, sizeof(GP_OpenSessionArgs));
    msg->session_args.session = session_id;

    /* Signal the remote TEE to begin processing */
    ipc_notify(0, 0);

    return 0;
};

static int crosscon_hv_tee_cancel(const struct device *dev, uint32_t session_id, uint32_t cancel_id)
{
    return 0;
};

// TEE_PARAM_ATTR_TYPE_VALUE_* are not supported
static int crosscon_hv_tee_invoke_func(const struct device *dev,
                                       struct tee_invoke_func_arg *arg,
                                       unsigned int num_param,
                                       struct tee_param *param)
{
    msg->call_type               = TEE_CALL_TYPE_INVOKE_FUNC;
    /* Write tee_invoke_func_arg fields into invoke_args */
    msg->invoke_args.func        = arg->func;
    msg->invoke_args.session     = arg->session;
    msg->invoke_args.cancel_id   = arg->cancel_id;
    msg->invoke_args.ret         = 0;  // Will be filled by TEE
    msg->invoke_args.ret_origin  = 0;

    /* Encode the paramTypes field */
    uint32_t t0 = (num_param > 0) ? (param[0].attr & TEE_PARAM_ATTR_TYPE_MASK)
                                 : TEE_PARAM_ATTR_TYPE_NONE;
    uint32_t t1 = (num_param > 1) ? (param[1].attr & TEE_PARAM_ATTR_TYPE_MASK)
                                 : TEE_PARAM_ATTR_TYPE_NONE;
    uint32_t t2 = (num_param > 2) ? (param[2].attr & TEE_PARAM_ATTR_TYPE_MASK)
                                 : TEE_PARAM_ATTR_TYPE_NONE;
    uint32_t t3 = (num_param > 3) ? (param[3].attr & TEE_PARAM_ATTR_TYPE_MASK)
                                 : TEE_PARAM_ATTR_TYPE_NONE;
    msg->invoke_args.paramTypes = CROSSCON_PARAM_TYPES(t0, t1, t2, t3);

    /* Fill each param entry in the shared header */
    for (unsigned int i = 0; i < num_param && i < 4; i++) {
        msg->params[i].attr = param[i].attr;
        msg->params[i].a    = param[i].a;
        msg->params[i].b    = param[i].b;
        msg->params[i].c    = param[i].c;
    }

    crosscon_hv_func_call_debug(msg);

    /* Signal the remote TEE to begin processing */
    ipc_notify(0, 0);

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
    msg = GP_SHARED_MSG_PTR;
    return 0;
}

void crosscon_hv_func_call_debug(volatile GP_SharedMessage *msg)
{
    /* Read header (invoke_args) */
    LOG_DBG("invoke_args:");
    LOG_DBG("  func       = 0x%08X", msg->invoke_args.func);
    LOG_DBG("  session    = 0x%08X", msg->invoke_args.session);
    LOG_DBG("  cancel_id  = 0x%08X", msg->invoke_args.cancel_id);
    LOG_DBG("  ret        = 0x%08X", msg->invoke_args.ret);
    LOG_DBG("  ret_origin = 0x%08X", msg->invoke_args.ret_origin);
    LOG_DBG("  paramTypes = 0x%08X", msg->invoke_args.paramTypes);

    /* Read each parameter's metadata */
    for (int i = 0; i < VMS_MAX_PARAMS; ++i) {
        LOG_DBG("param[%d]: attr=0x%llX, a=0x%llX, b=0x%llX, c=0x%llX",
            i,
            msg->params[i].attr,
            msg->params[i].a,
            msg->params[i].b,
            msg->params[i].c
        );
    }
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
