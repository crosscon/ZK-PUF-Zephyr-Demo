#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(PUF_VM, LOG_LEVEL_INF);

#include "fsl_puf.h"
#include <stdio.h>

#define PUF_KEY_SIZE 32
#define PUF_KEY_CODE_SIZE PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(PUF_KEY_SIZE)

int main(void)
{
    uint8_t activation_code[PUF_ACTIVATION_CODE_SIZE];
    uint8_t key_code[PUF_KEY_CODE_SIZE];

    puf_config_t pufConfig;
    status_t status;
    PUF_GetDefaultConfig(&pufConfig);

    status = PUF_Init(PUF, &pufConfig);
    if (status != kStatus_Success) {
        LOG_ERR("Error: PUF initialization failed!");
        return status;
    }
    LOG_INF("PUF Initialized Successfully.");

    memset(activation_code, 0, PUF_ACTIVATION_CODE_SIZE);
    status = PUF_Enroll(PUF, activation_code, PUF_ACTIVATION_CODE_SIZE);

    if (status != kStatus_Success) {
        LOG_ERR("Error: PUF enrollment failed!");
        return status;
    }

    LOG_INF("PUF Enroll successful. Activation Code created.");

    LOG_HEXDUMP_INF(activation_code, PUF_ACTIVATION_CODE_SIZE, "Activation Code");

    PUF_Deinit(PUF, &pufConfig);
    status = PUF_Init(PUF, &pufConfig);
    if (status != kStatus_Success) {
        LOG_ERR("Error: PUF reinitialization after enrollment failed!");
        return status;
    }
    LOG_INF("PUF Reinitialized after enrollment.");

    status = PUF_Start(PUF, activation_code, PUF_ACTIVATION_CODE_SIZE);
    if (status != kStatus_Success) {
        LOG_ERR("Error: PUF start failed!");
        return status;
    }
    LOG_INF("PUF Started successfully.");

    status = PUF_SetIntrinsicKey(PUF, kPUF_KeyIndex_01, PUF_KEY_SIZE, key_code, PUF_KEY_CODE_SIZE);
    if (status != kStatus_Success) {
        LOG_ERR("Error: PUF Intrinsic key 1 generation failed!");
        return status;
    }

    LOG_HEXDUMP_INF(key_code, PUF_KEY_CODE_SIZE, "Intrinsic key code");

    LOG_INF("END");

    return 0;
}
