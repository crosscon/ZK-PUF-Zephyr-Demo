#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(PUF_VM);

#include "puf_prover.h"

int get_response_to_challenge(uint8_t *challenge, TEE_BigInt *response)
{
    int ret;
    uint8_t puf_key[PUF_KEY_SIZE];
    uint8_t combined[RESPONSE_SIZE];
    uint8_t hash[32];

    ret = puf_get_key(&puf_key);
    if(ret!=0){
        LOG_ERR("Error: Can't Get Response From PUF");
        return ret;
    }

    // Combine keyCode and challenge
    memcpy(combined, puf_key, PUF_KEY_SIZE);
    memcpy(combined + PUF_KEY_SIZE, challenge, CHALLENGE_SIZE);

    ret = puf_flush_key(&puf_key);
    if(ret!=0){
        LOG_ERR("Error: Can't Flush PUF from memory");
        return ret;
    }

    // Hash the combined data into temporary buffer
    mbedtls_sha256(combined, RESPONSE_SIZE, hash, 0);

    ret = TEE_BigIntConvertFromBytes(response, hash, sizeof(hash));
    if (ret != 0) {
        LOG_ERR("Error: Can't read hash into MPI: -0x%04X\n", -ret);
        return ret;
    }

    return 0;
}

int get_commited_value(TEE_BigInt *response_0, TEE_BigInt *response_1, TEE_ECPoint *commitment)
{
    TEE_Result ret = TEE_ECPointMulAdd(commitment, grp, response_0, g, response_1, h);
    if(ret!=0){
        LOG_ERR("Error: Can't Calculate Commitment");
        return ret;
    }

    return 0;
}

// Writes raw 64-byte commitment (X || Y) into `raw_commitment`.
int extract_raw_commitment(TEE_ECPoint *commitment, uint8_t *raw_commitment)
{
    size_t coord_len = 32;
    size_t uncmp_len = 1 + 2 * coord_len;          // prefix + X + Y

    uint8_t *tmp = malloc(uncmp_len);
    if (!tmp) {
        LOG_ERR("Error: OOM allocating temp buffer\n");
        return -1;
    }

    TEE_Result ret = TEE_ECPointExportBytes(commitment, grp,
                                             tmp, &uncmp_len);
    if (ret != 0) {
        LOG_ERR("Error: Can't Serialize Point: -0x%04X\n", -ret);
        free(tmp);
        return ret;
    }

    memcpy(raw_commitment, tmp + 1, 2 * coord_len);
    free(tmp);
    return 0;
}
