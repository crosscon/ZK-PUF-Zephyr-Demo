#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(PUF_VM);

#include "puf_prover.h"

// Combine UUID, PUF response, and challenge into a single buffer
/* We only have a single TA here, but in a true multi-tenant TEE setup,
 * each TA should have its UUID mixed with the PUF response to enforce
 * identity-scoped personalization.
 */
int get_response_to_challenge(uint8_t *challenge, TEE_BigInt *response)
{
    TEE_DigestOperation *digest = TEE_AllocateDigestOperation();
    int ret;
    uint8_t puf_key[PUF_RESPONSE_SIZE];
    uint8_t interm_digest[32];  // Output of stage 1
    uint8_t final_digest[32];   // Final result
    size_t digest_len = 32;

    if (!digest) return TEE_ERROR_OUT_OF_MEMORY;

    ret = puf_get_key(&puf_key);
    if (ret != 0) {
        LOG_ERR("Error: Can't Get Response From PUF");
        TEE_FreeDigestOperation(digest);
        return ret;
    }

    // H(UUID || PUF_response)
    TEE_DigestUpdate(digest, PUF_TA_UUID, TEE_UUID_LEN);
    TEE_DigestUpdate(digest, puf_key, PUF_RESPONSE_SIZE);
    ret = TEE_DigestDoFinal(digest, NULL, 0, interm_digest, &digest_len);
    if (ret != 0) {
        TEE_FreeDigestOperation(digest);
        return ret;
    }

    ret = puf_flush_key(&puf_key);
    if (ret != 0) {
        LOG_ERR("Error: Can't Flush PUF from memory");
        TEE_FreeDigestOperation(digest);
        return ret;
    }

    // H(interm_digest || challenge)
    digest = TEE_AllocateDigestOperation();  // fresh context
    if (!digest) return TEE_ERROR_OUT_OF_MEMORY;

    TEE_DigestUpdate(digest, interm_digest, sizeof(interm_digest));
    TEE_DigestUpdate(digest, challenge, CHALLENGE_SIZE);
    ret = TEE_DigestDoFinal(digest, NULL, 0, final_digest, &digest_len);
    TEE_FreeDigestOperation(digest);
    if (ret != 0) return ret;

    ret = TEE_BigIntConvertFromBytes(response, final_digest, digest_len);
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
