#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(PUF_VM);

#include "crypto.h"
#include <zephyr/random/random.h>
#include "mbedtls/sha256.h"
#include "mbedtls/ecp.h"

// ----------------------------------------
// TEE_BigInt mapping
// ----------------------------------------

struct TEE_BigInt {
    mbedtls_mpi mpi;
};

TEE_BigInt* TEE_BigIntAlloc(void) {
    TEE_BigInt *x = malloc(sizeof(TEE_BigInt));
    if (x) mbedtls_mpi_init(&x->mpi);
    return x;
}

void TEE_BigIntInit(TEE_BigInt *X) {
    if (X) {
        mbedtls_mpi_init(&X->mpi);
    }
}

void TEE_BigIntFree(TEE_BigInt *X) {
    if (X) {
        mbedtls_mpi_free(&X->mpi);
        free(X);
    }
}

TEE_Result TEE_BigIntConvertFromBytes(TEE_BigInt *X, const uint8_t *buf, size_t len) {
    if (!X || !buf || len > TEE_MAX_BIGINT_BYTES) return TEE_ERROR_BAD_PARAMETERS;
    return mbedtls_mpi_read_binary(&X->mpi, buf, len);
}

TEE_Result TEE_BigIntConvertToBytes(const TEE_BigInt *X, uint8_t *buf, size_t len) {
    if (!X || !buf || len > TEE_MAX_BIGINT_BYTES) return TEE_ERROR_BAD_PARAMETERS;
    return mbedtls_mpi_write_binary(&X->mpi, buf, len);
}

TEE_Result TEE_BigIntMul(TEE_BigInt *R, const TEE_BigInt *A, const TEE_BigInt *B) {
    return mbedtls_mpi_mul_mpi(&R->mpi, &A->mpi, &B->mpi);
}

TEE_Result TEE_BigIntAdd(TEE_BigInt *R, const TEE_BigInt *A, const TEE_BigInt *B) {
    return mbedtls_mpi_add_mpi(&R->mpi, &A->mpi, &B->mpi);
}

TEE_Result TEE_BigIntMod(TEE_BigInt *R, const TEE_BigInt *A, const TEE_BigInt *N) {
    return mbedtls_mpi_mod_mpi(&R->mpi, &A->mpi, &N->mpi);
}

TEE_Result TEE_BigIntGenerateRandom(TEE_BigInt *X, size_t num_bytes,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng) {
    return mbedtls_mpi_fill_random(&X->mpi, num_bytes, f_rng, p_rng);
}

size_t TEE_BigIntSizeInBytes(const TEE_BigInt *X) {
    return mbedtls_mpi_size(&X->mpi);
}

// ----------------------------------------
// TEE_ECCurve mapping
// ----------------------------------------

struct TEE_ECCurve {
    mbedtls_ecp_group grp;
};

TEE_ECCurve* TEE_ECCurveAlloc(void) {
    TEE_ECCurve *curve = malloc(sizeof(TEE_ECCurve));
    mbedtls_ecp_group_init(&curve->grp);
    return curve;
}

// ----------------------------------------
// TEE_ECPoint mapping
// ----------------------------------------

struct TEE_ECPoint {
    mbedtls_ecp_point point;
};

TEE_ECPoint* TEE_ECPointAlloc(void) {
    TEE_ECPoint *pt = malloc(sizeof(TEE_ECPoint));
    mbedtls_ecp_point_init(&pt->point);
    return pt;
}

void TEE_ECPointFree(TEE_ECPoint *pt) {
    if (!pt) return;
    mbedtls_ecp_point_free(&pt->point);
    free(pt);
}

TEE_Result TEE_ECPointExportBytes(const TEE_ECPoint *pt,
                                  const TEE_ECCurve *curve,
                                  uint8_t *buf, size_t *len) {
    size_t l = *len;
    int ret = mbedtls_ecp_point_write_binary(&curve->grp, &pt->point,
                                             MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &l, buf, l);
    if (ret == MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL)
        return TEE_ERROR_SHORT_BUFFER;
    else if (ret != 0)
        return TEE_ERROR_GENERIC;
    *len = l;
    return TEE_SUCCESS;
}

TEE_Result TEE_ECPointMulAdd(TEE_ECPoint *R,
                             const TEE_ECCurve *grp,
                             const TEE_BigInt *m,
                             const TEE_ECPoint *P,
                             const TEE_BigInt *n,
                             const TEE_ECPoint *Q) {
    if (grp->grp.id == MBEDTLS_ECP_DP_NONE) {
        LOG_ERR("TEE_ECPointMulAdd: ECC group is uninitialized!");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    int ret = mbedtls_ecp_muladd(&grp->grp, &R->point,
                                 &m->mpi, &P->point,
                                 &n->mpi, &Q->point);

    if (ret != 0) {
        LOG_ERR("mbedtls_ecp_muladd failed: -0x%04X", -ret);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

// ----------------------------------------
// TEE_Digest mapping (SHA-256)
// ----------------------------------------

struct TEE_DigestOperation {
    mbedtls_sha256_context ctx;
    bool is_finalized;
};

TEE_DigestOperation* TEE_AllocateDigestOperation(void) {
    TEE_DigestOperation *op = malloc(sizeof(TEE_DigestOperation));
    if (!op) return NULL;
    mbedtls_sha256_init(&op->ctx);
    mbedtls_sha256_starts(&op->ctx, 0 /* is224 = 0 -> SHA-256 */);
    op->is_finalized = false;

    return op;
}

void TEE_FreeDigestOperation(TEE_DigestOperation *op) {
    if (!op) return;
    mbedtls_sha256_free(&op->ctx);
    free(op);
}

TEE_Result TEE_DigestUpdate(TEE_DigestOperation *op,
                            const void *data, size_t len) {
    if (!op || op->is_finalized) return TEE_ERROR_BAD_PARAMETERS;
    mbedtls_sha256_update(&op->ctx, data, len);
    return TEE_SUCCESS;
}

TEE_Result TEE_DigestDoFinal(TEE_DigestOperation *op,
                             const void *data, size_t len,
                             uint8_t *digest, size_t *digest_len) {
    if (!op || !digest || !digest_len) return TEE_ERROR_BAD_PARAMETERS;
    if (data && len) mbedtls_sha256_update(&op->ctx, data, len);

    mbedtls_sha256_finish(&op->ctx, digest);
    *digest_len = 32;
    op->is_finalized = true;
    return TEE_SUCCESS;
}

// ----------------------------------------
// Crypto functions
// ----------------------------------------

#define MAX_HASH_TRIES 10

TEE_ECPoint *h = NULL;
TEE_ECPoint *g = NULL;
TEE_ECCurve *grp = NULL;

int init_crypto()
{
    int ret;

    h = TEE_ECPointAlloc();
    g = TEE_ECPointAlloc();
    grp = TEE_ECCurveAlloc();

    ret = inner_init_ECC(grp, h, g);
    if (ret != 0) return ret;

    return TEE_SUCCESS;
}

void log_bigint_hex(const char *label, const TEE_BigInt *X)
{
    /* How many bytes we need to represent X in big-endian */
    size_t n_bytes = mbedtls_mpi_size(X);
    uint8_t  buf[n_bytes];
    int      ret;

    /* Serialize X into buf[] */
    ret = mbedtls_mpi_write_binary(X, buf, n_bytes);
    if (ret != 0) {
        LOG_ERR("Error writing MPI %s: -0x%04X", label, -ret);
        return;
    }

    /* One call dumps buf[] as hex, prefixed by label: */
    LOG_HEXDUMP_DBG(buf, n_bytes, label);
}

void log_ecp_point(const char *label, const TEE_ECPoint *P)
{
    uint8_t buf[65];
    size_t len = sizeof(buf);

    LOG_DBG("log_ecp_point(): label=%s", label);

    TEE_Result ret = TEE_ECPointExportBytes(P, grp, buf, &len);
    if (ret != TEE_SUCCESS) {
        LOG_ERR("log_ecp_point(): Failed to serialize %s: 0x%04X", label, ret);
        return;
    }

    LOG_HEXDUMP_DBG(buf, len, label);
}

int rand_function(void *rng_state, unsigned char *output, size_t len) {
    (void)rng_state;
    sys_csrand_get(output, len);
    return 0;
}

int get_random_bigint(TEE_BigInt *X)
{
    int ret;
    size_t n_bytes = mbedtls_mpi_size(&grp->grp.N);

    mbedtls_mpi_init(X);

    if ((ret = mbedtls_mpi_fill_random(X,
                                       n_bytes,
                                       rand_function,
                                       NULL)) != 0)
        return ret;

    return mbedtls_mpi_mod_mpi(X, X, &grp->grp.N);
}

// uses Hash-to-Curve Point Generation for ensuring independence of g and h
int inner_init_ECC(TEE_ECCurve *curve, TEE_ECPoint *h, TEE_ECPoint *g)
{
    int ret = 0;
    const char *label = "secp256r1-h-generator";
    size_t label_len = strlen(label);

    unsigned char hash[32];
    unsigned char buf[34];
    const unsigned char *p;

    if ((ret = mbedtls_ecp_group_load(&curve->grp, MBEDTLS_ECP_DP_SECP256R1)) != 0)
        return ret;

    if ((ret = mbedtls_ecp_copy(&g->point, &curve->grp.G)) != 0)
        return ret;

    // This should work but the check if result is on EC doesn't :(
    // Using value calculated with scripts/proofs/h_generation_calc.sage and "secp256r1-h-generator"
    //
    for (unsigned int ctr = 0; ctr < MAX_HASH_TRIES; ctr++) {
        // Build input = label || ctr_be
        unsigned char input[64] = {0};
        unsigned char ctr_be[4] = {
            (unsigned char)(ctr >> 24),
            (unsigned char)(ctr >> 16),
            (unsigned char)(ctr >> 8),
            (unsigned char)(ctr)
        };
        memcpy(input, label, label_len > 60 ? 60 : label_len);
        memcpy(input + 60, ctr_be, 4);

        // Compute SHA-256
        mbedtls_sha256(input, sizeof(input), hash, 0);

        LOG_HEXDUMP_DBG(hash, 32, "X candidate (hash)");

        // `mbedtls_ecp_tls_read_point` expects length at index 0 and type of compression at index 1
        // Try even Y (0x02 prefix)
        buf[0] = 0x21;
        buf[1] = 0x02;
        memcpy(buf + 2, hash, 33);
        p = buf;  // Reset p before each call
        ret = mbedtls_ecp_tls_read_point(&curve->grp, &h->point, &p, sizeof(buf));

        if (ret != 0) {
            // Try odd Y (0x03 prefix)
            buf[1] = 0x03;
            p = buf;
            ret = mbedtls_ecp_tls_read_point(&curve->grp, &h->point, &p, sizeof(buf));
        }

        if (ret == 0 && mbedtls_ecp_is_zero(&h->point) == 0) {
            LOG_DBG("Valid h point found at counter %u", ctr);
            break;
        }

        LOG_DBG("Try %u: failed to parse point, ret = -0x%04X", ctr, -ret);
    }

    if (ret != 0) {
        LOG_ERR("Failed to generate valid h after %d tries", MAX_HASH_TRIES);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    return ret;
}
