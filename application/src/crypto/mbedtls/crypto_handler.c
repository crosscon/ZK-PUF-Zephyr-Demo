#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(PUF_VM);

#include "crypto_handler.h"
#include <zephyr/random/random.h>

#define MBEDTLS_HEAP_SIZE  8192
#define MAX_HASH_TRIES 10

mbedtls_ecp_point h;
mbedtls_ecp_point g;
mbedtls_ecp_group grp;

static unsigned char mbedtls_heap[MBEDTLS_HEAP_SIZE] __aligned(4);

int init_crypto()
{
    int ret;

    mbedtls_ecp_point_init(&g);
    mbedtls_ecp_point_init(&h);
    mbedtls_ecp_group_init(&grp);

    mbedtls_memory_buffer_alloc_init(mbedtls_heap, sizeof(mbedtls_heap));
    ret = inner_init_ECC(&grp, &h, &g);
    if (ret != 0) return ret;
}

void log_mpi_hex(const char *label, const mbedtls_mpi *X)
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

int rand_function(void *rng_state, unsigned char *output, size_t len) {
    (void)rng_state;
    sys_csrand_get(output, len);  
    return 0;
}

int get_random_mpi(mbedtls_mpi *X)
{
    int ret;
    size_t n_bytes = mbedtls_mpi_size(&grp.N);

    mbedtls_mpi_init(X);

    if ((ret = mbedtls_mpi_fill_random(X,
                                       n_bytes,
                                       rand_function,
                                       NULL)) != 0)
        return ret;

    return mbedtls_mpi_mod_mpi(X, X, &grp.N);
}

// uses Hash-to-Curve Point Generation for ensuring independence of g and h
int inner_init_ECC(mbedtls_ecp_group *grp, mbedtls_ecp_point *h, mbedtls_ecp_point *g)
{
    int ret = 0;
    const char *label = "secp256r1-h-generator";
    size_t label_len = strlen(label);

    unsigned char hash[32];
    unsigned char buf[34];
    const unsigned char *p;

    if ((ret = mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1)) != 0)
        return ret;

    if ((ret = mbedtls_ecp_copy(g, &grp->G)) != 0)
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
        ret = mbedtls_ecp_tls_read_point(grp, h, &p, sizeof(buf));

        if (ret != 0) {
            // Try odd Y (0x03 prefix)
            buf[1] = 0x03;
            p = buf;
            ret = mbedtls_ecp_tls_read_point(grp, h, &p, sizeof(buf));
        }

        if (ret == 0 && mbedtls_ecp_is_zero(h) == 0) {
            LOG_DBG("Valid h point found at counter %u", ctr);
            break;
        }

        // Optional: log why it failed
        LOG_DBG("Try %u: failed to parse point, ret = -0x%04X", ctr, -ret);
    }

    if (ret != 0) {
        LOG_ERR("Failed to generate valid h after %d tries", MAX_HASH_TRIES);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    return ret;
}
