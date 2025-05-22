#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(PUF_VM);

#include "crypto_handler.h"

#define CONSTANT_FOR_H_GENERATOR 123456789

mbedtls_ecp_group grp;
mbedtls_ecp_point h;
mbedtls_ecp_point g;

int init_crypto()
{
    int ret;
    ret = innner_init_ECC(&grp, &h, &g);
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

    size_t use_len;
	int rnd;

	if (rng_state != NULL)
		rng_state = NULL;

	while (len > 0) {
		use_len = len;
		if (use_len > sizeof(int))
			use_len = sizeof(int);

		rnd = rand();
		memcpy(output, &rnd, use_len);
		output += use_len;
		len -= use_len;
	}

	return (0);
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

int innner_init_ECC(mbedtls_ecp_group *grp, mbedtls_ecp_point *h, mbedtls_ecp_point *g )
{
    int ret;
    mbedtls_ecp_group_init(grp);
    mbedtls_ecp_point_init(h);
    mbedtls_ecp_point_init(g);
    ret = mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);

    if (ret != 0) {
        LOG_ERR("Error: Failed to load EC group");
        return ret;
    }

    mbedtls_ecp_copy( g, &grp->G );

    mbedtls_mpi x;
	mbedtls_mpi_init(&x);
	ret = mbedtls_mpi_lset(&x, CONSTANT_FOR_H_GENERATOR);

     if (ret != 0) {
        LOG_ERR("Error: Failed to set X");
        return ret;
    }

    ret = mbedtls_ecp_mul(grp, h, &x, &grp->G, rand_function, NULL);

    if (ret != 0) {
        LOG_ERR("Error: Failed to generate h point");
        return ret;
    }

    return 0;
}
