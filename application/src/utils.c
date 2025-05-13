#include <stdio.h>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ecp.h"
#include "utils.h"

void sha256_hash(const unsigned char *data, size_t data_len,
    unsigned char *output) {
    mbedtls_sha256(data, data_len, output, 0);
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


size_t export_commitment(mbedtls_ecp_group *grp,const mbedtls_ecp_point *C, uint8_t *buf, size_t buf_size) {

    size_t olen;
	int ret = mbedtls_ecp_point_write_binary(grp, C, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, buf_size);

    return (ret == 0) ? olen : -1;
}

int import_commitment(mbedtls_ecp_group *grp,const uint8_t *buf, mbedtls_ecp_point *P) {
    int ret = mbedtls_ecp_point_read_binary(grp, P, buf, 65); // 65 bytes for uncompressed point
    return ret;
}

int generate_random_numbers(mbedtls_mpi *num, mbedtls_mpi *num2) {
    if (!rng_initialized) {
        if (init_random_generator() != 0) {
            return 1;
        }
    }

    unsigned char randomBytes[64]; // 2x 32 bytes

    if (mbedtls_ctr_drbg_random(&ctr_drbg, randomBytes, sizeof(randomBytes)) != 0) {
        return 1;
    }

    if (mbedtls_mpi_read_binary(num, randomBytes, 32) != 0) {
        return 1;
    }
    if (mbedtls_mpi_read_binary(num2, randomBytes + 32, 32) != 0) {
        return 1;
    }

    return 0;
}

void print_mpi(const char *label, const mbedtls_mpi *value) {
    char buf[100];
    size_t olen;
    if (mbedtls_mpi_write_string(value, 16, buf, sizeof(buf), &olen) == 0) {
        printf("%s = %s\n", label, buf);
    } else {
        printf("Failed to print %s\n", label);
    }
}


void print_ecp_point(const char *label, const mbedtls_ecp_group *grp, const mbedtls_ecp_point *point) {

    unsigned char buf[100];
    size_t olen;

    if (mbedtls_ecp_point_write_binary(grp, point,
            MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, sizeof(buf)) == 0)
    {
        printf("%s = ", label);
        for (size_t i = 0; i < olen; i++) {
            printf("%02X", buf[i]);
        }
        printf("\n");
    } else {
        printf("Failed to print %s (EC point)\n", label);
    }
}

int init_random_generator() {
    const char *pers = "nonce_gen";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *)pers, strlen(pers)) != 0) {
        printf("Failed to seed random generator\n");
        return -1;
    }
    rng_initialized = 1;
    return 0;
}

int hex_string_to_bytes(const char *hex, uint8_t *out, size_t out_size) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > out_size) {
        return -1; // Invalid length or buffer size too small
    }

    for (size_t i = 0; i < len / 2; i++) {
        sscanf(hex + 2 * i, "%2hhx", &out[i]); // Read two characters as one byte
    }
    return 0; // Success
}
