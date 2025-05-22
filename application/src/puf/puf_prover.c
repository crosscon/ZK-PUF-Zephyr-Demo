#include "puf_prover.h"

int inner_print_ecp_point(const char *label, const mbedtls_ecp_point *P) {
    size_t pt_len = 1 + 2 * ((grp.pbits + 7) / 8);
    uint8_t *buf = malloc(pt_len);
    if (!buf) {
        printf("OOM allocating point buffer for %s\n", label);
        return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    size_t olen = 0;
    int ret = mbedtls_ecp_point_write_binary(&grp, P,
                                             MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &olen, buf, pt_len);
    if (ret != 0) {
        printf("Error serializing point %s: -0x%04X\n", label, -ret);
        free(buf);
        return ret;
    }

    printf("%s (uncompressed, %zu bytes):\n", label, olen);
    for (size_t i = 0; i < olen; i++)
        printf("%02X", buf[i]);
    printf("\n");

    free(buf);
    return 0;
}

int get_response_to_challenge(uint8_t *challenge, mbedtls_mpi *response)
{
    int ret;
    uint8_t puf_key[PUF_KEY_SIZE];
    uint8_t combined[RESPONSE_SIZE];
    uint8_t hash[32];

    ret = puf_get_key(&puf_key);
    if(ret!=0){
        printf("Error While Getting Response From PUF");
        return ret;
    }

    // Combine keyCode and challenge
    memcpy(combined, puf_key, PUF_KEY_SIZE);
    memcpy(combined + PUF_KEY_SIZE, challenge, CHALLENGE_SIZE);

    ret = puf_flush_key(&puf_key);
    if(ret!=0){
        printf("Error While Flushing PUF from memory");
        return ret;
    }

    // Hash the combined data into temporary buffer
    mbedtls_sha256(combined, RESPONSE_SIZE, hash, 0);

    ret = mbedtls_mpi_read_binary(response, hash, sizeof(hash));
    if (ret != 0) {
        printf("Error reading hash into MPI: -0x%04X\n", -ret);
        return ret;
    }

    return 0;
}

int get_commited_value(mbedtls_mpi *response_0, mbedtls_mpi *response_1, mbedtls_ecp_point *commitment)
{
    int ret;
    ret = mbedtls_ecp_muladd(&grp, commitment, response_0, &g, response_1, &h);
    if(ret!=0){
        printf("Error While Calculating Commitment");
        printf("\r\n%d",ret);
        return ret;
    }

    inner_print_ecp_point("Commitment", commitment);
    return 0;
}

// Writes raw 64-byte commitment (X || Y) into `raw_commitment`.
int extract_raw_commitment(mbedtls_ecp_point *commitment, uint8_t *raw_commitment)
{
    int ret;
    size_t coord_len = (grp.pbits + 7) / 8;        // typically 32
    size_t uncmp_len = 1 + 2 * coord_len;          // prefix + X + Y

    uint8_t *tmp = malloc(uncmp_len);
    if (!tmp) {
        printf("OOM allocating temp buffer\n");
        return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    ret = mbedtls_ecp_point_write_binary(&grp, commitment,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &uncmp_len,
                                         tmp, uncmp_len);
    if (ret != 0) {
        printf("Error serializing point: -0x%04X\n", -ret);
        free(tmp);
        return ret;
    }

    memcpy(raw_commitment, tmp + 1, 2 * coord_len);
    free(tmp);
    return 0;
}
