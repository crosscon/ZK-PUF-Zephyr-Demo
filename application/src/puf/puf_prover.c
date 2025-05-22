#include "puf_prover.h"

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

    /* 6) debug‐print the MPI as hex */
    {
        /* 64 digits for 256-bit SHA + NULL + optional +/- sign */
        char hexstr[66];
        size_t olen = 0;
        ret = mbedtls_mpi_write_string(response,
                                       16,      /* radix = hex */
                                       hexstr,
                                       sizeof(hexstr),
                                       &olen);
        if (ret == 0) {
            printf("Response MPI = 0x%s\n", hexstr);
        } else {
            printf("Error writing MPI to string: -0x%04X\n", -ret);
        }
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

    /* 2) serialize to uncompressed binary form */
    size_t olen;
    /* group size in bytes = (bitlen + 7) / 8 */
    size_t pt_len = 1 + 2 * ((grp.pbits + 7) / 8);
    uint8_t *buf = malloc( pt_len );
    if( buf == NULL ) {
        printf( "OOM allocating point buffer\n" );
        return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    ret = mbedtls_ecp_point_write_binary( &grp,
                                          commitment,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &olen,
                                          buf,
                                          pt_len );
    if( ret != 0 ) {
        printf( "Error serializing point: -0x%04X\n", -ret );
        free(buf);
        return ret;
    }

    /* 3) hex-print the buffer */
    printf( "Commitment (uncompressed = %zu bytes):\n", olen );
    for( size_t i = 0; i < olen; i++ )
        printf( "%02X", buf[i] );
    printf( "\n" );

    free(buf);
    return 0;
}
