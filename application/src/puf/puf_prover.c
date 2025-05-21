#include "puf_prover.h"

int get_response_to_challenge(uint8_t *challenge, uint8_t *response)
{
    int ret;
    uint8_t puf_key[PUF_KEY_SIZE];

    uint8_t combined[RESPONSE_SIZE];

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

    // Hash the combined data
    mbedtls_sha256(combined, RESPONSE_SIZE, response, 0);

    printf("Response: ");
    for (int i = 0; i < RESPONSE_SIZE; i++) {
        printf("%02X", response[i]);
    }
    printf("\r\n");

    return 0;
}
