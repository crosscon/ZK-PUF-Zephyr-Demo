#ifndef PUF_PROVER_H
#define PUF_PROVER_H

#include <stdint.h>

#define CHALLENGE_SIZE 16

#ifndef PUF_KEY_SIZE
#define PUF_KEY_SIZE 32
#endif

#define RESPONSE_SIZE CHALLENGE_SIZE+PUF_KEY_SIZE

// Challenge arrays declaration
extern const uint8_t hardcoded_challenge_1[CHALLENGE_SIZE];
extern const uint8_t hardcoded_challenge_2[CHALLENGE_SIZE];

int get_response_to_challenge(uint8_t *challenge, uint8_t *response);

#endif /* PUF_PROVER_H */
