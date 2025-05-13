// config_data.h
#ifndef CONFIG_DATA_H
#define CONFIG_DATA_H

#include <stdint.h>

#define ENROLLMENT_IS_UP 1
#define COMMITMENT_BUFFER_SIZE 65
#define CHALLENGE_SIZE 16

// Commitment string declaration
extern const char *commitment_hex;

// Challenge arrays declaration
extern const uint8_t c1[CHALLENGE_SIZE];
extern const uint8_t c2[CHALLENGE_SIZE];

#endif // CONFIG_DATA_H
