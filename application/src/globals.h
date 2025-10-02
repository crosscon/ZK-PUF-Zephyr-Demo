#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>

/* Global vars or context for TEE session */
extern const struct device *tee_dev;
extern volatile uint8_t *shm_ptr;
