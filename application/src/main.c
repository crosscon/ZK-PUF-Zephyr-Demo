#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(GUEST_VM, LOG_LEVEL_DBG);

#include <stdio.h>
#include "crosscon_hv_config.h"
#include <zephyr/kernel.h>

#define IS_WRITE_TO_FLASH_ENABLED 1

#define CHALLENGE_SIZE 16
#define NONCE_SIZE 16

void vm_init() {
    IRQ_CONNECT(IPC_IRQ_ID, 0, ipc_irq_handler, NULL, 0);
    irq_enable(IPC_IRQ_ID);
    clear_mem();
    LOG_INF("VM Initialized");
}


void clear_mem(void)
{
    memset(message[0], 0, MESSAGE0_SIZE);
    memset(message[1], 0, MESSAGE1_SIZE);
    memset(message[2], 0, MESSAGE2_SIZE);
    memset(message[3], 0, MESSAGE3_SIZE);
    memset(message[4], 0, MESSAGE4_SIZE);
    memset(message[5], 0, MESSAGE5_SIZE);
    memset(message[6], 0, MESSAGE6_SIZE);
    memset(message[7], 0, MESSAGE7_SIZE);
    memset(message[8], 0, MESSAGE8_SIZE);
    memset(message[9], 0, MESSAGE9_SIZE);
    memset(message[10], 0, MESSAGE10_SIZE);
    memset(message[11], 0, MESSAGE11_SIZE);
    memset(message[12], 0, MESSAGE12_SIZE);
    memset(message[13], 0, MESSAGE13_SIZE);
}

int main(void)
{
    static const uint8_t uuid0[TEE_UUID_LEN] = {
        0x00, 0x11, 0x22, 0x33,   /* timeLow    */
        0x44, 0x55,               /* timeMid    */
        0x66, 0x77,               /* timeHi+ver */
        0x88, 0x99, 0xAA, 0xBB,   /* clockSeq   */
        0xCC, 0xDD, 0xEE, 0xFF    /* node       */
    };

    static const uint8_t uuid1[TEE_UUID_LEN] = {
        0x11, 0x22, 0x33, 0x44,   /* timeLow    */
        0x55, 0x66,               /* timeMid    */
        0x77, 0x88,               /* timeHi+ver */
        0x99, 0xAA, 0xBB, 0xCC,   /* clockSeq   */
        0xDD, 0xEE, 0xFF, 0x00    /* node       */
    };

    static const uint8_t uuid2[TEE_UUID_LEN] = {
        0x22, 0x33, 0x44, 0x55,   /* timeLow    */
        0x66, 0x77,               /* timeMid    */
        0x88, 0x99,               /* timeHi+ver */
        0xAA, 0xBB, 0xCC, 0xDD,   /* clockSeq   */
        0xEE, 0xFF, 0x00, 0x11    /* node       */
    };

    static const uint8_t challenge_1[CHALLENGE_SIZE] = {
        0x3C, 0xA1, 0xF4, 0x92,
        0x57, 0xB8, 0x0E, 0x6D,
        0x1F, 0xA9, 0xC3, 0xE7,
        0x74, 0x90, 0x12, 0xAD
    };

    static const uint8_t challenge_2[CHALLENGE_SIZE] = {
        0xFF, 0x00, 0xFF, 0x00,
        0xFF, 0x00, 0xFF, 0x00,
        0x00, 0xFF, 0x00, 0xFF,
        0x00, 0xFF, 0x00, 0xFF
    };

    static const uint8_t nonce[NONCE_SIZE] = {
        0xAA, 0xBB, 0xCC, 0xDD,
        0xEE, 0xFF, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33
    };

    vm_init();

    LOG_INF("Calling func 1");
    memcpy((void*)message[0], &uuid0, sizeof(uuid0));
    ipc_notify(0,0);

    k_msleep(500);
    clear_mem();

    LOG_INF("Calling func 2");
    memcpy((void*)message[0], &uuid1, sizeof(uuid1));
    memcpy((void*)message[2], &challenge_1, sizeof(challenge_1));
    memcpy((void*)message[3], &challenge_2, sizeof(challenge_2));
    ipc_notify(0,0);

    k_msleep(500);
    clear_mem();

    LOG_INF("Calling func 3");
    memcpy((void*)message[0], &uuid2, sizeof(uuid2));
    memcpy((void*)message[2], &challenge_1, sizeof(challenge_1));
    memcpy((void*)message[3], &challenge_2, sizeof(challenge_2));
    memcpy((void*)message[4], &nonce, sizeof(nonce));
    ipc_notify(0,0);

    // Wait for interrupts and handle them according to function_table
    while(1);
}
