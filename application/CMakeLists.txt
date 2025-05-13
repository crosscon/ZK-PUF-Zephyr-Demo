# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(hello_world)

target_sources(app PRIVATE src/main.c src/puf_prover.c src/flash_handler.c src/utils.c src/bao_config.c src/config_data.c)

include_directories(src/tee_mockcore/)

# Include the fsl_puf driver in HAL_NXP
set(PUF_path $ENV{ZEPHYR_BASE}/../modules/hal/nxp/mcux/mcux-sdk/drivers/puf)
zephyr_sources(${PUF_path}/fsl_puf.c)
zephyr_include_directories(${PUF_path})

zephyr_include_directories(${ZEPHYR_BASE}/../modules/crypto/mbedtls/include)
