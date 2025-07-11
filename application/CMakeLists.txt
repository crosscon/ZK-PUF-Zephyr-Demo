# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(puf_vm)

target_sources(app PRIVATE src/main.c
                           src/puf/lpc55s69/puf_handler.c
                           src/puf/puf_prover.c
                           src/crosscon_hv/crosscon_hv_config.c
                           src/crosscon_hv/hv_functions.c
                           src/crypto/mbedtls/crypto_handler.c
                           )

include_directories(src/
                    src/crosscon_hv/
                    src/crosscon_hv/crosscon_hv_tee/
                    src/puf
                    src/puf/lpc55s69
                    src/crypto
                    )

# Include the fsl_puf driver in HAL_NXP
set(PUF_path $ENV{ZEPHYR_BASE}/../modules/hal/nxp/mcux/mcux-sdk/drivers/puf)
zephyr_sources(${PUF_path}/fsl_puf.c)
zephyr_include_directories(${PUF_path})

zephyr_linker_sources(SECTIONS src/puf/lpc55s69/linker_puf_sections.ld)
