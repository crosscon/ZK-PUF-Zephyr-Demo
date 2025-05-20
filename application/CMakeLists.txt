# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(puf_vm)

target_sources(app PRIVATE src/main.c
                           src/puf_prover.c
                           src/flash_handler.c
                           src/crosscon_hv/crosscon_hv_config.c
                           src/crosscon_hv/hv_functions.c
                           )

include_directories(src/
                    src/crosscon_hv/
                    src/tee_mockcore/
                    )

# Include the fsl_puf driver in HAL_NXP
set(PUF_path $ENV{ZEPHYR_BASE}/../modules/hal/nxp/mcux/mcux-sdk/drivers/puf)
zephyr_sources(${PUF_path}/fsl_puf.c)
zephyr_include_directories(${PUF_path})
