# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(enrollment_app)

target_sources(app PRIVATE src/main.c
                           )

include_directories(src/
                    )

# Include the fsl_puf driver in HAL_NXP
set(PUF_path $ENV{ZEPHYR_BASE}/../modules/hal/nxp/mcux/mcux-sdk/drivers/puf)
zephyr_sources(${PUF_path}/fsl_puf.c)
zephyr_include_directories(${PUF_path})
