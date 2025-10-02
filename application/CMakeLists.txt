# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(guest_vm)

target_sources(app PRIVATE src/main.c
                           src/crosscon_hv/crosscon_hv_config.c
                           src/crosscon_hv/crosscon_hv_tee/crosscon_hv_tee.c
                           src/commands/helpers.c
                           src/commands/ta_init.c
                           src/commands/ta_commit.c
                           src/commands/ta_zk_get_proofs.c
                           )

include_directories(src/
                    src/crosscon_hv/
                    src/crosscon_hv/crosscon_hv_tee/
                    src/commands
                    )
