# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../oeext.edl host gen)

add_executable(oeext_host host.c ${gen})

target_include_directories(oeext_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oeext_host oehostapp)
