cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

set(_plugin_name gsmDecode)

project(${_plugin_name}
    HOMEPAGE_URL "https://tranalyzer.com"
    VERSION      0.9.3
    LANGUAGES    C
)

# ---------------------------------------------------------------------------- #
# Find libraries                                                               #
# ---------------------------------------------------------------------------- #

#find_package(PkgConfig REQUIRED)
#pkg_check_modules(LIBOSMOGSM REQUIRED libosmogsm)

# ---------------------------------------------------------------------------- #
# Source files                                                                 #
# ---------------------------------------------------------------------------- #

add_library(${_plugin_name}
    MODULE
        src/${_plugin_name}.c
        src/e164_list.c
        src/gsm_a_rp.c
        src/gsm_a_dtap.c
        src/gsm_amr.c
        src/gsm_lapd.c
        src/gsm_lapdm.c
        src/gsm_osmocore.c
        src/gsm_rsl.c
        src/gsm_sms.c
        src/gsm_utils.c
        src/gsmtap.c
        src/mcc_list.c
        src/tac_list.c
        ../../utils/t2buf.c
)

# ---------------------------------------------------------------------------- #
# C standard to use                                                            #
# ---------------------------------------------------------------------------- #

set_target_properties(${_plugin_name}
    PROPERTIES
        C_STANDARD          99
        C_EXTENSIONS        ON
        C_STANDARD_REQUIRED ON
)

# ---------------------------------------------------------------------------- #
# Include directories (-I ...)                                                 #
# ---------------------------------------------------------------------------- #

target_include_directories(${_plugin_name}
    PRIVATE
        ../../utils
        ../../tranalyzer2/src
        ${LIBOSMOGSM_INCLUDE_DIRS}
)

# ---------------------------------------------------------------------------- #
# Compile options                                                              #
# ---------------------------------------------------------------------------- #

target_compile_options(${_plugin_name}
    PRIVATE
        -Wall
        -Wextra
        -Wundef
        -Wno-unused-but-set-variable
        -Wno-unused-const-variable
        -Wno-unused-variable
)

# ---------------------------------------------------------------------------- #
# Compile definitions (-D ...)                                                 #
# ---------------------------------------------------------------------------- #

set(_pwd "${CMAKE_CURRENT_SOURCE_DIR}")
cmake_path(APPEND _header_file "${_pwd}" "src" "${_plugin_name}.h")

target_compile_definitions(${_plugin_name}
    PRIVATE
        PLUGIN_SRCH="${_header_file}"
)

if (APPLE)
    target_compile_definitions(${_plugin_name}
        PRIVATE
            _DARWIN_C_SOURCE
    )
    set_target_properties(${_plugin_name}
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
elseif (UNIX)
    target_compile_definitions(${_plugin_name}
        PRIVATE
            _GNU_SOURCE
    )
endif()

# ---------------------------------------------------------------------------- #
# Libraries (-l ..., -L)                                                       #
# ---------------------------------------------------------------------------- #

target_link_libraries(${_plugin_name}
    PRIVATE
        ${LIBOSMOGSM_LDFLAGS}
)

# ---------------------------------------------------------------------------- #
# Installation                                                                 #
# ---------------------------------------------------------------------------- #

set_target_properties(${_plugin_name}
    PROPERTIES
        OUTPUT_NAME "${_plugin_name}"
        SUFFIX      ".so"
)
