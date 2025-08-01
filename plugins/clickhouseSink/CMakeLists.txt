cmake_minimum_required(VERSION 3.8.0 FATAL_ERROR)

set(_plugin_name clickhouseSink)

project(${_plugin_name}
    HOMEPAGE_URL "https://tranalyzer.com"
    VERSION      0.9.3
    LANGUAGES    CXX
)

# ---------------------------------------------------------------------------- #
# Find libraries                                                               #
# ---------------------------------------------------------------------------- #

# See Libraries section below

# ---------------------------------------------------------------------------- #
# Source files                                                                 #
# ---------------------------------------------------------------------------- #

add_library(${_plugin_name}
    MODULE
        src/${_plugin_name}.cpp
)
# ---------------------------------------------------------------------------- #
# C++ standard to use                                                          #
# ---------------------------------------------------------------------------- #

set_target_properties(${_plugin_name}
    PROPERTIES
        CXX_STANDARD 17
)

# ---------------------------------------------------------------------------- #
# Include directories (-I ...)                                                 #
# ---------------------------------------------------------------------------- #

target_include_directories(${_plugin_name}
    PRIVATE
        ../../utils
        ../../tranalyzer2/src
)

# ---------------------------------------------------------------------------- #
# Compile options                                                              #
# ---------------------------------------------------------------------------- #

target_compile_options(${_plugin_name}
    PRIVATE
        -Wall
        -Wextra
        -Wundef
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
        clickhouse-cpp-lib
)

# ---------------------------------------------------------------------------- #
# Installation                                                                 #
# ---------------------------------------------------------------------------- #

set_target_properties(${_plugin_name}
    PROPERTIES
        OUTPUT_NAME "${_plugin_name}"
        SUFFIX      ".so"
)
