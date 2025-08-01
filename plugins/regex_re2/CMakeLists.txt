cmake_minimum_required(VERSION 3.5.0 FATAL_ERROR)

set(_plugin_name regex_re2)

project(${_plugin_name}
    HOMEPAGE_URL "https://tranalyzer.com"
    VERSION      0.9.3
    LANGUAGES    C
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBRE2 re2)

add_library(${_plugin_name}
    MODULE
        src/${_plugin_name}.c
        src/murmur.c
)

set_target_properties(${_plugin_name}
    PROPERTIES
        C_STANDARD          99
        C_EXTENSIONS        ON
        C_STANDARD_REQUIRED ON
)

target_include_directories(${_plugin_name}
    PRIVATE
        ../../utils
        ../../tranalyzer2/src
        src/cre2/src
)

target_compile_options(${_plugin_name}
    PRIVATE
        -Wall
        -Wextra
        -Wundef
)

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

target_link_libraries(${_plugin_name}
    PRIVATE
        ${LIBRE2_LDFLAGS}
        ${CMAKE_SOURCE_DIR}/src/cre2/build/.libs/libcre2.a
)

set_target_properties(${_plugin_name}
    PROPERTIES
        SUFFIX ".so"
)
