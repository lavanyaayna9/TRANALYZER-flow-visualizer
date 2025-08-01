cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

set(_plugin_name mongoSink)

project(${_plugin_name}
    HOMEPAGE_URL "https://tranalyzer.com"
    VERSION      0.9.3
    LANGUAGES    C
)

find_package(mongoc-1.0 QUIET)
if (mongoc-1.0_FOUND)
    set(MONGOC_LDFLAGS mongo::mongoc_shared)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(MONGOC REQUIRED libmongoc-1.0)
endif()

add_library(${_plugin_name}
    MODULE
        src/${_plugin_name}.c
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
        ${MONGOC_INCLUDE_DIRS}
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
        ${MONGOC_LDFLAGS}
)

set_target_properties(${_plugin_name}
    PROPERTIES
        SUFFIX ".so"
)
