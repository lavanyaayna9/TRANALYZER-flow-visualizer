cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

set(_plugin_name telegram)

project(${_plugin_name}
    HOMEPAGE_URL "https://tranalyzer.com"
    VERSION      0.9.3
    LANGUAGES    C
)

if (NOT APPLE)
    find_package(OpenSSL REQUIRED)
else()
    find_package(OpenSSL QUIET)
    if (NOT OPENSSL_FOUND)
        # For some reasons the linker uses the wrong libraries with find_package()...
        #set(OPENSSL_ROOT_DIR /usr/local/Cellar/openssl@1.1/1.1.1g)
        #find_package(OpenSSL REQUIRED)
        # Use pkg_check_modules() instead!
        set(ENV{PKG_CONFIG_PATH} "/usr/local/opt/openssl@1.1/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(OPENSSL REQUIRED openssl)
        set(OPENSSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIRS})
        set(OPENSSL_LIBRARIES ${OPENSSL_LDFLAGS})
    endif()
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
        ../basicFlow/src
        ${OPENSSL_INCLUDE_DIR}
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
        ${OPENSSL_LIBRARIES}
)

set_target_properties(${_plugin_name}
    PROPERTIES
        SUFFIX ".so"
)
