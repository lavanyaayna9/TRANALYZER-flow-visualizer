cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

set(_exec_name tranalyzer)

project(Tranalyzer2
    HOMEPAGE_URL "https://tranalyzer.com"
    VERSION      0.9.3
    LANGUAGES    C
)

set(_sources
    src/binaryValue.c
    src/flow.c
    src/hashTable.c
    src/hdrDesc.c
    src/ioBuffer.c
    src/loadPlugins.c
    src/main.c
    src/outputBuffer.c
    src/packetCapture.c

    src/hash/city.c
    src/hash/fasthash.c
    src/hash/hashlittle.c
    src/hash/murmur3.c
    src/hash/xxhash.c

    src/proto/ayiya.c
    src/proto/capwap.c
    src/proto/ethertype.c
    src/proto/geneve.c
    src/proto/gtp.c
    src/proto/ieee80211.c
    src/proto/l2tp.c
    src/proto/linktype.c
    src/proto/lwapp.c
    src/proto/teredo.c
    src/proto/vlan.c
    src/proto/vxlan.c

    ../utils/fsutils.c
    ../utils/memdebug.c
    ../utils/subnetHL4.c
    ../utils/subnetHL6.c
    ../utils/t2log.c
    ../utils/t2utils.c

    ../utils/missing/bsdstring.c
)

if (APPLE)
    list(APPEND _sources ../utils/missing/memrchr.c)
endif()

add_executable(${_exec_name} ${_sources})

set_target_properties(${_exec_name}
    PROPERTIES
        C_STANDARD          99
        C_EXTENSIONS        ON
        C_STANDARD_REQUIRED ON
)

#find_package(PCAP REQUIRED)
find_package(Threads REQUIRED)

target_include_directories(${_exec_name}
    PRIVATE
        src
        #${PCAP_INCLUDE_DIR}
        ../utils
)

target_compile_options(${_exec_name}
    PRIVATE
        -Wall
        -Wextra
        -Wundef
)

if (APPLE)
    target_compile_definitions(${_exec_name}
        PRIVATE
            _DARWIN_C_SOURCE
    )
elseif (UNIX)
    target_compile_definitions(${_exec_name}
        PRIVATE
            _GNU_SOURCE
    )
endif()

target_link_libraries(${_exec_name}
    PRIVATE
        dl
        m
        pcap
        #${PCAP_LIBRARY}
        ${CMAKE_THREAD_LIBS_INIT}
)

install(
    TARGETS
        ${_exec_name}
    DESTINATION
        bin
)
