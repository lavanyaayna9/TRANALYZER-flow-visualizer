project('tranalyzer', 'c',
    version: '0.9.3',
    license: 'GPLv2+',
    default_options: [
        'warning_level=2',
        'buildtype=release',
        'c_std=gnu99'
    ],
    #meson_version: '>= 0.45.0',
)

exec_name = meson.project_name()

cc = meson.get_compiler('c')
os = host_machine.system()
perl = find_program('perl')

libm        = cc.find_library('m')
libdl       = cc.find_library('dl')
threads_dep = dependency('threads')
zlib_dep    = dependency('zlib', version : '>= 1.2.8', required: false)

if meson.version().version_compare('>= 0.42')
    pcap_dep = dependency('pcap')
else
    pcap_dep = cc.find_library('pcap')
endif

deps = [
    libm,
    libdl,
    pcap_dep,
    threads_dep,
    zlib_dep,
]

cmd = run_command(perl, '-nle', 'print $1 if /^#define\s+DPDK_MP\s+(\d+).*$/', 'src/main.h', check: true)
dpdk_lib = cmd.stdout().strip()
if dpdk_lib != '0'
    message('Building Tranalyzer with DPDK support...')
    deps += dependency('libdpdk')
endif

if os == 'darwin'
    add_project_arguments('-D_DARWIN_C_SOURCE', language: 'c')
elif os == 'linux'
    add_project_arguments('-D_GNU_SOURCE', language: 'c')
endif

inc = include_directories(
    join_paths('src'),
    join_paths('..', 'utils'),
)

src = [
    join_paths('src', 'binaryValue.c'),
    join_paths('src', 'flow.c'),
    join_paths('src', 'hashTable.c'),
    join_paths('src', 'hdrDesc.c'),
    join_paths('src', 'ioBuffer.c'),
    join_paths('src', 'loadPlugins.c'),
    join_paths('src', 'main.c'),
    join_paths('src', 'outputBuffer.c'),
    join_paths('src', 'packetCapture.c'),

    join_paths('src', 'proto', 'ethertype.c'),
    join_paths('src', 'proto', 'ieee80211.c'),
    join_paths('src', 'proto', 'l2tp.c'),
    join_paths('src', 'proto', 'linktype.c'),
    join_paths('src', 'proto', 'vlan.c'),

    join_paths('..', 'utils', 'fsutils.c'),
    join_paths('..', 'utils', 'memdebug.c'),
    join_paths('..', 'utils', 'subnetHL4.c'),
    join_paths('..', 'utils', 'subnetHL6.c'),
    join_paths('..', 'utils', 't2log.c'),
    join_paths('..', 'utils', 't2utils.c'),

    join_paths('..', 'utils', 'missing', 'bsdstring.c'),
]

if os == 'darwin'
    src += join_paths('..', 'utils', 'missing', 'memrchr.c')
endif

# Only load requested dissectors
flags = [
    'ETH_ACTIVATE',
    'IPV6_ACTIVATE',
    'LAPD_ACTIVATE',
    'SCTP_ACTIVATE',
]

foreach f : flags
    # Check the value of the flag
    cmd = run_command(perl, '-nle', 'print $1 if /^#define\s+' + f + '\s+(\d+).*$/', 'src/networkHeaders.h', check: true)
    val = cmd.stdout().strip()
    if val == '0' or val == '1' or val == '2' or val == '3'
      message('Checking value for ' + f + ': ' + val)
    else
        err = cmd.stderr().strip()
        if err != ''
            err = ': ' + err
        endif
        error('Could not determine value of \'' + f + '\' in \'src/networkHeaders.h\'' + err)
    endif
endforeach

# Only load requested dissectors
proto = [
    'ayiya',
    'capwap',
    'geneve',
    'gtp',
    #'l2tp',  # t2_is_l2tp() is also used when L2TP=0
    'lwapp',
    'teredo',
    'vxlan',
]

foreach p : proto
    # Check the value of the flag
    cmd = run_command(perl, '-nle', 'print $1 if /^#define\s+' + p.to_upper() + '\s+(\d+).*$/', 'src/tranalyzer.h', check: true)
    val = cmd.stdout().strip()
    if val == '1'
        src += join_paths('src', 'proto', p + '.c')
        status = 'yes'
    elif val == '0'
        status = 'no'
    else
        err = cmd.stderr().strip()
        if err != ''
            err = ': ' + err
        endif
        error('Could not determine value of \'' + p.to_upper() + '\' in \'src/tranalyzer.h\'' + err)
    endif
    message('Checking whether to activate ' + p.to_upper() + ': ' + status)
endforeach

# Only load requested hash function
cmd = run_command(perl, '-nle', 'print $1 if /^#define\s+T2_HASH_FUNC\s+(\d+).*$/', 'src/hashTable.h', check: true)
hash_func = cmd.stdout().strip()
if hash_func == '0'
    hash_func_str = 'standard'
elif hash_func == '1'
    hash_func_str = 'Murmur3 32-bits'
    src += join_paths('src', 'hash', 'murmur3.c')
elif hash_func == '2'
    hash_func_str = 'Murmur3 128-bits (truncated to 64-bits)'
    src += join_paths('src', 'hash', 'murmur3.c')
elif hash_func == '3' or hash_func == '4'
    hash_func_str = 'xxHash ' + ((hash_func == '3') ? '32' : '64') + '-bits'
    src += join_paths('src', 'hash', 'xxhash.c')
elif hash_func == '5' or hash_func == '6'
    hash_func_str = 'XXH3 ' + ((hash_func == '5') ? '64-bits' : '128-bits (truncated to lower 64-bits)')
    src += join_paths('src', 'hash', 'xxhash.c')
elif hash_func == '7'
    hash_func_str = 'CityHash64'
    src += join_paths('src', 'hash', 'city.c')
elif hash_func == '8'
    hash_func_str = 'MUM-hash version 3 64-bits'
elif hash_func == '9'
    hash_func_str = 'hashlittle 32-bits'
    src += join_paths('src', 'hash', 'hashlittle.c')
elif hash_func == '10'
    hash_func_str = 'wyhash 64-bits'
elif hash_func == '11' or hash_func == '12'
    hash_func_str = 'FastHash' + ((hash_func == '9') ? '32' : '64')
    src += join_paths('src', 'hash', 'fasthash.c')
elif hash_func == '13' or hash_func == '14'
    hash_func_str = 't1ha' + ((hash_func == '11') ? '0' : '2')
    t1ha_dir = join_paths(meson.current_source_dir(), 'src', 'hash', 't1ha')
    deps += cc.find_library('t1ha', static: true, dirs: t1ha_dir, required: true)
else
  error('Unknown value ' + hash_func + ' for T2_HASH_FUNC')
endif
message('Checking which hash function to activate: ' + hash_func_str)

cmd = run_command(perl, '-nle', 'print $1 if /^#define\s+VERBOSE\s+(\d+).*$/', 'src/tranalyzer.h', check: true)
message('Verbose level: ' + cmd.stdout().strip())

if meson.version().version_compare('< 0.45')
    # fallback for export_dynamic in executable()
    add_project_link_arguments('-Wl,--export-dynamic', language: 'c')
endif

executable(exec_name,
    sources: src,
    dependencies: deps,
    include_directories: inc,
    export_dynamic: true,
    install: true,
)
