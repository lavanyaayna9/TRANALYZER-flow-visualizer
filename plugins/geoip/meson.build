project('geoip', 'c',
    version: '0.9.3',
    license: 'GPLv2+',
    default_options: [
        'warning_level=2',
        'buildtype=release',
        'c_std=gnu99'
    ],
    #meson_version: '>= 0.45.0',
)

plugin_name = meson.project_name()

cc = meson.get_compiler('c')
os = host_machine.system()
perl = find_program('perl')

pwd = meson.current_source_dir()
header_file = join_paths(pwd, 'src', plugin_name + '.h')
add_project_arguments('-DPLUGIN_SRCH="' + header_file + '"', language: 'c')

if os == 'darwin'
    add_project_arguments('-D_DARWIN_C_SOURCE', language: 'c')
elif os == 'linux'
    add_project_arguments('-D_GNU_SOURCE', language: 'c')
endif

deps = []

inc = include_directories(
    join_paths('..', '..', 'utils'),
    join_paths('..', '..', 'tranalyzer2', 'src'),
)

src = [
    join_paths('src', plugin_name + '.c'),
]

cmd = run_command(perl, '-nle', 'print $1 if /^#define\s+GEOIP_LIB\s+(\d+).*$/', 'src/' + plugin_name + '.h', check: true)
geoip_lib = cmd.stdout().strip()
if geoip_lib == '2'
    geoip_lib_status = 'GeoLite2 / Internal libmaxminddb'
elif geoip_lib == '1'
    geoip_lib_status = 'GeoLite2 / libmaxminddb'
elif geoip_lib == '0'
    geoip_lib_status = 'GeoLite / geoip (legacy)'
else
    err = cmd.stderr().strip()
    if err != ''
        err = ': ' + err
    endif
    error('Could not determine value of \'GEOIP_LIB\' in \'src/' + plugin_name + '.h\'' + err)
endif

message('Using ' + geoip_lib_status + ' library')
if geoip_lib == '2'
    message('Building internal MaxMind DB library...')
    cmd = run_command('sh', '-c', 'cd src/MMDB && autoreconf -fi && ./configure && make', check: false)
    if cmd.returncode() != 0
        err = cmd.stderr().strip()
        if err != ''
            err = ': ' + err
        endif
        error('Failed to build internal MaxMind DB library' + err)
    endif
    libmaxminddb_dir = join_paths(meson.current_source_dir(), 'src', 'MMDB', '.libs')
    deps += cc.find_library('maxminddb', dirs: libmaxminddb_dir)
elif geoip_lib == '1'
    deps += dependency('libmaxminddb')
else
    deps += dependency('geoip')
endif

shared_module(plugin_name,
    sources: src,
    dependencies: deps,
    include_directories: inc,
    name_suffix: 'so',
)
