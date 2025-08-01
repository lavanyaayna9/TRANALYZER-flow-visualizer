project('jsonSink', 'c',
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
    join_paths('..', '..', 'utils', 'bin2txt.c'),
]

cmd = run_command(perl, '-nle', 'print $1 if /^#define\s+JSON_GZ_COMPRESS\s+(\d+).*$/', 'src/' + plugin_name + '.h', check: true)
gz_compress = cmd.stdout().strip()
if gz_compress == '1'
    gz_compress_status = 'yes'
elif gz_compress == '0'
    gz_compress_status = 'no'
else
    err = cmd.stderr().strip()
    if err != ''
        err = ': ' + err
    endif
    error('Could not determine value of \'JSON_GZ_COMPRESS\' in \'src/' + plugin_name + '.h\'' + err)
endif
message('Checking whether to activate gzip compression: ' + gz_compress_status)

add_project_arguments('-DUSE_ZLIB=' + gz_compress, language: 'c')
if gz_compress == '1'
    zlib_dep = dependency('zlib', version: '>=1.2.8')
    deps += zlib_dep
    src += join_paths('..', '..', 'utils', 'gz2txt.c')
endif

shared_module(plugin_name,
    sources: src,
    dependencies: deps,
    include_directories: inc,
    name_suffix: 'so',
)
