project('kafkaSink', 'c',
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
#plugin_number = '999'

cc = meson.get_compiler('c')
os = host_machine.system()
#perl = find_program('perl')

pwd = meson.current_source_dir()
header_file = join_paths(pwd, 'src', plugin_name + '.h')
add_project_arguments('-DPLUGIN_SRCH="' + header_file + '"', language: 'c')

if os == 'darwin'
    add_project_arguments('-D_DARWIN_C_SOURCE', language: 'c')
elif os == 'linux'
    add_project_arguments('-D_GNU_SOURCE', language: 'c')
#elif os == 'windows'
#    message('You are using Windows...')
#else
#    warning('OS not recognized...')
endif

rdkafka_dep = dependency('rdkafka')

deps = [
    rdkafka_dep
]

inc = include_directories(
    join_paths('..', '..', 'utils'),
    join_paths('..', '..', 'tranalyzer2', 'src'),
    #join_paths('..', 'tcpFlags', 'src'),   # tell the compiler where to find header
                                            # files from dependent plugins
)

#subdir('doc')

src = [
    join_paths('src', plugin_name + '.c'),
    join_paths('..', '..', 'utils', 'bin2txt.c'),
]

#cmd = run_command(perl, '-nle', 'print $1 if /^#define\s+KAFKASINK_VAR1\s+(\d+).*$/', 'src/' + plugin_name + '.h', check: true)
#var1 = cmd.stdout().strip()
#if var1 == '1'
#    var1_status = 'yes'
#elif var1 == '0'
#    var1_status = 'no'
#else
#    err = cmd.stderr().strip()
#    if err != ''
#        err = ': ' + err
#    endif
#    error('Could not determine value of \'KAFKASINK_VAR1\' in \'src/' + plugin_name + '.h\'' + err)
#endif
#message('Checking whether to activate var1: ' + var1_status)

# We don't need b2t_funcs_gz in this plugin.
add_project_arguments('-DUSE_ZLIB=0', language: 'c')

shared_module(plugin_name,
    sources: src,
    dependencies: deps,
    include_directories: inc,
    #name_prefix: plugin_number + '_',
    name_suffix: 'so',
)
