project('nDPI', 'c',
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

pwd = meson.current_source_dir()
header_file = join_paths(pwd, 'src', plugin_name + '.h')
add_project_arguments('-DPLUGIN_SRCH="' + header_file + '"', language: 'c')

if os == 'darwin'
    add_project_arguments('-D_DARWIN_C_SOURCE', language: 'c')
elif os == 'linux'
    add_project_arguments('-D_GNU_SOURCE', language: 'c')
endif

if meson.version().version_compare('< 0.49')
    libgcrypt = cc.find_library('gcrypt')
else
    libgcrypt = dependency('libgcrypt')
endif

deps = [libgcrypt]

inc = include_directories(
    join_paths('..', '..', 'utils'),
    join_paths('..', '..', 'tranalyzer2', 'src'),
    join_paths('src', 'nDPI', 'src', 'include'),
)

src = [
    join_paths('src', plugin_name + '.c'),
]

message('Building internal nDPI library...')
add_project_arguments('-DNDPI_LIB_COMPILATION', language: 'c')
cmd = run_command('sh', '-c', 'cd src/nDPI && autoreconf -fi && CFLAGS="-DNDPI_LIB_COMPILATION" ./configure --with-only-libndpi && make', check: false)
if cmd.returncode() != 0
    err = cmd.stderr().strip()
    if err != ''
        err = ': ' + err
    endif
    error('Failed to build internal nDPI library' + err)
endif
libnDPI_dir = join_paths(meson.current_source_dir(), 'src', 'nDPI', 'src', 'lib', '.libs')
deps += cc.find_library('ndpi', dirs: libnDPI_dir)

shared_module(plugin_name,
    sources: src,
    dependencies: deps,
    include_directories: inc,
    name_suffix: 'so',
)
