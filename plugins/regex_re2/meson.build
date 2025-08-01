project('regex_re2', 'c',
    version: '0.9.3',
    license: 'GPLv2+',
    default_options: [
        'warning_level=2',
        'buildtype=release',
        'c_std=gnu99'
    ],
    meson_version: '>= 0.51.0',
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

re2_dep = dependency('re2')

# C wrapper for re2
libcre2_dir = join_paths(meson.current_source_dir(), 'src', 'cre2', 'build', '.libs')
libcre2 = cc.find_library('cre2', dirs: libcre2_dir, static: true)

deps = [
    libcre2,
    re2_dep.partial_dependency(link_args: true),
]

inc = include_directories(
    join_paths('..', '..', 'utils'),
    join_paths('..', '..', 'tranalyzer2', 'src'),
    join_paths('src', 'cre2', 'src'),
)

src = [
    join_paths('src', plugin_name + '.c'),
    join_paths('src', 'murmur.c'),
]

shared_module(plugin_name,
    sources: src,
    dependencies: deps,
    include_directories: inc,
    name_suffix: 'so',
)
