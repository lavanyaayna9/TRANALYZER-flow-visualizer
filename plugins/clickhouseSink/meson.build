project('clickhouseSink', 'cpp',
    version: '0.9.3',
    license: 'GPLv2+',
    default_options: [
        'warning_level=2',
        'buildtype=release',
        'cpp_std=c++17'
    ],
    #meson_version: '>= 0.45.0',
)

plugin_name = meson.project_name()

cc = meson.get_compiler('cpp')
os = host_machine.system()

pwd = meson.current_source_dir()
header_file = join_paths(pwd, 'src', plugin_name + '.hpp')
add_project_arguments('-DPLUGIN_SRCH="' + header_file + '"', language: 'cpp')

if os == 'darwin'
    add_project_arguments('-D_DARWIN_C_SOURCE', language: 'cpp')
elif os == 'linux'
    add_project_arguments('-D_GNU_SOURCE', language: 'cpp')
endif

libclickhouse = cc.find_library('clickhouse-cpp-lib')

deps = [
    libclickhouse,
]

inc = include_directories(
    join_paths('..', '..', 'utils'),
    join_paths('..', '..', 'tranalyzer2', 'src'),
)

src = [
    join_paths('src', plugin_name + '.cpp'),
]

shared_module(plugin_name,
    sources: src,
    dependencies: deps,
    include_directories: inc,
    name_suffix: 'so',
)
