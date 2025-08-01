project('centrality', 'c',
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

os = host_machine.system()

pwd = meson.current_source_dir()
header_file = join_paths(pwd, 'src', plugin_name + '.h')
add_project_arguments('-DPLUGIN_SRCH="' + header_file + '"', language: 'c')

if os == 'darwin'
    add_project_arguments('-D_DARWIN_C_SOURCE', language: 'c')
elif os == 'linux'
    add_project_arguments('-D_GNU_SOURCE', language: 'c')
endif

inc = include_directories(
    'src',  # required for src/csparse/*.c to find src/cs.h
    join_paths('..', '..', 'utils'),
    join_paths('..', '..', 'tranalyzer2', 'src'),
)

src = [
    join_paths('src', plugin_name + '.c'),
    join_paths('src', 'csparse', 'cs_add.c'),
    join_paths('src', 'csparse', 'cs_compress.c'),
    join_paths('src', 'csparse', 'cs_cumsum.c'),
    join_paths('src', 'csparse', 'cs_entry.c'),
    join_paths('src', 'csparse', 'cs_malloc.c'),
    join_paths('src', 'csparse', 'cs_multiply.c'),
    join_paths('src', 'csparse', 'cs_norm.c'),
    join_paths('src', 'csparse', 'cs_print.c'),
    join_paths('src', 'csparse', 'cs_scatter.c'),
    join_paths('src', 'csparse', 'cs_util.c'),
]

shared_module(plugin_name,
    sources: src,
    include_directories: inc,
    name_suffix: 'so',
)
