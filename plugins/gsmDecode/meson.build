project('gsmDecode', 'c',
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

add_project_arguments('-Wno-unused-variable', language: 'c')
if os == 'darwin'
    add_project_arguments('-D_DARWIN_C_SOURCE', language: 'c')
elif os == 'linux'
    add_project_arguments('-Wno-unused-but-set-variable', language: 'c')
    add_project_arguments('-D_GNU_SOURCE', language: 'c')
endif

deps = [
    #dependency('libosmogsm')
]

inc = include_directories(
    join_paths('..', '..', 'utils'),
    join_paths('..', '..', 'tranalyzer2', 'src'),
)

src = [
    join_paths('src', plugin_name + '.c'),
    join_paths('src', 'e164_list.c'),
    join_paths('src', 'gsm_a_rp.c'),
    join_paths('src', 'gsm_a_dtap.c'),
    join_paths('src', 'gsm_amr.c'),
    join_paths('src', 'gsm_lapd.c'),
    join_paths('src', 'gsm_lapdm.c'),
    join_paths('src', 'gsm_osmocore.c'),
    join_paths('src', 'gsm_rsl.c'),
    join_paths('src', 'gsm_sms.c'),
    join_paths('src', 'gsm_utils.c'),
    join_paths('src', 'gsmtap.c'),
    join_paths('src', 'mcc_list.c'),
    join_paths('src', 'tac_list.c'),
    join_paths('..', '..', 'utils', 't2buf.c'),
]

shared_module(plugin_name,
    sources: src,
    dependencies: deps,
    include_directories: inc,
    name_suffix: 'so',
)
