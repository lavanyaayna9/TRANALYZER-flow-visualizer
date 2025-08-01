#!/usr/bin/env python3

import os
import socket
import sys

from os import environ
from os.path import dirname, isfile, join, realpath
from subprocess import CalledProcessError, TimeoutExpired

from t2py import T2
from t2py import T2Plugin
from t2py import T2Utils

FATAL: bool = False
ERRORS: int = 0

T2PY_TESTS_HOME = join(dirname(realpath(__file__)))
PLUGIN_FOLDER = join(environ['HOME'], '.tranalyzer', 'plugins')
LOOPBACK = 'lo0' if 'lo0' in [iface[1] for iface in socket.if_nameindex()] else 'lo'


def print_color(msg: str, color: str = 'black'):
    if color == 'blue':
        print_blue(msg)
    elif color == 'red':
        print_red(msg)
    elif color == 'green':
        print_green(msg)
    else:
        print(msg)


def print_red(msg: str):
    print(f'\033[91m{msg}\033[0m')


def print_green(msg: str):
    print(f'\033[92m{msg}\033[0m')


def print_blue(msg: str):
    print(f'\033[94m{msg}\033[0m')


def print_title(msg: str):
    max_width = 80
    if len(msg) <= max_width:
        available = max_width - len(msg) - 6
        num_spaces1 = int(available / 2)
        num_spaces2 = available - num_spaces1
    else:
        num_spaces1 = 0
        num_spaces2 = 0
    header = f"\n# {'-' * (max_width - 4)} #\n"
    fmsg = f"{header}# {' ' * num_spaces1} {msg} {' ' * num_spaces2} #{header}"
    print_blue(fmsg)


def print_test(msg: str, newline: bool = False):
    print(f'{msg}... ', end='\n' if newline else '')


def print_fail():
    global ERRORS
    print_red('FAIL')
    ERRORS += 1
    if FATAL:
        sys.exit(1)


def print_ok():
    print_green('OK')


def t2_test_equal(a, b):
    if a == b:
        print_ok()
    else:
        print_fail()


def t2_test_raise(func, err, *func_args):
    try:
        func(*func_args)
    except err:
        print_ok()
        return
    print_fail()


def t2_test_do_not_raise(func, err, *func_args):
    try:
        func(*func_args)
    except err:
        print_fail()
        return
    print_ok()


def test_t2utils_env():
    print_test("T2Utils.T2HOME == environ['T2HOME']")
    if 'T2HOME' not in environ:
        print_fail()
    else:
        t2_test_equal(T2Utils.T2HOME, environ['T2HOME'])

    print_test("T2Utils.T2PLHOME == environ['T2PLHOME']")
    if 'T2PLHOME' not in environ:
        print_fail()
    else:
        t2_test_equal(T2Utils.T2PLHOME, environ['T2PLHOME'])

    if 'T2HOME' not in environ or 'T2PLHOME' not in environ:
        return

    print_test("T2Utils.T2BUILD == join(environ['T2HOME'], 'autogen.sh')")
    t2_test_equal(T2Utils.T2BUILD, join(environ['T2HOME'], 'autogen.sh'))

    print_test("T2Utils.T2CONF == join(environ['T2HOME'], 'scripts', 't2conf', 't2conf')")
    t2_test_equal(T2Utils.T2CONF, join(environ['T2HOME'], 'scripts', 't2conf', 't2conf'))

    print_test("T2Utils.T2FM == join(environ['T2HOME'], 'scripts', 't2fm', 't2fm')")
    t2_test_equal(T2Utils.T2FM, join(environ['T2HOME'], 'scripts', 't2fm', 't2fm'))

    print_test("T2Utils.T2PLUGIN == join(environ['T2HOME'], 'scripts', 't2plugin')")
    t2_test_equal(T2Utils.T2PLUGIN, join(environ['T2HOME'], 'scripts', 't2plugin'))

    print_test("T2Utils.TAWK == join(environ['T2HOME'], 'scripts', 'tawk', 'tawk')")
    t2_test_equal(T2Utils.TAWK, join(environ['T2HOME'], 'scripts', 'tawk', 'tawk'))

    print_test("T2Utils.t2_exec() == join(environ['T2HOME'], 'tranalyzer2', 'build', 'tranalyzer')")
    t2_test_equal(T2Utils.t2_exec(), join(environ['T2HOME'], 'tranalyzer2', 'build', 'tranalyzer'))

    print_test("T2Utils.t2_exec(debug=True) == join(environ['T2HOME'], 'tranalyzer2', 'debug', 'tranalyzer')")
    t2_test_equal(T2Utils.t2_exec(debug=True), join(environ['T2HOME'], 'tranalyzer2', 'debug', 'tranalyzer'))


def test_t2utils_plugin_description_number():
    print_test("T2Utils.plugin_description('arpDecode') == 'Address Resolution Protocol (ARP)'")
    t2_test_equal(T2Utils.plugin_description('arpDecode'), 'Address Resolution Protocol (ARP)')

    print_test("T2Utils.plugin_description('nonExistingPlugin') raise NameError")
    t2_test_raise(T2Utils.plugin_description, NameError, 'nonExistingPlugin')

    print_test("T2Utils.plugin_number('arpDecode') == '179'")
    t2_test_equal(T2Utils.plugin_number('arpDecode'), '179')

    print_test("T2Utils.plugin_number('nonExistingPlugin') raise NameError")
    t2_test_raise(T2Utils.plugin_number, NameError, 'nonExistingPlugin')

    print_test("type(T2Utils.plugins()) == list")
    t2_test_equal(type(T2Utils.plugins()), list)

    print_test("T2Utils.plugins() == T2Utils._all_plugins")
    t2_test_equal(T2Utils.plugins(), T2Utils._all_plugins)

    print_test("T2Utils.plugins('g') == ['protoStats'])")
    t2_test_equal(T2Utils.plugins('g'), ['protoStats'])

    print_test("T2Utils.plugins(['g', 'b']) == ['basicFlow', 'basicStats', 'connStat', 'macRecorder', 'portClassifier', 'protoStats'])")
    t2_test_equal(T2Utils.plugins(['g', 'b']), ['basicFlow', 'basicStats', 'connStat', 'macRecorder', 'portClassifier', 'protoStats'])


def test_t2utils_list_config():
    print_test("T2Utils.list_config('arpDecode') == ['ARP_MAX_IP']")
    t2_test_equal(T2Utils.list_config('arpDecode'), ['ARP_MAX_IP'])

    print_test("T2Utils.list_config('tcpStates') = []")
    t2_test_equal(T2Utils.list_config('tcpStates'), [])

    print_test("T2Utils.list_config('nonExistingPlugin') raise NameError")
    t2_test_raise(T2Utils.list_config, NameError, 'nonExistingPlugin')


def test_t2utils_get_config():
    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP') == 10")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP'), 10)

    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source') == 10")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source'), 10)

    print_test("T2Utils.get_config_from_source('arpDecode', 'ARP_MAX_IP') == 10")
    t2_test_equal(T2Utils.get_config_from_source('arpDecode', 'ARP_MAX_IP'), 10)

    print_test("T2Utils.get_config('nonExistingPlugin', 'ARP_MAX_IP') raise NameError")
    t2_test_raise(T2Utils.get_config, NameError, 'nonExistingPlugin', 'ARP_MAX_IP')


def test_t2utils_get_default():
    print_test("T2Utils.get_default('arpDecode', 'ARP_MAX_IP') == 10")
    t2_test_equal(T2Utils.get_default('arpDecode', 'ARP_MAX_IP'), 10)

    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='default') == 10")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='default'), 10)


def test_t2utils_set_config():
    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source') == 10")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source'), 10)

    print_test("T2Utils.set_config('arpDecode', 'ARP_MAX_IP', 15, outfile='source')", newline=True)
    T2Utils.set_config('arpDecode', 'ARP_MAX_IP', 15, outfile='source')

    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source') == 15")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source'), 15)

    print_test("T2Utils.set_config('arpDecode', 'ARP_MAX_IP', 10, outfile='source')", newline=True)
    T2Utils.set_config('arpDecode', 'ARP_MAX_IP', 10, outfile='source')

    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source') == 10")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source'), 10)

    print_test("T2Utils.set_config('arpDecode', 'ARP_MAX_IP', 1234, outfile='/tmp/arpDecode.config')", newline=True)
    T2Utils.set_config('arpDecode', 'ARP_MAX_IP', 1234, outfile='/tmp/arpDecode.config')

    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='/tmp/arpDecode.config') == 1234")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='/tmp/arpDecode.config'), 1234)

    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source') == 10")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source'), 10)

    print_test("T2Utils.set_config('nonExistingPlugin', 'ARP_MAX_IP', 10) raise NameError")
    t2_test_raise(T2Utils.set_config, NameError, 'nonExistingPlugin', 'ARP_MAX_IP', 10)


def test_t2utils_set_config_dict():
    print_test("T2Utils.set_config('basicStats', {'BS_VAR': 'yes', 'BS_STDDEV': 0})", newline=True)
    T2Utils.set_config('basicStats', {'BS_VAR': 'yes', 'BS_STDDEV': 0})

    print_test("T2Utils.get_config('basicStats', 'BS_VAR') == 1")
    t2_test_equal(T2Utils.get_config('basicStats', 'BS_VAR'), 1)

    print_test("T2Utils.get_config('basicStats', 'BS_STDDEV') == 0")
    t2_test_equal(T2Utils.get_config('basicStats', 'BS_STDDEV'), 0)

    print_test("T2Utils.set_config('basicStats', {'BS_VAR': 'no', 'BS_STDDEV': 1})", newline=True)
    T2Utils.set_config('basicStats', {'BS_VAR': 'no', 'BS_STDDEV': 1})

    print_test("T2Utils.get_config('basicStats', 'BS_VAR') == 0")
    t2_test_equal(T2Utils.get_config('basicStats', 'BS_VAR'), 0)

    print_test("T2Utils.get_config('basicStats', 'BS_STDDEV') == 1")
    t2_test_equal(T2Utils.get_config('basicStats', 'BS_STDDEV'), 1)


def test_t2utils_set_config_str():
    print_test("T2Utils.set_config('ftpDecode', 'FTP_NONAME', 'wurst')", newline=True)
    T2Utils.set_config('ftpDecode', 'FTP_NONAME', 'wurst')

    print_test("T2Utils.get_config('ftpDecode', 'FTP_NONAME') == 'wurst'")
    t2_test_equal(T2Utils.get_config('ftpDecode', 'FTP_NONAME'), 'wurst')

    print_test("T2Utils.set_config('ftpDecode', 'FTP_NONAME', 'nudel')", newline=True)
    T2Utils.set_config('ftpDecode', 'FTP_NONAME', 'nudel')

    print_test("T2Utils.get_config('ftpDecode', 'FTP_NONAME') == 'nudel'")
    t2_test_equal(T2Utils.get_config('ftpDecode', 'FTP_NONAME'), 'nudel')


def test_t2utils_set_default():
    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source') == 10")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source'), 10)

    print_test("T2Utils.set_config('arpDecode', 'ARP_MAX_IP', 15, outfile='source')", newline=True)
    T2Utils.set_config('arpDecode', 'ARP_MAX_IP', 15, outfile='source')

    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source') == 15")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source'), 15)

    print_test("T2Utils.set_default('arpDecode', 'ARP_MAX_IP', outfile='source')", newline=True)
    T2Utils.set_default('arpDecode', 'ARP_MAX_IP', outfile='source')

    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source') == 10")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source'), 10)

    print_test("T2Utils.set_default(['arpDecode', 'basicStats'], 'ARP_MAX_IP') raise NotImplementedError")
    t2_test_raise(T2Utils.set_default, NotImplementedError, ['arpDecode', 'basicStats'], 'ARP_MAX_IP')

    print_test("T2Utils.set_default('all', 'ARP_MAX_IP' raise NotImplementedError")
    t2_test_raise(T2Utils.set_default, NotImplementedError, 'all', 'ARP_MAX_IP')

    print_test("T2Utils.get_config('basicStats', 'BS_VAR') == 0")
    t2_test_equal(T2Utils.get_config('basicStats', 'BS_VAR'), 0)

    print_test("T2Utils.get_config('basicStats', 'BS_STDDEV') == 1")
    t2_test_equal(T2Utils.get_config('basicStats', 'BS_STDDEV'), 1)

    print_test("T2Utils.set_config('basicStats', 'BS_VAR', 1)", newline=True)
    T2Utils.set_config('basicStats', 'BS_VAR', 1)

    print_test("T2Utils.get_config('basicStats', 'BS_STDDEV', 0)", newline=True)
    T2Utils.set_config('basicStats', 'BS_STDDEV', 0)

    print_test("T2Utils.get_config('basicStats', 'BS_VAR') == 1")
    t2_test_equal(T2Utils.get_config('basicStats', 'BS_VAR'), 1)

    print_test("T2Utils.get_config('basicStats', 'BS_STDDEV') == 0")
    t2_test_equal(T2Utils.get_config('basicStats', 'BS_STDDEV'), 0)

    print_test("T2Utils.set_default('basicStats', ['BS_VAR', 'BS_STDDEV'])", newline=True)
    T2Utils.set_default('basicStats', ['BS_VAR', 'BS_STDDEV'])

    print_test("T2Utils.get_config('basicStats', 'BS_VAR') == 0")
    t2_test_equal(T2Utils.get_config('basicStats', 'BS_VAR'), 0)

    print_test("T2Utils.get_config('basicStats', 'BS_STDDEV') == 1")
    t2_test_equal(T2Utils.get_config('basicStats', 'BS_STDDEV'), 1)

    print_test("T2Utils.set_default('all') does not raise Exception")
    t2_test_do_not_raise(T2Utils.set_default, Exception, 'all')

    print_test("T2Utils.set_default(['arpDecode', 'basicStats']) does not raise Exception")
    t2_test_do_not_raise(T2Utils.set_default, Exception, ['arpDecode', 'basicStats'])

    print_test("T2Utils.set_default(['arpDecode', 'basicStats'], outfile='/tmp/plugin.config') raise NotImplementedError")
    t2_test_raise(T2Utils.set_default, NotImplementedError, ['arpDecode', 'basicStats'], None, '/tmp/plugin.config')

    print_test("T2Utils.set_default('arpDecode', outfile='/tmp/arpDecode.config') does not raise Exception")
    t2_test_do_not_raise(T2Utils.set_default, Exception, 'arpDecode', None, '/tmp/arpDecode.config')


def test_t2utils_reset_all():
    print_test("T2Utils.set_config('arpDecode', 'ARP_MAX_IP', 15, outfile='source')", newline=True)
    T2Utils.set_config('arpDecode', 'ARP_MAX_IP', 15, outfile='source')

    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source') == 15")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source'), 15)

    print_test("T2Utils.reset_config('arpDecode', outfile='source')", newline=True)
    T2Utils.reset_config('arpDecode', outfile='source')

    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source') == 10")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source'), 10)


def test_t2utils_reset_one():
    print_test("T2Utils.set_config('arpDecode', 'ARP_MAX_IP', 15, outfile='source')", newline=True)
    T2Utils.set_config('arpDecode', 'ARP_MAX_IP', 15, outfile='source')

    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source') == 15")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source'), 15)

    print_test("T2Utils.reset_config('arpDecode', outfile='source')", newline=True)
    T2Utils.reset_config('arpDecode', 'ARP_MAX_IP', outfile='source')

    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source') == 10")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', infile='source'), 10)


def test_t2utils_generate_config():
    print_test("T2Utils.generate_config('nonExistingPlugin') raise NameError")
    t2_test_raise(T2Utils.generate_config, NameError, 'nonExistingPlugin')

    if isfile('/tmp/testConfig.config'):
        os.remove('/tmp/testConfig.config')

    print_test("T2Utils.generate_config('arpDecode', '/tmp/testConfig.config')", newline=True)
    T2Utils.generate_config('arpDecode', '/tmp/testConfig.config')

    print_test("isfile('/tmp/testConfig.config') == True")
    t2_test_equal(isfile('/tmp/testConfig.config'), True)


def test_t2utils_apply_config():
    print_test("T2Utils.apply_config('nonExistingPlugin') raise NameError")
    t2_test_raise(T2Utils.apply_config, NameError, 'nonExistingPlugin')

    print_test("T2Utils.apply_config('arpDecode') does not raise Exception")
    t2_test_do_not_raise(T2Utils.apply_config, Exception, 'arpDecode')

    print_test("T2Utils.apply_config('arpDecode', T2Utils.T2PLHOME + '/arpDecode/default.config') does not raise Exception")
    t2_test_do_not_raise(T2Utils.apply_config, Exception, 'arpDecode', T2Utils.T2PLHOME + '/arpDecode/default.config')


def test_t2utils_create_plugin_list():
    default_loading_list = join(PLUGIN_FOLDER, 'plugins.load')
    if isfile(default_loading_list):
        os.remove(default_loading_list)

    print_test("T2Utils.create_plugin_list(['arpDecode', 'basicStats'])", newline=True)
    T2Utils.create_plugin_list(['arpDecode', 'basicStats'])

    print_test(f"isfile({default_loading_list}) == True")
    t2_test_equal(isfile(default_loading_list), True)

    print_test("T2Utils.list_plugins() == ['arpDecode', 'basicStats']")
    t2_test_equal(T2Utils.list_plugins(), ['arpDecode', 'basicStats'])


def test_t2utils_list_plugins():
    if isfile('/tmp/plugins.load'):
        os.remove('/tmp/plugins.load')

    print_test("T2Utils.create_plugin_list(['arpDecode', 'basicStats'], outfile='/tmp/plugins.load')", newline=True)
    T2Utils.create_plugin_list(['arpDecode', 'basicStats'], outfile='/tmp/plugins.load')

    print_test("isfile('/tmp/plugins.load') == True")
    t2_test_equal(isfile('/tmp/plugins.load'), True)

    print_test("T2Utils.list_plugins('/tmp/plugins.load') == ['arpDecode', 'basicStats']")
    t2_test_equal(T2Utils.list_plugins('/tmp/plugins.load'), ['arpDecode', 'basicStats'])

    print_test("T2Utils.list_plugins() does not raise Exception")
    t2_test_do_not_raise(T2Utils.list_plugins, Exception)


def test_t2utils_build():
    print_test("T2Utils.build('all') does not raise Exception")
    t2_test_do_not_raise(T2Utils.build, Exception, 'all')

    print_test("T2Utils.build('tranalyzer2') does not raise Exception")
    t2_test_do_not_raise(T2Utils.build, Exception, 'tranalyzer2')

    print_test("T2Utils.build(['tranalyzer2, 'basicFlow']) does not raise Exception")
    t2_test_do_not_raise(T2Utils.build, Exception, ['tranalyzer2', 'basicFlow'])

    print_test(f"T2Utils.build('arpDecode', plugin_folder='{PLUGIN_FOLDER}', force_rebuild=True, debug=True) does not raise Exception")
    t2_test_do_not_raise(T2Utils.build, Exception, 'arpDecode', PLUGIN_FOLDER, True, True)

    print_test("T2Utils.build(['arpDecode', 'basicStats']) does not raise Exception")
    t2_test_do_not_raise(T2Utils.build, Exception, ['arpDecode', 'basicStats'])

    print_test(f"T2Utils.build('arpDecode', plugin_folder='{PLUGIN_FOLDER}') does not raise Exception")
    t2_test_do_not_raise(T2Utils.build, Exception, 'arpDecode', PLUGIN_FOLDER)

    if isfile('/tmp/plugins.load'):
        os.remove('/tmp/plugins.load')

    print_test("T2Utils.create_plugin_list(['arpDecode', 'basicStats'], outfile='/tmp/plugins.load')", newline=True)
    T2Utils.create_plugin_list(['arpDecode', 'basicStats'], outfile='/tmp/plugins.load')

    print_test("isfile('/tmp/plugins.load') == True")
    t2_test_equal(isfile('/tmp/plugins.load'), True)

    print_test("T2Utils.build('/tmp/plugins.load') does not raise Exception")
    t2_test_do_not_raise(T2Utils.build, Exception, '/tmp/plugins.load')


def test_t2utils_clean():
    print_test("T2Utils.clean('all') does not raise Exception")
    t2_test_do_not_raise(T2Utils.clean, Exception, 'all')

    print_test("T2Utils.clean('arpDecode') does not raise Exception")
    t2_test_do_not_raise(T2Utils.clean, Exception, 'arpDecode')

    print_test("T2Utils.clean(['arpDecode', 'basicStats']) does not raise Exception")
    t2_test_do_not_raise(T2Utils.clean, Exception, ['arpDecode', 'basicStats'])

    if isfile('/tmp/plugins.load'):
        os.remove('/tmp/plugins.load')

    print_test("T2Utils.create_plugin_list(['arpDecode', 'basicStats'], outfile='/tmp/plugins.load')", newline=True)
    T2Utils.create_plugin_list(['arpDecode', 'basicStats'], outfile='/tmp/plugins.load')

    print_test("isfile('/tmp/plugins.load') == True")
    t2_test_equal(isfile('/tmp/plugins.load'), True)

    print_test("T2Utils.clean('/tmp/plugins.load') does not raise Exception")
    t2_test_do_not_raise(T2Utils.clean, Exception, '/tmp/plugins.load')


def test_t2utils_unload():
    print_test("T2Utils.unload('all') does not raise Exception")
    t2_test_do_not_raise(T2Utils.unload, Exception, 'all')

    print_test("T2Utils.unload('arpDecode') does not raise Exception")
    t2_test_do_not_raise(T2Utils.unload, Exception, 'arpDecode')

    print_test("T2Utils.unload(['arpDecode', 'basicStats']) does not raise Exception")
    t2_test_do_not_raise(T2Utils.unload, Exception, ['arpDecode', 'basicStats'])

    print_test(f"T2Utils.unload('arpDecode', plugin_folder='{PLUGIN_FOLDER}') does not raise Exception")
    t2_test_do_not_raise(T2Utils.unload, Exception, 'arpDecode', PLUGIN_FOLDER)

    if isfile('/tmp/plugins.load'):
        os.remove('/tmp/plugins.load')

    print_test("T2Utils.create_plugin_list(['arpDecode', 'basicStats'], outfile='/tmp/plugins.load')", newline=True)
    T2Utils.create_plugin_list(['arpDecode', 'basicStats'], outfile='/tmp/plugins.load')

    print_test("isfile('/tmp/plugins.load') == True")
    t2_test_equal(isfile('/tmp/plugins.load'), True)

    print_test("T2Utils.unload('/tmp/plugins.load') does not raise Exception")
    t2_test_do_not_raise(T2Utils.unload, Exception, '/tmp/plugins.load')


def test_t2utils_to_json_array():
    print_test(f"T2Utils.to_json_array('{T2PY_TESTS_HOME}/data/file_flows.json') does not raise Exception")
    t2_test_do_not_raise(T2Utils.to_json_array, Exception, f'{T2PY_TESTS_HOME}/data/file_flows.json')

    print_test(f"T2Utils.to_json_array('{T2PY_TESTS_HOME}/data/file_flows.txt') does not raise Exception")
    t2_test_do_not_raise(T2Utils.to_json_array, Exception, f'{T2PY_TESTS_HOME}/data/file_flows.txt')


def test_t2utils_to_pandas():
    print_test(f"T2Utils.to_pandas('{T2PY_TESTS_HOME}/data/file_flows.json') does not raise Exception")
    t2_test_do_not_raise(T2Utils.to_pandas, Exception, f'{T2PY_TESTS_HOME}/data/file_flows.json')

    print_test(f"T2Utils.to_pandas('{T2PY_TESTS_HOME}/data/file_flows.txt') does not raise Exception")
    t2_test_do_not_raise(T2Utils.to_pandas, Exception, f'{T2PY_TESTS_HOME}/data/file_flows.txt')


def test_t2utils_to_pdf():
    print_test("T2Utils.unload('socketSink')", newline=True)
    T2Utils.unload('socketSink')

    print_test("T2Utils.to_pdf() raise RuntimeError")
    t2_test_raise(T2Utils.to_pdf, RuntimeError)

    print_test("T2Utils.to_pdf(pcap='file.pcap', flow_file='file_flows.txt') raise RuntimeError")
    t2_test_raise(T2Utils.to_pdf, RuntimeError, 'file.pcap', 'file_flows.txt')

    print_test(f"T2Utils.to_pdf(pcap='{T2PY_TESTS_HOME}/data/file.pcap', prefix='/tmp/') does not raise RuntimeError")
    t2_test_do_not_raise(T2Utils.to_pdf, RuntimeError, f'{T2PY_TESTS_HOME}/data/file.pcap', None, '/tmp/')

    print_test(f"T2Utils.to_pdf(flow_file='{T2PY_TESTS_HOME}/data/file_flows.txt', prefix='/tmp/') does not raise RuntimeError")
    t2_test_do_not_raise(T2Utils.to_pdf, RuntimeError, None, f'{T2PY_TESTS_HOME}/data/file_flows.txt', '/tmp/')


def test_t2utils_tawk():
    print_test("T2Utils.tawk(None, 'nonExistingFile.txt') raise RuntimeError")
    t2_test_raise(T2Utils.tawk, RuntimeError, None, 'nonExistingFile.txt')

    print_test("T2Utils.tawk(None, None, ['-V', 'flowStat=0x1234']) does not raise Exception")
    t2_test_do_not_raise(T2Utils.tawk, Exception, None, None, ['-V', 'flowStat=0x1234'])

    print_test(f"len(T2Utils.tawk('aggr(shost())', '{T2PY_TESTS_HOME}/data/file_flows.txt').splitlines()) == 2")
    t2_test_equal(len(T2Utils.tawk('aggr(shost())', f'{T2PY_TESTS_HOME}/data/file_flows.txt').splitlines()), 2)


def test_t2utils_follow_stream():
    print_test("T2Utils.follow_stream(None, 1) raise RuntimeError")
    t2_test_raise(T2Utils.follow_stream, RuntimeError, None, 1)

    print_test(f"T2Utils.follow_stream('{T2PY_TESTS_HOME}/data/file_flows.txt', 1, direction='unknown') raise RuntimeError")
    t2_test_raise(T2Utils.follow_stream, RuntimeError, f'{T2PY_TESTS_HOME}/data/file_flows.txt', 1, 0, 'unknown')

    for output_format in range(3):
        print_test(f"T2Utils.follow_stream('{T2PY_TESTS_HOME}/data/file_flows.txt', 1, output_format={output_format}, payload_format=0) raise CalledProcessError")
        t2_test_raise(T2Utils.follow_stream, CalledProcessError, f'{T2PY_TESTS_HOME}/data/file_flows.txt', 1, output_format, None, 0)

    for output_format in range(3, 5):
        print_test(f"T2Utils.follow_stream('{T2PY_TESTS_HOME}/data/file_flows.txt', 1, output_format={output_format}) raise RuntimeError")
        t2_test_raise(T2Utils.follow_stream, RuntimeError, f'{T2PY_TESTS_HOME}/data/file_flows.txt', 1, output_format)

    for payload_format in range(4):
        print_test(f"T2Utils.follow_stream('{T2PY_TESTS_HOME}/data/file_flows.txt', 1, payload_format={payload_format}) raise CalledProcessError")
        t2_test_raise(T2Utils.follow_stream, CalledProcessError, f'{T2PY_TESTS_HOME}/data/file_flows.txt', 1, 2, None, payload_format)

    print_test(f"T2Utils.follow_stream('{T2PY_TESTS_HOME}/data/file_flows.txt', 1, output_format=1, payload_format=4) raise RuntimeError")
    t2_test_raise(T2Utils.follow_stream, RuntimeError, f'{T2PY_TESTS_HOME}/data/file_flows.txt', 1, 1, None, 4)

    print_test(f"T2Utils.follow_stream('{T2PY_TESTS_HOME}/data/file_flows.txt', 1, payload_format=5) raise RuntimeError")
    t2_test_raise(T2Utils.follow_stream, RuntimeError, f'{T2PY_TESTS_HOME}/data/file_flows.txt', 1, 2, None, 5)

    print_test(f"type(T2Utils.follow_stream('{T2PY_TESTS_HOME}/data/file_packets.txt', 1, output_format=0)) == list")
    t2_test_equal(type(T2Utils.follow_stream(f'{T2PY_TESTS_HOME}/data/file_packets.txt', 1, output_format=0)), list)

    print_test(f"type(T2Utils.follow_stream('{T2PY_TESTS_HOME}/data/file_packets.txt', 1, output_format=2)) == list")
    t2_test_equal(type(T2Utils.follow_stream(f'{T2PY_TESTS_HOME}/data/file_packets.txt', 1, output_format=2)), list)

    print_test(f"type(T2Utils.follow_stream('{T2PY_TESTS_HOME}/data/file_packets.txt', 3, output_format=2)[0]) == dict")
    t2_test_equal(type(T2Utils.follow_stream(f'{T2PY_TESTS_HOME}/data/file_packets.txt', 3, output_format=2)[0]), dict)

    print_test(f"type(T2Utils.follow_stream('{T2PY_TESTS_HOME}/data/file_packets.txt', 3, output_format=0, payload_format=4)[0]) == bytearray")
    t2_test_equal(type(T2Utils.follow_stream(f'{T2PY_TESTS_HOME}/data/file_packets.txt', 3, output_format=0, payload_format=4)[0]), bytearray)

    print_test(f"type(T2Utils.follow_stream('{T2PY_TESTS_HOME}/data/file_packets.txt', 3, output_format=2, payload_format=4)[0]['payload']) == bytearray")
    t2_test_equal(type(T2Utils.follow_stream(f'{T2PY_TESTS_HOME}/data/file_packets.txt', 3, output_format=2, payload_format=4)[0]['payload']), bytearray)

    print_test(f"type(T2Utils.follow_stream('{T2PY_TESTS_HOME}/data/file_packets.txt', 3, output_format=3, payload_format=4, direction='A')) == bytearray")
    t2_test_equal(type(T2Utils.follow_stream(f'{T2PY_TESTS_HOME}/data/file_packets.txt', 3, output_format=3, payload_format=4, direction='A')), bytearray)


def test_t2utils_network_interfaces():
    print_test("type(T2Utils.network_interfaces()) == list")
    t2_test_equal(type(T2Utils.network_interfaces()), list)

    print_test(f"'{LOOPBACK}' in T2Utils.network_interfaces()")
    t2_test_equal(LOOPBACK in T2Utils.network_interfaces(), True)


def test_t2utils_valid_plugin_names():
    print_test("type(T2Utils.valid_plugin_names()) == list")
    t2_test_equal(type(T2Utils.valid_plugin_names()), list)

    print_test("'tranalyzer2' in T2Utils.valid_plugin_names()")
    t2_test_equal('tranalyzer2' in T2Utils.valid_plugin_names(), True)


def test_t2utils_create_pcap_list():
    print_test("T2Utils.create_pcap_list(['file1.pcap', 'file2.pcap']) does not raise Exception")
    t2_test_do_not_raise(T2Utils.create_pcap_list, Exception, ['file1.pcap', 'file2.pcap'])

    print_test("T2Utils.create_pcap_list(['file1.pcap', 'file2.pcap'], outfile='/tmp/myPcaps.txt') does not raise Exception")
    t2_test_do_not_raise(T2Utils.create_pcap_list, Exception, ['file1.pcap', 'file2.pcap'], '/tmp/myPcaps.txt')


def test_t2utils_run_tranalyzer():
    print_test("T2Utils.unload('socketSink')", newline=True)
    T2Utils.unload('socketSink')

    print_test("T2Utils.run_tranalyzer(pcap='file.pcap', pcap_list='pcap_list.txt') raise RuntimeError")
    t2_test_raise(T2Utils.run_tranalyzer, RuntimeError, 'file.pcap', None, 'pcap_list.txt')

    print_test("T2Utils.run_tranalyzer(pcap='file.pcap', iface='eth0') raise RuntimeError")
    t2_test_raise(T2Utils.run_tranalyzer, RuntimeError, 'file.pcap', 'eth0')

    print_test("T2Utils.run_tranalyzer(iface='eth0', pcap_list='pcap_list.txt') raise RuntimeError")
    t2_test_raise(T2Utils.run_tranalyzer, RuntimeError, None, 'eth0', 'pcap_list.txt')

    print_test("T2Utils.run_tranalyzer() raise RuntimeError")
    t2_test_raise(T2Utils.run_tranalyzer, RuntimeError)

    print_test("T2Utils.run_tranalyzer(iface='tranalyzer2') raise OSError")
    t2_test_raise(T2Utils.run_tranalyzer, OSError, None, 'tranalyzer2')

    print_test("T2Utils.run_tranalyzer(t2_exec='/tmp/t2') raise RuntimeError")
    t2_test_raise(T2Utils.run_tranalyzer, RuntimeError, 'file.pcap', None, None, None, False, False, False, None, None, None, None, '/tmp/t2')

    print_test(f"T2Utils.run_tranalyzer(pcap='{T2PY_TESTS_HOME}/data/file.pcap', output_prefix='/tmp/', log_file=True, packet_mode=True, plugin_folder='{PLUGIN_FOLDER}', bpf='tcp') does not raise Exception")
    t2_test_do_not_raise(T2Utils.run_tranalyzer, Exception, f'{T2PY_TESTS_HOME}/data/file.pcap', None, None, '/tmp/', True, False, True, PLUGIN_FOLDER, None, ['basicFlow', 'txtSink'], 'tcp')

    print_test("T2Utils.run_tranalyzer(pcap_list=['file1.pcap', 'file2.pcap']) raise CalledProcessError")
    t2_test_raise(T2Utils.run_tranalyzer, CalledProcessError, None, None, ['file1.pcap', 'file2.pcap'])

    print_test(f"T2Utils.run_tranalyzer(iface='{LOOPBACK}', output_prefix='/tmp/', log_file=True, timeout=5) raise TimeoutExpired")
    t2_test_raise(T2Utils.run_tranalyzer, TimeoutExpired, None, LOOPBACK, None, '/tmp/', True, False, False, None, None, None, None, None, 5)


def test_t2utils_load_plugins():
    print_test("T2Utils.load_plugins('tcpStates') does not raise Exception")
    t2_test_do_not_raise(T2Utils.load_plugins, Exception, 'tcpStates')

    print_test("type(T2Utils.tcpStates) == T2Plugin")
    t2_test_equal(type(T2Utils.tcpStates), T2Plugin)

    print_test("T2Utils.load_plugins('nonExistingPlugin') raise NameError")
    t2_test_raise(T2Utils.load_plugins, NameError, 'nonExistingPlugin')

    print_test("T2Utils.load_plugins(['arpDecode', 'basicStats']) does not raise Exception")
    t2_test_do_not_raise(T2Utils.load_plugins, Exception, ['arpDecode', 'basicStats'])

    print_test("type(T2Utils.arpDecode) == T2Plugin")
    t2_test_equal(type(T2Utils.arpDecode), T2Plugin)

    print_test("type(T2Utils.basicStats) == T2Plugin")
    t2_test_equal(type(T2Utils.basicStats), T2Plugin)

    print_test("T2Utils.load_plugins() does not raise Exception")
    t2_test_do_not_raise(T2Utils.load_plugins, Exception)


def test_t2plugin_type():
    print_test("arpDecode = T2Plugin('arpDecode')", newline=True)
    arpDecode = T2Plugin('arpDecode')

    print_test("type(arpDecode) == T2Plugin")
    t2_test_equal(type(arpDecode), T2Plugin)


def test_t2plugin_name_description_number_flags_default():
    print_test("T2Plugin('nonExistingPlugin') raise NameError")
    t2_test_raise(T2Plugin, NameError, 'nonExistingPlugin')

    print_test("arpDecode = T2Plugin('arpDecode')", newline=True)
    arpDecode = T2Plugin('arpDecode')

    print_test("arpDecode.name == 'arpDecode'")
    t2_test_equal(arpDecode.name, 'arpDecode')

    print_test("arpDecode.description == 'Address Resolution Protocol (ARP)'")
    t2_test_equal(arpDecode.description, 'Address Resolution Protocol (ARP)')

    print_test("arpDecode.number == '179'")
    t2_test_equal(arpDecode.number, '179')

    print_test("arpDecode.flags == ['ARP_MAX_IP']")
    t2_test_equal(arpDecode.flags, ['ARP_MAX_IP'])

    print_test("arpDecode.list_config() == ['ARP_MAX_IP']")
    t2_test_equal(arpDecode.list_config(), ['ARP_MAX_IP'])

    print_test("arpDecode.default == {'ARP_MAX_IP': 10}")
    t2_test_equal(arpDecode.default, {'ARP_MAX_IP': 10})

    print_test("tcpStates = T2Plugin('tcpStates', T2Utils.T2PLHOME + '/tcpStates/default.config')", newline=True)
    tcpStates = T2Plugin('tcpStates', T2Utils.T2PLHOME + '/tcpStates/default.config')

    print_test("tcpStates.name == 'tcpStates'")
    t2_test_equal(tcpStates.name, 'tcpStates')


def test_t2plugin_build_clean_unload():
    print_test("arpDecode = T2Plugin('arpDecode')", newline=True)
    arpDecode = T2Plugin('arpDecode')

    print_test("arpDecode.build()", newline=True)
    arpDecode.build()

    print_test("arpDecode.clean()", newline=True)
    arpDecode.clean()

    print_test("arpDecode.unload()", newline=True)
    arpDecode.unload()


def test_t2plugin_load_config():
    print_test("arpDecode = T2Plugin('arpDecode')", newline=True)
    arpDecode = T2Plugin('arpDecode')

    print_test("arpDecode.load_config(T2Utils.T2PLHOME + '/arpDecode/default.config')", newline=True)
    arpDecode.load_config(T2Utils.T2PLHOME + '/arpDecode/default.config')

    if isfile('/tmp/testConfig.config'):
        os.remove('/tmp/testConfig.config')

    print_test("arpDecode.generate_config('/tmp/testConfig.config')", newline=True)
    arpDecode.generate_config('/tmp/testConfig.config')

    print_test("isfile('/tmp/testConfig.config') == True")
    t2_test_equal(isfile('/tmp/testConfig.config'), True)


def test_t2plugin_get_default():
    print_test("arpDecode = T2Plugin('arpDecode')", newline=True)
    arpDecode = T2Plugin('arpDecode')

    print_test("arpDecode.default['ARP_MAX_IP'] == 10")
    t2_test_equal(arpDecode.default['ARP_MAX_IP'], 10)

    print_test("arpDecode.get_default('ARP_MAX_IP') == 10")
    t2_test_equal(arpDecode.get_default('ARP_MAX_IP'), 10)

    print_test("arpDecode.get_default('NON_EXISTING_FLAG') raise NameError")
    t2_test_raise(arpDecode.get_default, NameError, 'NON_EXISTING_FLAG')


def test_t2plugin_get_set_set_default():
    print_test("arpDecode = T2Plugin('arpDecode')", newline=True)
    arpDecode = T2Plugin('arpDecode')

    print_test("arpDecode.ARP_MAX_IP == 10")
    t2_test_equal(arpDecode.ARP_MAX_IP, 10)

    print_test("arpDecode.ARP_MAX_IP = 15", newline=True)
    arpDecode.ARP_MAX_IP = 15

    print_test("arpDecode.ARP_MAX_IP == 15")
    t2_test_equal(arpDecode.ARP_MAX_IP, 15)

    print_test("arpDecode.changes == {'ARP_MAX_IP': 15}")
    t2_test_equal(arpDecode.changes, {'ARP_MAX_IP': 15})

    print_test("arpDecode.set_default('ARP_MAX_IP')", newline=True)
    arpDecode.set_default('ARP_MAX_IP')

    print_test("arpDecode.ARP_MAX_IP == 10")
    t2_test_equal(arpDecode.ARP_MAX_IP, 10)

    print_test("arpDecode.ARP_MAX_IP = 15", newline=True)
    arpDecode.ARP_MAX_IP = 15

    print_test("arpDecode.ARP_MAX_IP == 15")
    t2_test_equal(arpDecode.ARP_MAX_IP, 15)

    print_test("arpDecode.set_default()", newline=True)
    arpDecode.set_default()

    print_test("arpDecode.ARP_MAX_IP == 10")
    t2_test_equal(arpDecode.ARP_MAX_IP, 10)

    print_test("arpDecode.ARP_MAX_IP = 15", newline=True)
    arpDecode.ARP_MAX_IP = 15

    print_test("arpDecode.ARP_MAX_IP == 15")
    t2_test_equal(arpDecode.ARP_MAX_IP, 15)

    print_test("arpDecode.status()", newline=True)
    arpDecode.status()

    print_test("arpDecode.discard_changes()", newline=True)
    arpDecode.discard_changes()

    print_test("arpDecode.ARP_MAX_IP == 10")
    t2_test_equal(arpDecode.ARP_MAX_IP, 10)

    print_test("arpDecode.status()", newline=True)
    arpDecode.status()


def test_t2plugin_diff():
    print_test("arpDecode = T2Plugin('arpDecode')", newline=True)
    arpDecode = T2Plugin('arpDecode')

    print_test("arpDecode.ARP_MAX_IP == 10")
    t2_test_equal(arpDecode.ARP_MAX_IP, 10)

    print_test("arpDecode.ARP_MAX_IP = 15", newline=True)
    arpDecode.ARP_MAX_IP = 15

    print_test("arpDecode.ARP_MAX_IP == 15")
    t2_test_equal(arpDecode.ARP_MAX_IP, 15)

    print_test("arpDecode.diff('source') raise NotImplementedError")
    t2_test_raise(arpDecode.diff, NotImplementedError, 'source')

    print_test("arpDecode.diff() == {}")
    t2_test_equal(arpDecode.diff(), {})

    print_test("arpDecode.apply_changes()", newline=True)
    arpDecode.apply_changes()

    print_test("arpDecode.diff() == {'ARP_MAX_IP': 15}")
    t2_test_equal(arpDecode.diff(), {'ARP_MAX_IP': 15})

    print_test("arpDecode.ARP_MAX_IP = 10", newline=True)
    arpDecode.ARP_MAX_IP = 10

    print_test("arpDecode.ARP_MAX_IP == 10")
    t2_test_equal(arpDecode.ARP_MAX_IP, 10)

    print_test("arpDecode.apply_changes()", newline=True)
    arpDecode.apply_changes()

    print_test("arpDecode.ARP_MAX_IP = 15", newline=True)
    arpDecode.ARP_MAX_IP = 15

    print_test("arpDecode.ARP_MAX_IP == 15")
    t2_test_equal(arpDecode.ARP_MAX_IP, 15)

    print_test("arpDecode.discard_changes()", newline=True)
    arpDecode.discard_changes()

    print_test("arpDecode.ARP_MAX_IP == 10")
    t2_test_equal(arpDecode.ARP_MAX_IP, 10)


def test_t2plugin_get_set_reset():
    print_test("arpDecode = T2Plugin('arpDecode')", newline=True)
    arpDecode = T2Plugin('arpDecode')

    print_test("type(arpDecode) == T2Plugin")
    t2_test_equal(type(arpDecode), T2Plugin)

    print_test("arpDecode.ARP_MAX_IP == 10")
    t2_test_equal(arpDecode.ARP_MAX_IP, 10)

    print_test("arpDecode.ARP_MAX_IP = 15", newline=True)
    arpDecode.ARP_MAX_IP = 15

    print_test("arpDecode.ARP_MAX_IP == 15")
    t2_test_equal(arpDecode.ARP_MAX_IP, 15)

    print_test("arpDecode.reset('NON_EXISTING_FLAG') raise NameError")
    t2_test_raise(arpDecode.reset, NameError, 'NON_EXISTING_FLAG')

    print_test("arpDecode.reset('ARP_MAX_IP')", newline=True)
    arpDecode.reset('ARP_MAX_IP')

    print_test("arpDecode.ARP_MAX_IP == 10")
    t2_test_equal(arpDecode.ARP_MAX_IP, 10)

    print_test("arpDecode.ARP_MAX_IP = 15", newline=True)
    arpDecode.ARP_MAX_IP = 15

    print_test("arpDecode.ARP_MAX_IP == 15")
    t2_test_equal(arpDecode.ARP_MAX_IP, 15)

    print_test("arpDecode.reset(['ARP_MAX_IP', 'NON_EXISTING_FLAG']) raise NameError")
    t2_test_raise(arpDecode.reset, NameError, ['ARP_MAX_IP', 'NON_EXISTING_FLAG'])

    print_test("arpDecode.reset()", newline=True)
    arpDecode.reset()

    print_test("arpDecode.ARP_MAX_IP == 10")
    t2_test_equal(arpDecode.ARP_MAX_IP, 10)

    print_test("arpDecode._set_config('NON_EXISTING_FLAG', 1) raise NameError")
    t2_test_raise(arpDecode._set_config, NameError, 'NON_EXISTING_FLAG', 1)


def test_t2plugin_save_config():
    print_test("arpDecode = T2Plugin('arpDecode')", newline=True)
    arpDecode = T2Plugin('arpDecode')

    print_test("type(arpDecode) == T2Plugin")
    t2_test_equal(type(arpDecode), T2Plugin)

    print_test("arpDecode.ARP_MAX_IP == 10")
    t2_test_equal(arpDecode.ARP_MAX_IP, 10)

    print_test("arpDecode.ARP_MAX_IP = 15", newline=True)
    arpDecode.ARP_MAX_IP = 15

    if isfile('/tmp/testConfig.config'):
        os.remove('/tmp/testConfig.config')

    print_test("arpDecode.config = '/tmp/testConfig.config", newline=True)
    arpDecode.config_file = '/tmp/testConfig.config'

    print_test("arpDecode.save_config()", newline=True)
    arpDecode.save_config()

    print_test("T2Utils.get_config('arpDecode', 'ARP_MAX_IP', '/tmp/testConfig.config') == 15")
    t2_test_equal(T2Utils.get_config('arpDecode', 'ARP_MAX_IP', '/tmp/testConfig.config'), 15)


def test_t2_type():
    print_test("t2 = T2()", newline=True)
    t2 = T2()

    print_test("type(t2) == T2")
    t2_test_equal(type(t2), T2)


def test_t2_constructor():
    print_test("T2(pcap='file.pcap', pcap_list='pcap_list.txt') raise RuntimeError")
    t2_test_raise(T2, RuntimeError, 'file.pcap', None, 'pcap_list.txt')

    print_test("T2(pcap='file.pcap', iface='eth0') raise RuntimeError")
    t2_test_raise(T2, RuntimeError, 'file.pcap', 'eth0')

    print_test("T2(pcap='file.pcap', iface='eth0') raise RuntimeError")
    t2_test_raise(T2, RuntimeError, None, 'eth0', 'pcap_list.txt')

    print_test("T2(iface='tranalyzer2') raise OSError")
    t2_test_raise(T2, OSError, None, 'tranalyzer2')

    print_test("t2 = T2(plugins=['tcpFlags', 'tcpStates'], output_format='json')", newline=True)
    t2 = T2(plugins=['tcpFlags', 'tcpStates'], output_format='json')

    print_test("type(t2) == T2")
    t2_test_equal(type(t2), T2)

    print_test("t2.list_plugins() == ['tcpFlags', 'tcpStates', 'jsonSink']")
    t2_test_equal(t2.list_plugins(), ['jsonSink', 'tcpFlags', 'tcpStates'])

    print_test("t2 = T2(output_format=['txt', 'json'])", newline=True)
    t2 = T2(output_format=['txt', 'json'])

    print_test("type(t2) == T2")
    t2_test_equal(type(t2), T2)

    print_test("t2.list_plugins() == ['jsonSink', 'txtSink']")
    t2_test_equal(t2.list_plugins(), ['jsonSink', 'txtSink'])

    print_test(f"t2.default_plugin_folder == '{PLUGIN_FOLDER}'")
    t2_test_equal(t2.default_plugin_folder, PLUGIN_FOLDER)

    if isfile('/tmp/plugins.load'):
        os.remove('/tmp/plugins.load')

    print_test("T2Utils.create_plugin_list(['arpDecode', 'basicStats'], outfile='/tmp/plugins.load')", newline=True)
    T2Utils.create_plugin_list(['arpDecode', 'basicStats'], outfile='/tmp/plugins.load')

    print_test("t2.loading_list = '/tmp/plugins.load'", newline=True)
    t2.loading_list = '/tmp/plugins.load'

    print_test("t2.loading_list == '/tmp/plugins.load'")
    t2_test_equal(t2.loading_list, '/tmp/plugins.load')

    print_test(f"t2.t2_exec == join('{PLUGIN_FOLDER}', 'bin', 'tranalyzer')")
    t2_test_equal(t2.t2_exec, join(PLUGIN_FOLDER, 'bin', 'tranalyzer'))

    print_test("t2.plugin_folder = '/tmp/'", newline=True)
    t2.plugin_folder = '/tmp/'

    print_test("t2.t2_exec == join('/tmp', 'bin', 'tranalyzer')")
    t2_test_equal(t2.t2_exec, join('/tmp', 'bin', 'tranalyzer'))


def test_t2_status():
    print_test("T2().status()", newline=True)
    T2().status()

    print_test(f"t2 = T2(pcap='file.pcap', output_prefix='/tmp/', plugin_folder='{PLUGIN_FOLDER}', plugins=['arpDecode', 'basicStats', 'tcpFlags', 'tcpStates'], output_format=['json', 'txt.gz'], packet_mode=True, bpf='tcp')", newline=True)
    t2 = T2(pcap='file.pcap', output_prefix='/tmp/', plugin_folder=PLUGIN_FOLDER, plugins=['arpDecode', 'basicStats', 'tcpFlags', 'tcpStates'], output_format=['json', 'txt.gz'], packet_mode=True, bpf='tcp')

    print_test("type(t2) == T2")
    t2_test_equal(type(t2), T2)

    print_test("t2.tranalyzer2.SCTP_ACTIVATE = 1", newline=True)
    t2.tranalyzer2.SCTP_ACTIVATE = 1

    print_test("t2.status()", newline=True)
    t2.status()

    print_test("t2.pcap = None", newline=True)
    t2.pcap = None

    print_test(f"t2.iface = '{LOOPBACK}'", newline=True)
    t2.iface = LOOPBACK

    print_test("t2.status()", newline=True)
    t2.status()

    print_test("t2.iface = None", newline=True)
    t2.iface = None

    print_test("t2.pcap_list = 'pcap_list.txt'", newline=True)
    t2.pcap_list = 'pcap_list.txt'

    print_test("t2.status()", newline=True)
    t2.status()

    print_test("t2.pcap_list = ['file1.pcap', 'file2.pcap']", newline=True)
    t2.pcap_list = ['file1.pcap', 'file2.pcap']

    print_test("t2.status()", newline=True)
    t2.status()

    if isfile('/tmp/plugins.load'):
        os.remove('/tmp/plugins.load')

    print_test("T2Utils.create_plugin_list(['basicStats', 'jsonSink', 'tcpFlags', 'txtSink'], outfile='/tmp/plugins.load')", newline=True)
    T2Utils.create_plugin_list(['basicStats', 'jsonSink', 'tcpFlags', 'txtSink'], outfile='/tmp/plugins.load')

    print_test("t2.loading_list = '/tmp/plugins.load'", newline=True)
    t2.loading_list = '/tmp/plugins.load'

    print_test("t2.arpDecode.ARP_MAX_IP = 1234", newline=True)
    t2.arpDecode.ARP_MAX_IP = 1234

    print_test("t2.status()", newline=True)
    t2.status()


def test_t2_add_output_format():
    for i in (
            'bin', 'bin.gz',
            'csv', 'csv.gz',
            'txt', 'txt.gz',
            'json', 'json.gz',
            'netflow',
            'mysql', 'sqlite', 'postgres', 'mongo',
            'socket',
            'streaming',
            'pcap'):
        print_test(f"t2 = T2(output_format='{i}')", newline=True)
        t2 = T2(output_format=f'{i}')

        print_test("len(t2.list_plugins()) == 1")
        t2_test_equal(len(t2.list_plugins()), 1)

    print_test("t2.add_output_format('nonExistingFormat') raise RuntimeError")
    t2_test_raise(t2.add_output_format, RuntimeError, 'nonExistingFormat')


def test_t2_add_remove_plugins():
    print_test("t2 = T2()", newline=True)
    t2 = T2()

    print_test("type(t2.tranalyzer2) == T2Plugin")
    t2_test_equal(type(t2.tranalyzer2), T2Plugin)

    print_test("t2.plugins == {}")
    t2_test_equal(t2.plugins, {})

    print_test("t2.add_plugin('arpDecode')", newline=True)
    t2.add_plugin('arpDecode')

    print_test("type(t2.arpDecode) == T2Plugin")
    t2_test_equal(type(t2.arpDecode), T2Plugin)

    print_test("t2.add_plugins(['basicStats', 'txtSink'])", newline=True)
    t2.add_plugins(['basicStats', 'txtSink'])

    for plugin in ('basicStats', 'txtSink'):
        print_test(f"type(t2.plugins['{plugin}']) == T2Plugin")
        t2_test_equal(type(t2.plugins[plugin]), T2Plugin)

    print_test("t2.list_plugins() == ['arpDecode', 'basicStats', 'txtSink'])")
    t2_test_equal(t2.list_plugins(), ['arpDecode', 'basicStats', 'txtSink'])

    print_test("t2.remove_plugin('arpDecode')", newline=True)
    t2.remove_plugin('arpDecode')

    print_test("'arpDecode' not in t2.plugins == True")
    t2_test_equal('arpDecode' not in t2.plugins, True)

    print_test("t2.remove_plugins(['basicStats', 'txtSink'])", newline=True)
    t2.remove_plugins(['basicStats', 'txtSink'])

    for plugin in ('basicStats', 'txtSink'):
        print_test(f"'{plugin}' not in t2.plugins == True")
        t2_test_equal(plugin not in t2.plugins, True)

    print_test("t2.add_plugins(['arpDecode', 'basicStats', 'txtSink'])", newline=True)
    t2.add_plugins(['arpDecode', 'basicStats', 'txtSink'])

    print_test("t2.list_plugins() == ['arpDecode', 'basicStats', 'txtSink'])")
    t2_test_equal(t2.list_plugins(), ['arpDecode', 'basicStats', 'txtSink'])

    print_test("t2.clear_plugins()", newline=True)
    t2.clear_plugins()

    print_test("t2.list_plugins() == [])")
    t2_test_equal(t2.list_plugins(), [])

    print_test("t2.add_plugins(['arpDecode', 'basicStats', 'txtSink'])", newline=True)
    t2.add_plugins(['arpDecode', 'basicStats', 'txtSink'])

    print_test("t2.list_plugins() == ['arpDecode', 'basicStats', 'txtSink'])")
    t2_test_equal(t2.list_plugins(), ['arpDecode', 'basicStats', 'txtSink'])

    default_loading_list = join(PLUGIN_FOLDER, 'plugins.load')
    if isfile(default_loading_list):
        os.remove(default_loading_list)

    print_test("t2.create_plugin_list()", newline=True)
    t2.create_plugin_list()

    print_test(f"isfile({default_loading_list}) == True")
    t2_test_equal(isfile(default_loading_list), True)

    if isfile('/tmp/plugins.load'):
        os.remove('/tmp/plugins.load')

    print_test("t2.plugin_folder = '/tmp/'", newline=True)
    t2.plugin_folder = '/tmp/'

    print_test("t2.create_plugin_list()", newline=True)
    t2.create_plugin_list()

    print_test("isfile('/tmp/plugins.load') == True")
    t2_test_equal(isfile('/tmp/plugins.load'), True)

    if isfile('/tmp/plugins.load'):
        os.remove('/tmp/plugins.load')

    print_test("t2.create_plugin_list(outfile='/tmp/plugins.load')", newline=True)
    t2.create_plugin_list(outfile='/tmp/plugins.load')

    print_test("isfile('/tmp/plugins.load') == True")
    t2_test_equal(isfile('/tmp/plugins.load'), True)

    print_test("t2.set_plugins(['basicFlow'])", newline=True)
    t2.set_plugins(['basicFlow'])

    print_test("t2.list_plugins() == ['basicFlow'])")
    t2_test_equal(t2.list_plugins(), ['basicFlow'])


def test_t2_build_clean_unload():
    print_test("t2 = T2()", newline=True)
    t2 = T2()

    print_test("t2.build()", newline=True)
    t2.build()

    print_test("t2.build(plugin='arpDecode', plugin_folder='/tmp/')", newline=True)
    t2.build(plugin='arpDecode', plugin_folder='/tmp/')

    print_test("t2.clean()", newline=True)
    t2.clean()

    print_test("t2.clean(plugin='arpDecode')", newline=True)
    t2.clean(plugin='arpDecode')

    print_test("t2.unload()", newline=True)
    t2.unload()

    print_test("t2.unload(plugin='arpDecode', plugin_folder='/tmp/')", newline=True)
    t2.unload(plugin='arpDecode', plugin_folder='/tmp/')


def test_t2_run():
    print_test("T2().run(pcap='file.pcap', pcap_list='pcap_list.txt') raise RuntimeError")
    t2_test_raise(T2().run, RuntimeError, 'file.pcap', None, 'pcap_list.txt')

    print_test("T2().run(pcap='file.pcap', iface='eth0') raise RuntimeError")
    t2_test_raise(T2().run, RuntimeError, 'file.pcap', 'eth0')

    print_test("T2().run(pcap='file.pcap', iface='eth0') raise RuntimeError")
    t2_test_raise(T2().run, RuntimeError, None, 'eth0', 'pcap_list.txt')

    print_test("T2().run(iface='tranalyzer2') raise OSError")
    t2_test_raise(T2().run, OSError, None, 'tranalyzer2')

    print_test("T2().run() raise RuntimeError")
    t2_test_raise(T2().run, RuntimeError)

    print_test("T2().run(pcap='file.pcap') raise CalledProcessError")
    t2_test_raise(T2().run, CalledProcessError, 'file.pcap')

    print_test("T2().run(pcap_list=['file1.pcap', 'file2.pcap']) raise CalledProcessError")
    t2_test_raise(T2().run, CalledProcessError, None, None, ['file1.pcap', 'file2.pcap'])

    print_test("t2 = T2()", newline=True)
    t2 = T2()

    print_test("t2.create_plugin_list(['txtSink'], '/tmp/plugins.load')", newline=True)
    t2.create_plugin_list(['txtSink'], '/tmp/plugins.load')

    print_test(f"t2.run(iface='{LOOPBACK}', output_prefix='/tmp/', packet_mode=True, plugin_folder='{PLUGIN_FOLDER}', loading_list='/tmp/plugins.load', bpf='tcp', rebuild=True, timeout=10) raise TimeoutExpired")
    t2_test_raise(t2.run, TimeoutExpired, None, LOOPBACK, None, '/tmp/', False, True, None, PLUGIN_FOLDER, '/tmp/plugins.load', 'tcp', True, False, 10)

    print_test("t2 = T2(streaming=True)", newline=True)
    t2 = T2(streaming=True)

    print_test("t2.apply_changes()", newline=True)
    t2.apply_changes()

    print_test("t2.build()", newline=True)
    t2.build()

    print_test(f"t2.run(pcap='{T2PY_TESTS_HOME}/data/file.pcap')", newline=True)
    t2.run(pcap=f'{T2PY_TESTS_HOME}/data/file.pcap')

    print_test("for flow in t2.stream(): print(flow)", newline=True)
    for flow in t2.stream():
        print(flow)

    print_test("t2.socketSink.SKS_CONTENT_TYPE = 0", newline=True)
    t2.socketSink.SKS_CONTENT_TYPE = 0

    print_test("t2.socketSink.apply_changes()", newline=True)
    t2.socketSink.apply_changes()

    print_test("t2.run(pcap='file.pcap') raise RuntimeError")
    t2_test_raise(t2.run, RuntimeError, 'file.pcap')

    print_test("flows = T2().stream()", newline=True)
    flows = T2().stream()

    print_test("next(flows) raise RuntimeError")
    t2_test_raise(next, RuntimeError, flows)

    print_test("T2().run(streaming=True) raise RuntimeError")
    t2_test_raise(T2().run, RuntimeError, 'file.pcap', None, None, '/tmp/', False, True, None, PLUGIN_FOLDER, None, 'tcp', True, True)


def test_t2_apply_changes():
    print_test("t2 = T2(output_format='txt')", newline=True)
    t2 = T2(output_format='txt')

    print_test("t2.apply_changes()", newline=True)
    t2.apply_changes()

    print_test("t2.discard_changes()", newline=True)
    t2.discard_changes()

    print_test("t2.reset()", newline=True)
    t2.reset()


def test_t2_files_empty():
    print_test("t2 = T2()", newline=True)
    t2 = T2()

    if isfile('/tmp/file_flows.json'):
        os.remove('/tmp/file_flows.json')
    if isfile('/tmp/file_flows.txt'):
        os.remove('/tmp/file_flows.txt')
    if isfile('/tmp/file_packets.txt'):
        os.remove('/tmp/file_packets.txt')
    if isfile('/tmp/file_log.txt'):
        os.remove('/tmp/file_log.txt')
    if isfile('/tmp/file_monitoring.txt'):
        os.remove('/tmp/file_monitoring.txt')
    if isfile('/tmp/file_headers.txt'):
        os.remove('/tmp/file_headers.txt')

    print_test("t2._load_file('/tmp/nonExistingFile.txt') == None")
    t2_test_equal(t2._load_file('/tmp/nonExistingFile.txt'), None)

    print_test("t2.pcap = '/home/user/file.pcap'", newline=True)
    t2.pcap = '/home/user/file.pcap'

    print_test("t2.output_prefix = '/tmp/'", newline=True)
    t2.output_prefix = '/tmp/'

    print_test("t2.flow_file_json() = '/tmp/file_flows.json'")
    t2_test_equal(t2.flow_file_json(), '/tmp/file_flows.json')

    print_test("t2.flows_json() raise RuntimeError")
    t2_test_raise(t2.flows_json, RuntimeError)

    print_test("t2.print_flows_json() raise RuntimeError")
    t2_test_raise(t2.print_flows_json, RuntimeError)

    print_test("t2.flow_file_txt() = '/tmp/file_flows.txt'")
    t2_test_equal(t2.flow_file_txt(), '/tmp/file_flows.txt')

    print_test("t2.flows_txt() raise RuntimeError")
    t2_test_raise(t2.flows_txt, RuntimeError)

    print_test("t2.print_flows_txt() raise RuntimeError")
    t2_test_raise(t2.print_flows_txt, RuntimeError)

    print_test("t2.headers_file() = '/tmp/file_headers.txt'")
    t2_test_equal(t2.headers_file(), '/tmp/file_headers.txt')

    print_test("t2.headers() raise RuntimeError")
    t2_test_raise(t2.headers, RuntimeError)

    print_test("t2.print_headers() raise RuntimeError")
    t2_test_raise(t2.print_headers, RuntimeError)

    print_test("t2.log_file() = '/tmp/file_log.txt'")
    t2_test_equal(t2.log_file(), '/tmp/file_log.txt')

    print_test("t2.log() raise RuntimeError")
    t2_test_raise(t2.log, RuntimeError)

    print_test("t2.print_log() raise RuntimeError")
    t2_test_raise(t2.print_log, RuntimeError)

    print_test("t2.report() raise RuntimeError")
    t2_test_raise(t2.report, RuntimeError)

    print_test("t2.print_report() raise RuntimeError")
    t2_test_raise(t2.print_report, RuntimeError)

    print_test("t2.monitoring_file() = '/tmp/file_monitoring.txt'")
    t2_test_equal(t2.monitoring_file(), '/tmp/file_monitoring.txt')

    print_test("t2.monitoring() raise RuntimeError")
    t2_test_raise(t2.monitoring, RuntimeError)

    print_test("t2.print_monitoring() raise RuntimeError")
    t2_test_raise(t2.print_monitoring, RuntimeError)

    print_test("t2.packet_file() = '/tmp/file_packets.txt'")
    t2_test_equal(t2.packet_file(), '/tmp/file_packets.txt')

    print_test("t2.packets() raise RuntimeError")
    t2_test_raise(t2.packets, RuntimeError)

    print_test("t2.print_packets() raise RuntimeError")
    t2_test_raise(t2.print_packets, RuntimeError)

    print_test("t2.flow_file() == None")
    t2_test_equal(t2.flow_file(), None)

    print_test("t2.flows() raise RuntimeError")
    t2_test_raise(t2.flows, RuntimeError)

    print_test("t2.print_flows() raise RuntimeError")
    t2_test_raise(t2.print_flows, RuntimeError)

    print_test("t2.to_pandas() raise RuntimeError")
    t2_test_raise(t2.to_pandas, RuntimeError)

    print_test("t2.add_output_format('json')", newline=True)
    t2.add_output_format('json')

    print_test("t2.flow_file() == t2.flow_file_json()")
    t2_test_equal(t2.flow_file(), t2.flow_file_json())

    print_test("t2.remove_plugin('jsonSink')", newline=True)
    t2.remove_plugin('jsonSink')

    print_test("t2.add_output_format('txt')", newline=True)
    t2.add_output_format('txt')

    print_test("t2.flow_file() == t2.flow_file_txt()")
    t2_test_equal(t2.flow_file(), t2.flow_file_txt())

    print_test("t2.to_pandas('/tmp/nonExistingFile.txt') raise FileNotFoundError")
    t2_test_raise(t2.to_pandas, FileNotFoundError, '/tmp/nonExistingFile.txt')


def test_t2_files():
    print_test("T2(output_prefix='/tmp/results')._output_prefix() == '/tmp/results'")
    t2_test_equal(T2(output_prefix='/tmp/results')._output_prefix(), '/tmp/results')

    print_test("T2(output_prefix='/tmp/', pcap='mypcap')._output_prefix() == '/tmp/mypcap'")
    t2_test_equal(T2(output_prefix='/tmp/', pcap='mypcap')._output_prefix(), '/tmp/mypcap')

    print_test("T2(pcap='mypcap')._output_prefix() == 'mypcap'")
    t2_test_equal(T2(pcap='mypcap')._output_prefix(), 'mypcap')

    print_test("T2(pcap='file.pcap')._output_prefix() == 'file'")
    t2_test_equal(T2(pcap='file.pcap')._output_prefix(), 'file')

    print_test("T2()._output_prefix() == None")
    t2_test_equal(T2()._output_prefix(), None)

    print_test(f"t2 = T2(pcap='{T2PY_TESTS_HOME}/data/file.pcap', output_prefix='/tmp/', packet_mode=True, save_monitoring=True, plugins=['basicFlow'], output_format=['json', 'txt'])", newline=True)
    t2 = T2(pcap=f'{T2PY_TESTS_HOME}/data/file.pcap', output_prefix='/tmp/', packet_mode=True, plugins=['basicFlow'], output_format=['json', 'txt'])

    print_test("t2.build()", newline=True)
    t2.build()

    print_test("t2.run()", newline=True)
    t2.run()

    print_test("t2.headers()", newline=True)
    t2.headers()

    print_test("t2.flows()", newline=True)
    t2.flows()

    print_test("t2.flows_json()", newline=True)
    t2.flows_json()

    print_test("t2.flows_txt()", newline=True)
    t2.flows_txt()

    print_test("t2.remove_plugin('txtSink')", newline=True)
    t2.remove_plugin('txtSink')

    print_test("t2.flows_txt()", newline=True)
    t2.flows_txt()

    print_test("t2.packets()", newline=True)
    t2.packets()

    print_test("t2.report()", newline=True)
    t2.report()

    print_test("t2.print_headers()", newline=True)
    t2.print_headers()

    print_test("t2.print_flows()", newline=True)
    t2.print_flows()

    print_test("t2.print_flows_json()", newline=True)
    t2.print_flows_json()

    print_test("t2.print_flows_txt()", newline=True)
    t2.print_flows_txt()

    print_test("t2.remove_plugin('jsonSink')", newline=True)
    t2.remove_plugin('jsonSink')

    print_test("t2.add_plugin('txtSink')", newline=True)
    t2.add_plugin('txtSink')

    print_test("t2.flows()", newline=True)
    t2.flows()

    print_test("t2.print_packets()", newline=True)
    t2.print_packets()

    print_test("t2.print_log()", newline=True)
    t2.print_log()

    print_test("t2.print_monitoring() raise RuntimeError", newline=True)
    t2_test_raise(t2.print_monitoring, RuntimeError)

    print_test("t2.to_pandas()", newline=True)
    t2.to_pandas()


def test_t2_follow_stream():
    print_test("T2().follow_stream(1) raise RuntimeError")
    t2_test_raise(T2().follow_stream, RuntimeError, 1)

    print_test(f"t2 = T2(output_prefix='{T2PY_TESTS_HOME}/data/file')", newline=True)
    t2 = T2(output_prefix=f'{T2PY_TESTS_HOME}/data/file')

    print_test("t2.follow_stream(1)")
    t2.follow_stream(1)


if __name__ == '__main__':
    import argparse

    tests_t2utils = [
        test_t2utils_env,
        test_t2utils_plugin_description_number,
        test_t2utils_list_config,
        test_t2utils_get_config,
        test_t2utils_get_default,
        test_t2utils_set_config,
        test_t2utils_set_config_dict,
        test_t2utils_set_config_str,
        test_t2utils_set_default,
        test_t2utils_reset_all,
        test_t2utils_reset_one,
        test_t2utils_generate_config,
        test_t2utils_apply_config,
        test_t2utils_create_plugin_list,
        test_t2utils_list_plugins,
        test_t2utils_build,
        test_t2utils_clean,
        test_t2utils_unload,
        test_t2utils_to_json_array,
        test_t2utils_to_pandas,
        test_t2utils_to_pdf,
        test_t2utils_tawk,
        test_t2utils_follow_stream,
        test_t2utils_network_interfaces,
        test_t2utils_valid_plugin_names,
        test_t2utils_create_pcap_list,
        test_t2utils_run_tranalyzer,
        test_t2utils_load_plugins,
    ]

    tests_t2plugin = [
        test_t2plugin_type,
        test_t2plugin_name_description_number_flags_default,
        test_t2plugin_build_clean_unload,
        test_t2plugin_load_config,
        test_t2plugin_get_default,
        test_t2plugin_get_set_set_default,
        test_t2plugin_diff,
        test_t2plugin_get_set_reset,
        test_t2plugin_save_config,
    ]

    tests_t2 = [
        test_t2_type,
        test_t2_constructor,
        test_t2_status,
        test_t2_add_output_format,
        test_t2_add_remove_plugins,
        test_t2_build_clean_unload,
        test_t2_run,
        test_t2_apply_changes,
        test_t2_files_empty,
        test_t2_files,
        test_t2_follow_stream,
    ]

    tests = []

    parser = argparse.ArgumentParser(description='Test t2py modules')
    parser.add_argument('-f', '--fatal', help='Abort as soon as a test fails', action='store_true')
    parser.add_argument('-u', '--t2utils', help='Test the T2Utils module', action='store_true')
    parser.add_argument('-p', '--t2plugin', help='Test the T2Plugin module', action='store_true')
    parser.add_argument('-t', '--t2', help='Test the T2 module', action='store_true')

    args = parser.parse_args()

    if args.fatal:
        FATAL = True

    if not args.t2utils and not args.t2plugin and not args.t2:
        args.t2utils = True
        args.t2plugin = True
        args.t2 = True

    if args.t2utils:
        tests.extend(tests_t2utils)
    if args.t2plugin:
        tests.extend(tests_t2plugin)
    if args.t2:
        tests.extend(tests_t2)

    for test in tests:
        print_title(f"{test.__name__}")
        test()

    if ERRORS > 0:
        print_red(f'\nSummary: {ERRORS} test{"s" if ERRORS > 1 else ""} failed')
    else:
        print_green('\nAll tests were successfully completed')
