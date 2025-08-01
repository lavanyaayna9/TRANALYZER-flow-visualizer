#!/usr/bin/env python3
#
# Toggle test.
# Use '--help' option for more information.
#
# Missing features:
#   - save all logs
#   - sequences to test: 0x3,0x4
#   - rerun-failed
#   - accept -b and -s options with -J and -S[12]

import os
import platform
import shutil
import signal
import sys
import time

from subprocess import PIPE, Popen


# Mac OS X
apple = bool(platform.mac_ver()[0])

T2HOME = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..')
T2HOME = os.path.normpath(T2HOME)
T2PLHOME = os.path.join(T2HOME, 'plugins')

autogen = {
    'exec': os.path.join(T2HOME, 'autogen.sh'),
    'opts': [],
}

sed = {
    'exec': shutil.which(('sed', 'gsed')[apple]),
    'opts': ['-rzi'],
    'regex': r's/(\n#define\s+{}\s+)[0-9]+([^\n]*)/\1{}\2/',
}


def find_t2_exec():
    """Find the path to the tranalyzer executable."""
    t2_home = os.path.join(T2HOME, 'tranalyzer2')
    t2_exec = []
    for root, _, files in os.walk(t2_home):
        for f in files:
            if f == 'tranalyzer':
                t2_exec.append(os.path.join(root, f))
    if len(t2_exec) == 0:
        return os.path.join(t2_home, 'tranalyzer')
    return max(t2_exec, key=os.path.getmtime)


t2 = {
    'exec': find_t2_exec(),
    'opts': ['-l'],
    'pcap': 'wurst.dmp',
    'prefix': '/tmp/wurst',
}

valgrind = {
    'exec': shutil.which('valgrind'),
    'opts': [
        '--tool=memcheck',
        '--leak-check=full',
        '--leak-resolution=high',
        '--trace-children=yes',
        '--num-callers=20',
        '--log-file=log-valgrind',
        '-v',
    ],
}

# For storing faulty configurations
toggle_err = {
    'build': [],
    'warn': [],
    't2': [],
    'leaks': [],
    'invrw': [],
}

FATAL_ERR = False
IGNORE_ERROR = False
IGNORE_WARNING = False
SILENT = False
VERBOSE_OUT = False
VERBOSE_ERR = False
FILES = set()  # List of files containing flags to toggle
FLAGS = []


def usage():
    """Print the program help."""
    print('Usage:')
    print(f'    {__file__} [option...] -f <file>')
    print()
    print('If no option is provided, check for build errors')
    print()
    print('Required arguments:')
    print('    -f file     the file containing the flags to toggle')
    print()
    print('Optional arguments:')
    print('    -w          check for compilation warnings')
    print('    -m          check for memory leaks (valgrind)')
    print('    -i          check for invalid read/write (valgrind)')
    print('    -t          check for runtime errors')
    print('                (if set, valgrind actions are ignored)')
    print()
    print("    -e          ignore compilation errors caused by '#error' macros")
    print("    -W          ignore compilation warnings caused by '#warning' macros")
    print('    -F          stop as soon as an error is encountered')
    print()
    print('    -b index    begin testing at index')
    print('    -s index    stop testing at index')
    print('    -c index    test configuration index')
    print('    -J          johnson counter (instead of toggle bits)')
    print('    -S1         one pass left shift (instead of toggle bits)')
    print('    -S2         multiple passes left shift (instead of toggle bits)')
    print('    -T          do not toggle flags from tranalyzer2, utils or another plugin')
    print()
    print('    -P pcap     pcap file to use')
    print('    -p folder   plugin folder')
    print('    -o out      tranalyzer output prefix')
    print()
    print('    -d          build in debug mode')
    print('    -r          force rebuild of makefiles')
    print('    -R          rebuild Tranalyzer and all the plugins in the plugin folder')
    print('    -X          bypass t2build lock file at your own risks...')
    print('                (concurrent modifications may happen)')
    print("    -B backend  use 'backend' (if available) instead of meson")
    print('                (meson, cmake, autotools-out-of-tree, autotools [deprecated])')
    print()
    print('    -n          reduced output mode')
    print('    -v          verbose mode (errors only)')
    print('    -vv         verbose mode')
    print()
    print('    -h, --help  show this help and exit')


def set_pcap_file(pcap):
    """Set the input pcap file in the tranalyzer command."""
    if not os.path.isfile(pcap):
        fatal(f"'{pcap}' is not a valid pcap file")
    t2['pcap'] = pcap


def set_output_prefix(prefix):
    """Set the output prefix in the tranalyzer command."""
    t2['prefix'] = prefix


def set_plugin_folder(folder):
    """Set the plugin folder in the autogen and tranalyzer commands."""
    new_opts = ['-p', folder]
    autogen['opts'].extend(new_opts)
    t2['opts'].extend(new_opts)


def printtxt(msg):
    """Print a message if required."""
    if not SILENT:
        print(msg)


def printerr(msg):
    """Print an error message in red."""
    print(f'\033[91m{msg}\033[0m', file=sys.stderr)  # Red


def printinf(msg):
    """Print an information message in blue."""
    printtxt(f'\033[94m{msg}\033[0m')  # Blue


def printok(msg):
    """Print an ok message in green."""
    print(f'\033[92m{msg}\033[0m')  # Green


def printwrn(msg):
    """Print a warning message in orange."""
    print(f'\033[93m{msg}\033[0m')  # Orange


def printout(out, err):
    """Print stdout and/or stderr if required."""
    if VERBOSE_OUT:
        msg = out.decode('utf-8')
        if len(msg):
            print(f'\n{msg}')
    if VERBOSE_ERR:
        msg = err.decode('utf-8')
        if len(msg):
            print(f'\n{msg}')


def fatal(msg):
    """Print an error message and exit."""
    printerr(msg)
    sys.exit(1)


def backup_files(files):
    """Backup all files."""
    for f in files:
        backup_file(f)


def backup_file(f):
    """Make a copy of `f` with the bak extension."""
    shutil.copy(f, f + '.bak')


def restore_files(files):
    """Restore all backup files."""
    for f in files:
        restore_file(f)


def restore_file(f):
    """Restore the backup file."""
    bak = f + '.bak'
    if os.path.isfile(bak):
        shutil.move(bak, f)


def cleanup():
    """Rebuild the plugin with the default configuration."""
    restore_files(FILES)
    with Popen(get_cmd_autogen(), stdout=PIPE, stderr=PIPE) as proc:
        proc.communicate()


def arg_error(msg):
    """Print an error message and exit."""
    printerr(msg)
    print(f"Try '{__file__} --help' for more information.")
    sys.exit(1)


def numeric_arg_error(opt):
    """Print an error message for missing numeric argument and exit."""
    arg_error(f"Option '{opt}' requires a numeric argument")


def missing_arg_error(opt):
    """Print an error message for missing argument and exit."""
    arg_error(f"Option '{opt}' requires an argument")


def abort(msg, flags, flagsv):
    """Abort the testing."""
    if flagsv is None:
        printerr(f'{msg}\n')
    else:
        flagsv_hex = hex(int(flagsv, base=2))
        text = '\n{} with the following configuration ({}){}'
        printerr(text.format(msg, flagsv_hex, '' if SILENT else ':'))
        if not SILENT:
            text = '    {}: {}\t{}'
            for i, flag in enumerate(flags):
                printtxt(text.format(flag['file'], flag['name'], flagsv[i]))
    if FATAL_ERR:
        cleanup()
        sys.exit(1)


def list_errors(msg, errors):
    """Print the plufin configuration which caused an error."""
    if not errors:
        return False
    text = f'\nThe following configurations {msg}:'
    if not SILENT:
        printerr(text)
    for err in errors:
        val = hex(int(err, base=2))
        if SILENT:
            text += ' ' + val
        else:
            printerr(f'    {val}:')
            txt = '        {}: {}\t{}'
            for i, flag in enumerate(FLAGS):
                printtxt(txt.format(flag['file'], flag['name'], err[i]))
    if SILENT:
        printerr(text)
    return True


def list_all_errors():
    """Print a summary of all the errors encountered during the test."""
    failed = False
    failed |= list_errors('failed to build', toggle_err['build'])
    failed |= list_errors('caused compilation warnings', toggle_err['warn'])
    failed |= list_errors('failed to run', toggle_err['t2'])
    failed |= list_errors('leaked memory', toggle_err['leaks'])
    failed |= list_errors('caused invalid read/write', toggle_err['invrw'])
    if failed:
        cleanup()
        fatal('\nToggle test encountered errors\n')
    else:
        printok('\nToggle test successfully run\n')
    return failed


def patch_plugin(flags, flagsv):
    """Patch the plugin for the next test to run."""
    for j, flag in enumerate(flags):
        printtxt(f"    {flag['name']} {flagsv[j]}")
        run_sed(flag['name'], flagsv[j], flag['file'])


def is_error_macro(out, err):
    """
    Return `True` if `out` or `err` contain an error caused by a #error macro,
    `False` otherwise.
    """
    macro = b'#error'
    return (err.find(macro) != -1 or out.find(macro) != -1)


def is_warning_macro(out, err):
    """
    Return `True` if `out` or `err` contain a warning caused by a #warning macro,
    `False` otherwise.
    """
    macro = b'#warning'
    return (err.find(macro) != -1 or out.find(macro) != -1)


def has_warning(out, err):
    """Return `True` if `out` or `err` contain a warning, `False` otherwise."""
    warning = b'warning: '
    return (err.find(warning) != -1 or out.find(warning) != -1)


def build_plugin(flags, flagsv, actions):
    """
    Build the plugin under test and
    check for build errors and/or compilation warnings if required.
    """
    cmd_autogen = get_cmd_autogen()
    printtxt(f"\nRunning {' '.join(cmd_autogen)}\n")
    with Popen(cmd_autogen, stdout=PIPE, stderr=PIPE) as proc:
        out, err = proc.communicate()
        printout(out, err)

    # Check for build errors
    if proc.returncode != 0:
        if IGNORE_ERROR and is_error_macro(out, err):
            return True
        abort('Build error', flags, flagsv)
        toggle_err['build'].append(flagsv)
        return False

    # Check for compilation warnings
    if '-w' in actions and has_warning(out, err):
        if IGNORE_WARNING and is_warning_macro(out, err):
            return True
        abort('Compilation warnings', flags, flagsv)
        toggle_err['warn'].append(flagsv)
        return False

    return True


def get_cmd_autogen():
    """Build the autogen command."""
    cmd = [autogen['exec']]
    cmd.extend(autogen['opts'])
    return cmd


def get_cmd_sed(flag, value, infile):
    """Build the sed command."""
    cmd = [sed['exec']]
    cmd.extend(sed['opts'])
    cmd.append(sed['regex'].format(flag, value))
    cmd.append(infile)
    return cmd


def get_cmd_t2():
    """Build the tranalyzer command."""
    cmd = [t2['exec'], '-r', t2['pcap'], '-w', t2['prefix']]
    cmd.extend(t2['opts'])
    return cmd


def get_cmd_valgrind():
    """Build the valgrind command."""
    cmd = [valgrind['exec']]
    cmd.extend(valgrind['opts'])
    cmd.extend(get_cmd_t2())
    return cmd


def run_sed(flag, value, infile):
    """Run sed to patch the value of `flag` in `infile`."""
    cmd_sed = get_cmd_sed(flag, value, infile)
    # printtxt('Running {}\n'.format(' '.join(cmd_sed)))
    if os.spawnv(os.P_WAIT, sed['exec'], cmd_sed) != 0:
        cleanup()
        fatal(f'Failed to change flags {flag} value to {value}')


def run_tranalyzer(flags, flagsv):
    """Run tranalyzer."""
    cmd_t2 = get_cmd_t2()
    printtxt(f'Running {cmd_t2}\n')
    if run_cmd(cmd_t2) != 0:
        abort('Runtime error', flags, flagsv)
        toggle_err['t2'].append(flagsv)


def run_cmd(cmd):
    """Run the command `cmd`, print its output if required and return its return code."""
    with Popen(cmd, stdout=PIPE, stderr=PIPE) as proc:
        out, err = proc.communicate()
        printout(out, err)
        return proc.returncode


def check_leaks():
    """Check for memory leaks in log-valgrind."""
    cmd = ('grep', 'definitely lost: [1-9]', 'log-valgrind')
    return run_cmd(cmd) == 0


def check_invalid_rw():
    """Check for invalid read/write in log-valgrind."""
    cmd = ('grep', 'Invalid', 'log-valgrind')
    return run_cmd(cmd) == 0


def run_valgrind(flags, flagsv, actions):
    """Run valgrind and check for memory leaks and/or invalid read/write."""
    cmd_valgrind = get_cmd_valgrind()
    printtxt(f"Running {' '.join(cmd_valgrind)}\n")
    # TODO check return value of spawnv?
    os.spawnv(os.P_WAIT, valgrind['exec'], cmd_valgrind)

    # Check for memory leaks
    if '-m' in actions and check_leaks():
        abort('Memory leaks', flags, flagsv)
        toggle_err['leaks'].append(flagsv)
        if '-i' not in actions:
            return

    # Check for invalid read/write
    if '-i' in actions and check_invalid_rw():
        abort('Invalid read/write', flags, flagsv)
        toggle_err['invrw'].append(flagsv)


def toggle_bits(start, stop, length):
    """Default testing method."""
    for i in range(start, stop):
        report_progress(start, stop, i, i)
        yield i, bin(i)[2:].zfill(length)


def shift_bits_1(start, stop, length):
    """Each iteration sets all bits to 0 except one."""
    stop = length + 1
    report_progress(start, stop, 0, 0)
    yield 0, bin(0)[2:].zfill(length)
    for i in range(start, length):
        k = 1 << i
        report_progress(start, stop, i + 1, k)
        yield k, bin(k)[2:].zfill(length)


def shift_bits_2(start, stop, length):
    """
    Each iteration sets all bits to 0 except one.
    After the last bit has been set to 1, it is left at 1 and
    the whole process is repeated on the remaining bits.
    """
    stop = length * (length + 1) / 2 + 1
    report_progress(start, stop, 0, 0)
    yield 0, bin(0)[2:].zfill(length)
    s = 0
    cnt = 1
    for i in range(length, 0, -1):
        for j in range(start, i):
            k = (1 << j) | s
            report_progress(start, stop, cnt, k)
            yield k, bin(k)[2:].zfill(length)
            cnt += 1

        s |= (1 << (i - 1))


def johnson_counter(start, stop, length):
    """Johnson counter toggle method."""
    stop = 2 * length
    if length == 1:
        yield from toggle_bits(start, stop, length)
        return
    cnt = 0
    shift_right = True
    for i in range(length, 1, -1):
        if shift_right:
            for j in range(start, i + 1):
                if j == start:
                    v = j
                else:
                    v |= 1 << (i - j)
                if v == 0 and cnt > 0:
                    return
                report_progress(start, stop, cnt, v)
                yield v, bin(v)[2:].zfill(length)
                cnt += 1
        else:
            v = 0
            for j in range(start, i):
                if j == 0:
                    v = (1 << i) - 1 - j
                else:
                    v >>= 1
                if v == 0 and cnt > 0:
                    return
                report_progress(start, stop, cnt, v)
                yield v, bin(v)[2:].zfill(length)
                cnt += 1
        shift_right = not shift_right


def report_progress(start, stop, curr_idx, curr_val):
    """Print progress status (current configuration and percentage completed)."""
    percent = 100.0 / (stop - start)
    msg = 'Current configuration: {} ({}%)'
    msg = msg.format(hex(curr_val), int((curr_idx - start) * percent))
    if not SILENT:
        printinf('\n' + msg + ':')
    else:
        sys.stdout.write('\x1b[2K\r')  # clear the line
        sys.stdout.write(f'\033[94m{msg}\033[0m')
        sys.stdout.flush()


def get_toggle_func(actions):
    """Get the toggle function for the requested testing mode."""
    if '-J' in actions:
        return johnson_counter
    if '-S1' in actions:
        return shift_bits_1
    if '-S2' in actions:
        return shift_bits_2
    return toggle_bits


def toggle(flags, start, stop, actions):
    """Toggle flags, patch the plugin, and test the current configuration."""
    toggle_func = get_toggle_func(actions)
    for _, flagsv in toggle_func(start, stop + 1, len(flags)):
        patch_plugin(flags, flagsv)
        build_plugin_and_run(flags, flagsv, actions)


def build_plugin_and_run(flags, flagsv, actions):
    """Build the plugin under test and run tranalyzer or valgrind if required."""
    if build_plugin(flags, flagsv, actions):
        if '-t' in actions:
            run_tranalyzer(flags, flagsv)
        elif '-m' in actions or '-i' in actions:
            run_valgrind(flags, flagsv, actions)


def read_file(filename, partial):
    """Read flags to toggle from `filename'."""
    with open(filename, encoding='utf-8') as f:
        flags = []
        for line in f:
            # skip comments and empty lines
            if line.isspace() or line.startswith('#'):
                continue
            line = line.split('#')[0]  # discard trailing comments
            try:
                name, infile = line.split()
            except ValueError:
                fatal(f"Invalid line '{line.strip()}' in '{filename}'")
            if not os.path.isfile(infile):
                printerr(f"Invalid line '{line.strip()}' in '{filename}':")
                printerr(f"    '{infile}' is not a valid file")
                sys.exit(1)
            if partial and infile.startswith('..'):
                continue
            cmd = ('grep', fr'^#define\s\+{name}\s\+', infile)
            with Popen(cmd, stdout=PIPE, stderr=PIPE) as proc:
                proc.communicate()
                if proc.returncode != 0:
                    fatal(f"Flag '{name}' does not exist in '{infile}'")
            FILES.add(infile)
            flag = {'name': name, 'file': infile}
            if flag not in flags:
                flags.append({'name': name, 'file': infile})
            else:
                printwrn(f"Flag '{name}' defined multiple times in '{filename}'")
    if not flags:
        print(f"No flags defined in '{filename}'")
    return flags


def validate_backend(backend):
    """
    Make sure `backend` is valid.
    Exit with an appropriate message on error.
    """
    backends = ('autotools', 'autotools-out-of-tree', 'cmake', 'meson')
    if backend not in backends:
        arg_error(f"Unknown backend '{backend}'")


def validate_indices(start, stop, total):
    """
    Make sure the `start` and `stop` index are valid.
    Exit with an appropriate message on error.
    """
    if start < 0:
        fatal(f'Start index {start} is smaller than zero')
    if stop < 0:
        fatal(f'Stop index {stop} is smaller than zero')
    if start > stop:
        fatal(f'Start index {start} is bigger than stop index {stop}')
    if start >= total:
        fatal(f'Start index {start} is bigger than number of combinations {total-1}')
    if stop >= total:
        fatal(f'Stop index {stop} is bigger than number of combinations {total-1}')


def print_estimated_runtime(flags, start, stop, opts):
    """Print the estimated runtime in days, hours, minutes and seconds."""
    actions = opts['actions']
    if stop == start:
        # A single combination to test, print nothing
        return

    length = len(flags)

    if '-J' in actions:
        total = 2 * length
    elif '-S1' in actions:
        total = 1 + length
    elif '-S2' in actions:
        total = int(length * (length + 1) / 2 + 1)
    else:
        total = stop - start + 1

    msg = '{}: {} flags, {} combinations{}'
    plugin = opts['filename'].split('/')[-1].split('.')[0]
    print(msg.format(plugin, length, total, (' left.' if start > 0 else '.')))

    # Estimated runtime (based on a 1s execution time)
    days = int(total / 3600. / 24.)
    hours = int(total / 3600. - days * 24)
    minutes = int(total / 60. - hours * 60 - days * 24 * 60)
    seconds = int(total - minutes * 60 - hours * 3600 - days * 24 * 3600)
    seconds = int(total % 60.)

    msg = 'Estimated runtime: {} days {} hours {} minutes and {} seconds.\n'
    print(msg.format(days, hours, minutes, seconds))
    if days > 0:
        # let it sink in...
        time.sleep(2)


def sigint_handler(_signalnum, _frame):
    """Called when the INT or TERM signal is received."""
    cleanup()
    list_all_errors()
    sys.exit(1)


def setup_signal_handlers():
    """Setup signal handlers for INT and TERM signals."""
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)


def validate_next_arg(arg, next_arg):
    """Make sure `next_arg exists`. Print an appropriate error message and exit if it does not."""
    if not next_arg:
        missing_arg_error(arg)


def validate_next_arg_numeric(arg, next_arg):
    """Make sure `next_arg` exists. Print an appropriate error message and exit if it does not."""
    if not next_arg:
        numeric_arg_error(arg)


def parse_next_arg_numeric(a, next_arg):
    """
    Parse `next_arg` as an int and return the result.
    Print an appropriate error message and exit if the operation failed.
    """
    result = 0
    try:
        result = int(next_arg, 0)
    except ValueError:
        numeric_arg_error(a)
    return result


def validate_args(opts):
    """Make sure the combinations of command line options provided is valid."""
    if 'filename' not in opts:
        arg_error("Option '-f' or plugin name is required")

    if not os.path.isfile(opts['filename']):
        fatal(f"File '{opts['filename']}' does not exist")

    if all(k in opts['actions'] for k in ('-J', '-S1', '-S2')):
        fatal("Cannot use '-J', '-S1' and '-S3' options at the same time")

    s_or_j_opt = any(k in opts['actions'] for k in ('-J', '-S1', '-S2'))
    if s_or_j_opt and any(k in opts for k in ('start', 'stop')):
        fatal("Cannot use '-b', '-s' or '-c' option with '-J', '-S1' or '-S2'")

    # If -R option was not passed, only rebuild the plugin under test
    if '-R' not in autogen['opts']:
        plugin = os.path.basename(opts['filename']).split('.')[0]
        autogen['opts'].append(plugin)


def check_dependencies(opts):
    """Check for required dependencies (sed, tranalyzer, valgrind)."""
    if not sed['exec']:
        fatal('Could not find sed/gsed executable')
    plugin = os.path.basename(opts['filename']).split('.')[0]
    if opts['require_t2'] and plugin != 'tranalyzer2' and not os.path.isfile(t2['exec']):
        fatal(f"Tranalyzer executable not found in {os.path.dirname(t2['exec'])}")
    if '-m' in opts['actions'] or '-i' in opts['actions']:
        if not valgrind['exec']:
            fatal('Could not find valgrind executable')


def parse_args(args):
    """Parse command line arguments."""
    global FATAL_ERR
    global IGNORE_ERROR
    global IGNORE_WARNING
    global SILENT
    global VERBOSE_ERR
    global VERBOSE_OUT

    opts = {
        'actions': [],
        'require_t2': False
    }

    skip_next = False
    argc = len(args)

    for i, a in enumerate(args):
        if a in ('-?', '-h', '--help'):
            usage()
            sys.exit(0)
        if i == 0 or skip_next:
            skip_next = False
            continue
        next_arg = args[i + 1] if ((i + 1) < argc) else None
        if a in ('-f', '--file'):
            validate_next_arg(a, next_arg)
            opts['filename'] = next_arg
            skip_next = True
        elif a in ('-p', '--plugin-folder'):
            validate_next_arg(a, next_arg)
            set_plugin_folder(next_arg)
            skip_next = True
        elif a in ('-P', '--pcap'):
            validate_next_arg(a, next_arg)
            set_pcap_file(next_arg)
            skip_next = True
        elif a in ('-o', '--output-prefix'):
            validate_next_arg(a, next_arg)
            set_output_prefix(next_arg)
            skip_next = True
        elif a in ('-b', '--resume', '--begin'):
            validate_next_arg_numeric(a, next_arg)
            opts['start'] = parse_next_arg_numeric(a, next_arg)
            skip_next = True
        elif a in ('-s', '--stop'):
            validate_next_arg_numeric(a, next_arg)
            opts['stop'] = parse_next_arg_numeric(a, next_arg)
            skip_next = True
        elif a in ('-c', '--check'):
            validate_next_arg_numeric(a, next_arg)
            opts['start'] = opts['stop'] = parse_next_arg_numeric(a, next_arg)
            skip_next = True
        elif a in ('-e', '--no-error'):
            IGNORE_ERROR = True
        elif a in ('-W', '--no-warning'):
            IGNORE_WARNING = True
        elif a in ('-F', '--fatal'):
            FATAL_ERR = True
        elif a in ('-n', '--silent'):
            SILENT = True
        elif a in ('-v', '--verbose-err'):
            VERBOSE_ERR = True
        elif a in ('-vv', '--verbose'):
            VERBOSE_OUT = True
            VERBOSE_ERR = True
        elif a in ('-J', '--johnson'):
            opts['actions'].append('-J')
        elif a in ('-S1', '--shift-1'):
            opts['actions'].append('-S1')
        elif a in ('-S2', '--shift-2'):
            opts['actions'].append('-S2')
        elif a in ('-T', '--no-parent-flags'):
            opts['-T'] = True
        elif a in ('-w', '--warnings'):
            opts['actions'].append('-w')
        elif a in ('-t', '--runtime'):
            opts['require_t2'] = True
            opts['actions'].append('-t')
        elif a in ('-m', '--memory'):
            opts['require_t2'] = True
            opts['actions'].append('-m')
        elif a in ('-i', '--invalid-rw'):
            opts['require_t2'] = True
            opts['actions'].append('-i')
        elif a in ('-d', '--debug', '-R', '--rebuild', '-X', '--bypass-lock', '-r', '--configure'):
            autogen['opts'].append(a)
        elif a in ('-B', '--backend'):
            validate_next_arg(a, next_arg)
            backend = next_arg
            validate_backend(backend)
            autogen['opts'].extend([a, backend])
            skip_next = True
        else:
            plugin = a.rstrip('/')
            if plugin == 'tranalyzer2':
                plugin_home = os.path.join(T2HOME, plugin)
            else:
                plugin_home = os.path.join(T2PLHOME, plugin)
                autogen_sh = os.path.join(plugin_home, 'autogen.sh')
                if not os.path.isfile(autogen_sh):
                    arg_error(f"Unknown option '{plugin}'")
            filename = os.path.join(plugin_home, 'tests', plugin + '.flags')
            opts['filename'] = filename

    validate_args(opts)
    check_dependencies(opts)

    return opts


def main():
    """Program entry point."""
    global FLAGS

    opts = parse_args(sys.argv)

    # for now, work from the plugin root directory
    path = os.path.join(os.path.dirname(opts['filename']), '..')
    path = os.path.normpath(path)
    if not os.path.isdir(os.path.join(path, 'tests')):
        fatal(f"No 'tests' folder found in '{path}'")
    os.chdir(path)

    FLAGS = read_file(opts['filename'], '-T' in opts)
    total = 1 << len(FLAGS)
    start = opts.get('start', 0)
    stop = opts.get('stop', total - 1)
    validate_indices(start, stop, total)
    print_estimated_runtime(FLAGS, start, stop, opts)

    setup_signal_handlers()

    backup_files(FILES)

    if total > 1:
        toggle(FLAGS, start, stop, opts['actions'])
    else:
        build_plugin_and_run(FLAGS, None, opts['actions'])

    list_all_errors()

    cleanup()


if __name__ == '__main__':
    main()
