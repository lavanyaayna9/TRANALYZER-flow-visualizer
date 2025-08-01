#!/usr/bin/env python3

import csv
import json
import socket
import subprocess

from os import makedirs
from os.path import dirname, isdir, isfile, join, normpath, realpath
from typing import Any, Dict, List, Union


class T2Utils:

    """Simple wrapper around Tranalyzer2 scripts and utilities."""

    T2HOME: str = normpath(join(dirname(realpath(__file__)), '..', '..'))
    """The path to Tranalyzer home folder."""

    T2PLHOME: str = join(T2HOME, 'plugins')
    """The path to Tranalyzer plugins folder, i.e., `$T2HOME/plugins`."""

    T2BUILD: str = join(T2HOME, 'autogen.sh')
    """The path to the `autogen.sh` script, i.e., `$T2HOME/autogen.sh`."""

    T2CONF: str = join(T2HOME, 'scripts', 't2conf', 't2conf')
    """The path to the `t2conf` script, i.e., `$T2HOME/scripts/t2conf/t2conf`."""

    T2FM: str = join(T2HOME, 'scripts', 't2fm', 't2fm')
    """The path to the `t2fm` script, i.e., `$T2HOME/scripts/t2fm/t2fm`."""

    T2PLUGIN: str = join(T2HOME, 'scripts', 't2plugin')
    """The path to the `t2plugin` script, i.e., `$T2HOME/scripts/t2plugin`."""

    TAWK: str = join(T2HOME, 'scripts', 'tawk', 'tawk')
    """The path to the `tawk` script, i.e., `$T2HOME/scripts/tawk/tawk`."""

    _all_plugins: List[str] = None

    @staticmethod
    def t2_exec(
            debug: bool = False
    ) -> str:
        """Return the path to Tranalyzer2 release or debug executable.

        Parameters
        ----------
        debug : bool, default: False

                - If `True`, returns the path to the debug executable.
                - If `False`, returns the path to the release executable.

        Returns
        -------
        str
            The path to Tranalyzer2 executable.

        Examples
        --------
        >>> T2Utils.t2_exec()
        /home/user/tranalyzer2-0.9.0/tranalyzer2/build/tranalyzer
        >>> T2Utils.t2_exec(debug=True)
        /home/user/tranalyzer2-0.9.0/tranalyzer2/debug/tranalyzer
        """
        folder: str = 'debug' if debug else 'build'
        return join(T2Utils.T2HOME, 'tranalyzer2', folder, 'tranalyzer')

    @staticmethod
    def run_tranalyzer(
            pcap: str = None,
            iface: str = None,
            pcap_list: Union[str, List[str]] = None,
            output_prefix: str = None,
            log_file: bool = False,
            save_monitoring: bool = False,
            packet_mode: bool = False,
            plugin_folder: str = None,
            loading_list: str = None,
            plugins: List[str] = None,
            bpf: str = None,
            t2_exec: str = None,
            timeout: int = None,
            verbose: bool = False
    ):
        """Run Tranalyzer2.

        Parameters
        ----------
        pcap : str, default: None
            Path to a pcap file.

        iface : str, default: None
            Name of a network interface.

        pcap_list : str or list of str, default: None

            - Path to a list of pcap files, e.g., `'/tmp/myPcaps.txt'`.
            - Or list of path to pcap files, e.g., `['file1.pcap', 'file2.pcap']`.

        output_prefix : str, default: None
            If `None`, automatically derived from input.

        log_file : bool, default: False
            Save the final report in a `_log.txt` file.

        save_monitoring : bool, default: False
            Save the monitoring report in a `_monitoring.txt` file.

        packet_mode : bool, default: False
            Activate Tranalyzer2 packet mode.

        plugin_folder : str, default: None
            Path to the plugin folder.

        loading_list : str, default: None
            Path to a plugin loading list.

            If set, the `plugins` parameter is ignored.

        plugins : list of str, default: None
            The list of plugins to use.

            If `None`, load the plugins available in the plugin folder.

        bpf : str, default: None
            A BPF filter.

        t2_exec : str, default: None
            Path to the Tranalyzer2 executable.

            If `None`, use `T2Utils.t2_exec()`

        timeout : int, default: None
            Number of seconds after which to terminate the process.

            If `None`, run forever or until the end of file is reached.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        OSError
            If specified interface `iface` does not exist locally.

        RuntimeError
            If none or more than one input (`pcap`, `pcap_list`, `iface`) is specified.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        subprocess.TimeoutExpired
            If `timeout` was expired and its value reached.

        Examples
        --------
        >>> T2Utils.run_tranalyzer(pcap='/tmp/file.pcap', output_prefix='/tmp/')
        """
        if sum(bool(i) for i in (pcap, pcap_list, iface)) > 1:
            raise RuntimeError('Only one input (pcap, pcap_list, iface) may be specified')

        if not pcap and not iface and not pcap_list:
            raise RuntimeError('An input (pcap, pcap_list or iface) is required')

        if not t2_exec:
            t2_exec = T2Utils.t2_exec()

        if not t2_exec or not isfile(t2_exec):
            raise RuntimeError(f'Tranalyzer2 executable could not be found at {t2_exec}')

        cmd = [t2_exec]

        # Input arguments: -r pcap or -R pcap_list or -i iface
        if pcap:
            cmd.extend(['-r', pcap])
        elif pcap_list:
            if isinstance(pcap_list, list):
                T2Utils.create_pcap_list(pcap_list, '/tmp/pcap_list.txt')
                pcap_list = '/tmp/pcap_list.txt'
            cmd.extend(['-R', pcap_list])
        elif iface:
            if iface not in T2Utils.network_interfaces():
                raise OSError(f'Interface {iface} does not exist locally')
            cmd.extend(['-i', iface])

        # Output arguments: -w prefix / -l / -m / -s
        if output_prefix:
            cmd.extend(['-w', output_prefix])
        if log_file:
            cmd.append('-l')
        if save_monitoring:
            cmd.append('-m')
        if packet_mode:
            cmd.append('-s')

        # Optional arguments
        if not loading_list and plugins:
            loading_list = '/tmp/plugins.load'
            T2Utils.create_plugin_list(plugins, outfile=loading_list, verbose=verbose)
        if loading_list:
            cmd.extend(['-b', loading_list])
        if plugin_folder:
            cmd.extend(['-p', plugin_folder])
        if bpf:
            cmd.append(bpf)

        subprocess.run(cmd, capture_output=not verbose, check=True, timeout=timeout)

    @staticmethod
    def list_config(
            plugin: str
    ) -> List[str]:
        """List the configuration flags available for `plugin`.

        Parameters
        ----------
        plugin : str
            The name of a plugin

        Returns
        -------
        list of str
            The list of configuration flags available for the plugin.

        Raises
        ------
        NameError
            If the plugin could not be found.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        Notes
        -----
        Equivalent to: `$ t2conf pluginName -I`.

        Examples
        --------
        >>> T2Utils.list_config('arpDecode')
        ['MAX_IP']
        """
        if plugin not in T2Utils.valid_plugin_names():
            raise NameError(f'Plugin {plugin} could not be found')
        cmd = [T2Utils.T2CONF, '-y', plugin, '-I']
        config = subprocess.run(cmd, text=True, check=True, stdout=subprocess.PIPE).stdout.strip()
        all_flags = config.split('\n') if config else []
        flags = [f.strip() for f in all_flags]
        if len(flags) == 1 and flags[0] == f'No configuration flags found for {plugin}':
            flags = []
        return flags

    @staticmethod
    def get_config(
            plugin: str,
            name: str,
            infile: str = None
    ) -> Any:
        """Get the value of a define from a configuration or header file.

        Parameters
        ----------
        plugin : str
            The name of a plugin.

        name : str
            The name of a configuration flag.

        infile : str, default: None
            Specify from which file (absolute path) to get the value from, e.g.,
            `'$T2PLHOME/pluginName/pluginName.cfg'`.

            Use the special value `'default'` to get the value from `default.config`.

            If `'source'` or `None`, get the value from the header file.

        Raises
        ------
        NameError
            If the plugin could not be found.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        See Also
        --------
        T2Utils.get_config_from_source : Alias for `T2Utils.get_config(plugin, name, 'source')`
        T2Utils.get_default : Alias for `T2Utils.get_config(plugin, name, 'default')`.

        Notes
        -----
        Equivalent to: `$ t2conf pluginName -G name [-g infile]`.

        Examples
        --------
        >>> T2Utils.get_config('arpDecode', 'MAX_IP')
        10
        """
        if plugin not in T2Utils.valid_plugin_names():
            raise NameError(f'Plugin {plugin} could not be found')
        cmd = [T2Utils.T2CONF, '-y', plugin, '-G', name]
        if infile and infile != 'source':
            cmd.extend(['-g', infile])
        config = subprocess.run(cmd, text=True, check=True, stdout=subprocess.PIPE).stdout
        val = config.split('=')[1].strip() if config else None
        if val:
            if val == 'no':
                val = 0
            elif val == 'yes':
                val = 1
            elif val.lstrip('-').isdigit():
                val = int(val)
            elif val.lstrip('-').replace('.', '', 1).isdigit():
                val = float(val)
            elif val.startswith('"'):
                val = val.strip('"')
            elif val.startswith("'"):
                val = val.strip("'")
        return val

    @staticmethod
    def get_default(
            plugin: str,
            name: str
    ) -> Any:
        """Get the default value of a define.

        Parameters
        ----------
        plugin : str
            The name of a plugin.

        name : str
            The name of a configuration flag.

        Raises
        ------
        NameError
            If the plugin could not be found.

        See Also
        --------
        T2Utils.get_config : Get the value of a define from a configuration or header file.
        T2Utils.get_config_from_source : Get the value of a define from a header file.

        Notes
        -----
        Equivalent to: `$ t2conf pluginName -G name -g default`.

        Alias for `T2Utils.get_config(plugin, name, infile='default')`.

        Examples
        --------
        >>> T2Utils.get_default('arpDecode', 'MAX_IP')
        10
        """
        return T2Utils.get_config(plugin, name, 'default')

    @staticmethod
    def get_config_from_source(
            plugin: str,
            name: str
    ) -> Any:
        """Get the value of a define from the header file, e.g., `pluginName.h`.

        Parameters
        ----------
        plugin : str
            The name of a plugin.

        name : str
            The name of a configuration flag.

        Raises
        ------
        NameError
            If the plugin could not be found.

        See Also
        --------
        T2Utils.get_config : Get the value of a define from a configuration or header file.
        T2Utils.get_default : Get the default value of a define.

        Notes
        -----
        Equivalent to: `$ t2conf pluginName -G name`.

        Alias for `T2Utils.get_config(plugin, name, infile='source')`.

        Examples
        --------
        >>> T2Utils.get_config_from_source('arpDecode', 'MAX_IP')
        10
        """
        return T2Utils.get_config(plugin, name, 'source')

    @staticmethod
    def set_config(
            plugin: str,
            flag_name: Union[str, Dict[str, Any]],
            flag_value: Any = None,
            outfile: str = None,
            verbose: bool = False
    ):
        """Set the value of a define in a configuration or header file.

        Parameters
        ----------
        plugin : str
            The name of a plugin.

        flag_name : str or dict of str, Any
            The name of the configuration flag to set or a dictionary of key/value to set.

        flag_value : Any, default: None
            The new value for `flag_name`.

            Use `'default'` to reset the value to its default.

            Not required if `flag_name` is a dictionary of key/value to set.

        outfile : str, default: None
            Use `'source'` to set the value in the header file.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        NameError
            If the plugin could not be found.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        Notes
        -----
        Equivalent to: `$ t2conf pluginName -D name1=value1 [-D name2=value2 ...] [-g outfile]`.

        Examples
        --------
        >>> T2Utils.set_config('arpDecode', 'MAX_IP', 25)
        """
        if plugin not in T2Utils.valid_plugin_names():
            raise NameError(f'Plugin {plugin} could not be found')

        name_val = {flag_name: flag_value} if isinstance(flag_name, str) else flag_name

        for name, value in name_val.items():
            current = T2Utils.get_config(plugin, name)
            # Make sure value is properly quoted
            if isinstance(current, str):
                if current[0] == '"' and current[-1] == '"':
                    if value[0] != '"':
                        value = '"' + value
                    if value[-1] != '"':
                        value += '"'
            cmd = [T2Utils.T2CONF, '-y', plugin, '-D', f'{name}={value}']
            if outfile and outfile != 'source':
                cmd.extend(['-g', outfile])
            subprocess.run(cmd, capture_output=not verbose, check=True)

    @staticmethod
    def set_default(
            plugin: Union[str, List[str]],
            name: Union[str, List[str]] = None,
            outfile: str = None,
            verbose: bool = False
    ):
        """Reset the value of a define to its default.

        Parameters
        ----------
        plugin : str or list of str
            `plugin` can be:

            - a single plugin, e.g., `'pluginName'`
            - a list of plugins, e.g., `['pluginName1', 'pluginName2']`
            - `all` to apply the operation to all available plugins

        name : str or list of str, default: None
            The name of a configuration flag to reset.

            If `name` is set, only reset the value for the specified flag(s).

        outfile : str, default: None
            Path to a configuration file where the changes will be rest.

            Use `outfile='source'` to set the value in the header file.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        NameError
            If a plugin could not be found.

        NotImplementedError
            If trying to reset specific flag(s) with multiple plugins.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        See Also
        --------
        T2Utils.set_config : Set the value of a define in a configuration or header file.
        T2Utils.reset_config : Reset all configuration flags from a plugin to their default values.

        Notes
        -----
        Equivalent to: `$ t2conf pluginName -D name=default [-g outfile]`.

        Alias for `T2Utils.set_config(plugin, name, 'default', outfile)`.

        Examples
        --------
        >>> T2Utils.set_default('arpDecode', 'MAX_IP')
        >>> T2Utils.set_default('basicStats', ['BS_VAR', 'BS_STDDEV'])
        >>> T2Utils.set_default(['arpDecode', 'basicStats'])
        """
        if name:
            if isinstance(plugin, list):
                raise NotImplementedError('Cannot reset specific flag(s) with list of plugins')

            if plugin == 'all':
                raise NotImplementedError("Cannot reset specific flag(s) for 'all' plugins")

            if isinstance(name, list):
                for n in name:
                    T2Utils.set_config(plugin, n, 'default', outfile=outfile, verbose=verbose)
            else:
                T2Utils.set_config(plugin, name, 'default', outfile=outfile, verbose=verbose)
        else:
            cmd = [T2Utils.T2CONF, '-y', '--reset']
            accept_outfile = False
            if plugin == 'all':
                cmd.append('-a')
            elif isinstance(plugin, list):
                cmd.extend(plugin)
            else:
                accept_outfile = True
                cmd.append(plugin)
            if outfile and outfile != 'source':
                if not accept_outfile:
                    raise NotImplementedError("Cannot reset configuration in specific file "
                                              "with list of plugins or 'all' plugins")
                cmd.extend(['-g', outfile])
            subprocess.run(cmd, capture_output=not verbose, check=True)

    @staticmethod
    def reset_config(
            plugin: Union[str, List[str]],
            name: Union[str, List[str]] = None,
            outfile: str = None,
            verbose: bool = False
    ):
        """Reset all configuration flags from a plugin to their default values.

        Parameters
        ----------
        plugin : str or list of str
            `plugin` can be:

            - a single plugin, e.g., `'pluginName'`
            - a list of plugins, e.g., `['pluginName1', 'pluginName2']`

        name : str, default: None
            The name of a configuration flag to reset.

            If `name` is set, only reset the value for the specified flag(s).

        outfile : str, default: None
            Path to a configuration file where the changes will be rest.

            Use `outfile='source'` to reset the value in the header file.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        NameError
            If a plugin could not be found.

        NotImplementedError
            If trying to reset specific flag(s) with multiple plugins.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        See Also
        --------
        T2Utils.set_default : Set the value of a define in a configuration or header file.

        Notes
        -----
        Equivalent to: `$ t2conf pluginName --reset [-g outfile]`.

        Alias for `T2Utils.set_default(plugin, None, outfile)`.

        Examples
        --------
        >>> T2Utils.reset_config('arpDecode')
        >>> T2Utils.reset_config('arpDecode', 'MAX_IP')
        >>> T2Utils.reset_config(['arpDecode', 'txtSink'])
        >>> T2Utils.reset_config('arpDecode', 'MAX_IP', '/tmp/arpDecode.config')
        """
        T2Utils.set_default(plugin, name, outfile=outfile, verbose=verbose)

    @staticmethod
    def generate_config(
            plugin: str,
            outfile: str = None,
            verbose: bool = False
    ):
        """Generate a configuration file for `plugin`.

        Parameters
        ----------
        plugin : str
            The name of a plugin.

        outfile : str, default: None
            The filename where to save the configuration.

            If `None`, default to `'pluginName.config'` in the plugin home folder.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        NameError
            If the plugin could not be found.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        See Also
        --------
        T2Utils.apply_config : Apply a configuration file to the sources.

        Notes
        -----
        Equivalent to: `$ t2conf pluginName -g [file]`.

        Examples
        --------
        >>> T2Utils.generate_config('arpDecode')
        >>> T2Utils.generate_config('arpDecode', '/tmp/arpDecode.config')
        """
        if plugin not in T2Utils.valid_plugin_names():
            raise NameError(f'Plugin {plugin} could not be found')
        cmd = [T2Utils.T2CONF, '-y', plugin, '-g']
        if outfile:
            cmd.append(outfile)
        subprocess.run(cmd, capture_output=not verbose, check=True)

    @staticmethod
    def apply_config(
            plugin: str,
            infile: str = None,
            verbose: bool = False
    ):
        """Apply a configuration file to the sources.

        Parameters
        ----------
        plugin : str
            The name of a plugin.

        infile : str, default: None
            The name of the configuration file to apply.

            If `None`, default to `'pluginName.config'` in the plugin home folder.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        NameError
            If the plugin could not be found.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        See Also
        --------
        T2Utils.generate_config : Generate configuration files for plugins

        Notes
        -----
        Equivalent to: `$ t2conf pluginName -C [file|auto]`.

        Examples
        --------
        >>> T2Utils.apply_config('arpDecode')
        >>> T2Utils.apply_config('arpDecode', '/tmp/arpDecode.config')
        """
        if plugin not in T2Utils.valid_plugin_names():
            raise NameError(f'Plugin {plugin} could not be found')
        cmd = [T2Utils.T2CONF, '-y', plugin, '-C']
        cmd.append(infile if infile else 'auto')
        subprocess.run(cmd, capture_output=not verbose, check=True)

    @staticmethod
    def build(
            plugin: Union[str, List[str]],
            plugin_folder: str = None,
            force_rebuild: bool = False,
            debug: bool = False,
            verbose: bool = False
    ):
        """Build a plugin or Tranalyzer2.

        Parameters
        ----------
        plugin : str or list of str
            `plugin` can be:

            - a single plugin, e.g., `'pluginName'`
            - a list of plugins, e.g., `['pluginName1', 'pluginName2']`
            - a plugin loading list, e.g., `'myPlugins.txt'`
            - `all` to apply the operation to all available plugins

        plugin_folder : str, default: None
            Path to the plugin folder.

            If `None`, default to `'$HOME/.tranalyzer/plugins'`.

        force_rebuild : bool, default: False
            Force the rebuild of the configuration files (`$ t2build -r ...`).

        debug : bool, default: False
            Build the plugin(s) in debug mode.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        See Also
        --------
        T2Utils.clean : Remove files generated by `T2Utils.build()`.

        Notes
        -----
        Equivalent to:

        - `$ t2build pluginName`
        - `$ t2build pluginName1 pluginName2`
        - `$ t2build -b myPlugins.txt`
        - `$ t2build -b -a`

        Examples
        --------
        >>> T2Utils.build('arpDecode')
        >>> T2Utils.build(['arpDecode', 'txtSink'])
        >>> T2Utils.build('/tmp/myPlugins.load')
        >>> T2Utils.build('all')
        """
        cmd = [T2Utils.T2BUILD, '-y']
        if debug:
            cmd.append('-d')
        if force_rebuild:
            cmd.append('-r')
        if plugin_folder:
            cmd.extend(['-p', plugin_folder])
        if 'tranalyzer2' in plugin:
            cmd.append('-i')
        if plugin == 'all':
            cmd.append('-a')
        elif isinstance(plugin, list):
            cmd.extend(plugin)
        elif isfile(plugin):
            cmd.extend(['-b', plugin])
        else:
            cmd.append(plugin)
        subprocess.run(cmd, capture_output=not verbose, check=True)

    @staticmethod
    def clean(
            plugin: Union[str, List[str]],
            verbose: bool = False
    ):
        """Remove files generated by `T2Utils.build()`.

        Parameters
        ----------
        plugin : str or list of str
            `plugin` can be:

            - a single plugin, e.g., `'pluginName'`
            - a list of plugins, e.g., `['pluginName1', 'pluginName2']`
            - a plugin loading list, e.g., `'myPlugins.txt'`
            - `all` to apply the operation to all available plugins

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        See Also
        --------
        T2Utils.build : Build a plugin or Tranalyzer2.

        Notes
        -----
        Equivalent to:

        - `$ t2build -c pluginName`
        - `$ t2build -c pluginName1 pluginName2`
        - `$ t2build -c -b myPlugins.txt`
        - `$ t2build -c -a`

        Examples
        --------
        >>> T2Utils.clean('arpDecode')
        >>> T2Utils.clean(['arpDecode', 'txtSink'])
        >>> T2Utils.clean('/tmp/myPlugins.load')
        >>> T2Utils.clean('all')
        """
        cmd = [T2Utils.T2BUILD, '-y', '-c']
        if plugin == 'all':
            cmd.append('-a')
        elif isinstance(plugin, list):
            cmd.extend(plugin)
        elif isfile(plugin):
            cmd.extend(['-b', plugin])
        else:
            cmd.append(plugin)
        subprocess.run(cmd, capture_output=not verbose, check=True)

    @staticmethod
    def unload(
            plugin: Union[str, List[str]],
            plugin_folder: str = None,
            verbose: bool = False
    ):
        """Remove (unload) a plugin from the plugin folder.

        Parameters
        ----------
        plugin : str or list of str
            `plugin` can be:

            - a single plugin, e.g., `'pluginName'`
            - a list of plugins, e.g., `['pluginName1', 'pluginName2']`
            - a plugin loading list, e.g., `'myPlugins.txt'`
            - `all` to apply the operation to all available plugins

        plugin_folder : str, default: None
            The plugin folder from where the plugin must be unloaded.

            If `None`, use the default plugin folder (`'$HOME/.tranalyzer/plugins'`).

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        Notes
        -----
        Equivalent to:
            - `$ t2build -u pluginName`
            - `$ t2build -u pluginName1 pluginName2`
            - `$ t2build -u -b myPlugins.txt`
            - `$ t2build -u -a`

        Examples
        --------
        >>> T2Utils.unload('arpDecode')
        >>> T2Utils.unload(['arpDecode', 'txtSink'])
        >>> T2Utils.unload('/tmp/myPlugins.load')
        >>> T2Utils.unload('all')
        """
        cmd = [T2Utils.T2BUILD, '-y', '-u']
        if plugin_folder:
            cmd.extend(['-p', plugin_folder])
        if plugin == 'all':
            cmd.append('-a')
        elif isinstance(plugin, list):
            cmd.extend(plugin)
        elif isfile(plugin):
            cmd.extend(['-b', plugin])
        else:
            cmd.append(plugin)
        subprocess.run(cmd, capture_output=not verbose, check=True)

    @staticmethod
    def plugin_description(
            plugin: str
    ) -> str:
        """Return a short description of a plugin.

        Parameters
        ----------
        plugin : str
            The name of a plugin.

        Returns
        -------
        str
            The description of the plugin.

        Raises
        ------
        NameError
            If the plugin could not be found.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        Notes
        -----
        Equivalent to: `$ t2plugin -l | awk '$1 == "plugin" { sub("^" $1 FS "+" $2 FS "+", "");
                                             print }'`.

        Examples
        --------
        >>> T2Utils.plugin_description('arpDecode')
        'Address Resolution Protocol (ARP)'
        """
        if plugin not in T2Utils.valid_plugin_names():
            raise NameError(f'Plugin {plugin} could not be found')
        cmd = [T2Utils.T2PLUGIN, '-l']
        out = subprocess.run(cmd, text=True, check=True, stdout=subprocess.PIPE).stdout
        for line in out.splitlines():
            cols = line.split()
            if len(cols) > 2 and cols[0] == plugin:
                return ' '.join(cols[2:])
        return None

    @staticmethod
    def plugin_number(
            plugin: str
    ) -> str:
        """Return the plugin number of a plugin.

        Parameters
        ----------
        plugin : str
            The name of a plugin.

        Returns
        -------
        str
            The plugin number.

        Raises
        ------
        NameError
            If the plugin could not be found.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        Notes
        -----
        Equivalent to: `$ t2plugin -l | awk '$1 == "pluginName" { print $2; exit }'`

        Examples
        --------
        >>> T2Utils.plugin_number('arpDecode')
        '179'
        """
        if plugin not in T2Utils.valid_plugin_names():
            raise NameError(f'Plugin {plugin} could not be found')
        cmd = [T2Utils.T2PLUGIN, '-l']
        out = subprocess.run(cmd, text=True, check=True, stdout=subprocess.PIPE).stdout
        for line in out.splitlines():
            cols = line.split()
            if len(cols) > 2 and cols[0] == plugin:
                return cols[1]
        return None

    @staticmethod
    def plugins(
            category: Union[str, List[str]] = None
    ) -> List[str]:
        """Alphabetically List all the available plugins.

        Parameters
        ----------
        category : str or list of str, default: None
            `category` can be used to specify the types of plugins to list:

            - `'g'` : global
            - `'b'` : basic
            - `'l2'`: layer 2
            - `'l4'`: layer 3/4
            - `'l7'`: layer 7
            - `'a'` : application
            - `'m'` : math
            - `'c'` : classifier
            - `'o'` : output
            - `None`: all

        Returns
        -------
        list of str
            List of all available plugins.

        Raises
        ------
        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        Examples
        --------
        >>> T2Utils.plugins()
        >>> T2Utils.plugins('g')
        ['protoStats']
        >>> T2Utils.plugins(['g', 'l2'])
        ['arpDecode', 'cdpDecode', 'lldpDecode', 'protoStats', 'stpDecode', 'vtpDecode']
        """
        cmd = [T2Utils.T2PLUGIN, '-H', '-N']
        if isinstance(category, list):
            for c in category:
                cmd.append(f'-l={c}')
        elif category:
            cmd.append(f'-l={category}')
        elif T2Utils._all_plugins:
            return T2Utils._all_plugins
        else:
            cmd.append('-l')
        out = subprocess.run(cmd, text=True, check=True, stdout=subprocess.PIPE).stdout
        sorted_list = sorted(out.splitlines())
        if not category:
            T2Utils._all_plugins = sorted_list
        return sorted_list

    @staticmethod
    def list_plugins(
            infile: str = None
    ) -> List[str]:
        """List the active plugins in `infile`.

        Parameters
        ----------
        infile : str, default: None
            Name of a plugin loading list.

            If `None`, default to `'plugins.load'` in the plugin folder.

        Returns
        -------
        list of str
           List of active plugins in `infile`.

        Raises
        ------
        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        Notes
        -----
        Equivalent to: `$ t2conf -S [file]`.

        Examples
        --------
        >>> T2Utils.list_plugins()
        ['arpDecode', 'txtSink']
        >>> T2Utils.list_plugins('/tmp/myPlugins.load')
        ['arpDecode', 'txtSink']
        """
        cmd = [T2Utils.T2CONF, '-y', '-S']
        if infile:
            cmd.append(infile)
        out = subprocess.run(cmd, text=True, check=True, stdout=subprocess.PIPE).stdout
        return sorted(out.splitlines())

    @staticmethod
    def create_pcap_list(
            pcaps: List[str],
            outfile: str = None
    ):
        """Create a loading list of pcaps.

        Parameters
        ----------
        pcaps : list of str
            List of pcap files.

        outfile : str, default: None
            Name of the file to save.

            If `None`, default to `/tmp/pcap_list.txt'`.

        Notes
        -----
        Equivalent to: `$ t2caplist pcaps > outfile`.

        Examples
        --------
        >>> T2Utils.create_pcap_list(['file1.pcap', 'file2.pcap'])
        >>> T2Utils.create_pcap_list(['file1.pcap', 'file2.pcap'], '/tmp/myPcaps.txt')
        """
        if not outfile:
            outfile = '/tmp/pcap_list.txt'
        with open(outfile, 'w', encoding='utf-8') as f:
            for pcap in pcaps:
                f.write(pcap + '\n')

    @staticmethod
    def create_plugin_list(
            plugins: List[str],
            outfile: str = None,
            verbose: bool = False
    ):
        """Create a loading list of plugins.

        Parameters
        ----------
        plugins : list of str
            List of plugin names.

        outfile : str, default: None
            Name of the file to save.

            If `None`, default to `'plugins.load'` in the plugin folder.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        subprocess.CalledProcessError
            If the process exited with a non-zero exit code (if `plugins is not None`).

        Notes
        -----
        Equivalent to: `$ t2conf -L plugin1 plugin2 ...`.

        Examples
        --------
        >>> T2Utils.create_plugin_list(['arpDecode', 'txtSink'])
        >>> T2Utils.create_plugin_list(['arpDecode', 'txtSink'], '/tmp/myPlugins.txt')
        """
        if outfile:
            directory = dirname(outfile)
            if not isdir(directory):
                makedirs(directory)
            # simpler format, only active plugins
            with open(outfile, 'w', encoding='utf-8') as f:
                for plugin in plugins:
                    f.write(plugin + '\n')
        else:
            cmd = [T2Utils.T2CONF, '-y', '-L']
            cmd.extend(plugins)
            subprocess.run(cmd, capture_output=not verbose, check=True)

    @staticmethod
    def tawk(
            program: str = None,
            filename: str = None,
            options: List[str] = None
    ) -> str:
        """Call `tawk` with the `program`, `options` and `filename` specified.

        Parameters
        ----------
        program : str, default: None
            A `tawk` program, e.g., `"$dstPort == 80 { print tuple5() }"`.

        filename : str, default: None
            Name of the file to analyze.

        options : list of str, default: None
            List of options to pass to `tawk`.

        Returns
        -------
        str
            The result of the `tawk` command.

        Raises
        ------
        RuntimeError
            If `filename` was specified, but the file does not exist.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        Notes
        -----
        Equivalent to: `$ tawk [options] 'program' filename`.

        Examples
        --------
        >>> result = T2Utils.tawk(None, None, ['-V', 'flowStat=0x1234'])
        >>> print(result)
        >>> T2Utils.tawk('host("1.2.3.4") { aggr(proto()) }', 'file.txt')
        """
        if filename and not isfile(filename):
            raise RuntimeError(f"Input file '{filename}' does not exist")
        cmd = [T2Utils.TAWK]
        if program:
            cmd.append(program)
        if options:
            cmd.extend(options)
        if filename:
            cmd.append(filename)
        result = subprocess.run(cmd, capture_output=True, check=True)
        result = result.stdout.decode('utf8').strip()
        return result

    @staticmethod
    def follow_stream(
            filename: str,
            flow: int,
            output_format: Union[int, str] = 2,
            direction: str = None,
            payload_format: Union[int, str] = 4,
            reassembly: bool = True,
            colors: bool = True
    ) -> Union[str, List[str], List[bytearray], List[Dict[str, Any]]]:
        """Call `tawk` `follow_stream()` function with the specified options.

        Return the reassembled payload of flow with index `flow` and direction `direction`.

        Parameters
        ----------
        filename : str
            Name of the file to analyze.

        flow : int
            Index (`flowInd`) of the flow to analyze.

        output_format : int or str, default: 2
            The format to use for the output:

            - 0 or `'payload_only'`
            - 1 or `'info'`: Prefix each payload with packet/flow info
            - 2 or `'json'`
            - 3 or `'reconstruct'`

        direction : str, default: None
            The direction to follow (`'A'` or `'B'`).

            Use `None` to follow both directions.

        payload_format : int or str, default: 4
            The format to use for the payload:

            - 0 or 'ascii'
            - 1 or 'hexdump'
            - 2, 'raw' or 'binary'
            - 3 or 'base64'
            - 4 or 'bytearray'

        reassembly : bool, default: True
            Analyze TCP sequence numbers, reassemble and reorder TCP segments.

        colors : bool, default: True
            Output colors.

        Returns
        -------
        list of bytearray
            If `output_format` is 0 or 2 and `payload_format` is 4 or `'bytearray'`.

        list of dict
            If `output_format` is 2.

        list of str
            If `output_format` is 0 and `payload_format` is not 4 or `'bytearray'`.

        str
            If none of the above applied.

        Raises
        ------
        RuntimeError

            - If `filename` could not be found.
            - If `output_format` or `payload_format` was out of bound.
            - If `direction` was not `'A'`, `'B'` or `None`.
            - If `output_format` was 3 or `'reconstruct'` and `direction` was not `'A'` or `'B'`.
            - If `payload_format` was 4 or `'bytearray'` and `output_format` was 1 or `'info'`.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        See Also
        --------
        T2Utils.tawk : Call `tawk` with the `program`, `options` and `filename` specified.

        Notes
        -----
        Equivalent to: `$ tawk 'follow_stream(flow, output_format, direction, payload_format,
                                              not reassembly, not colors)' filename`.

        Examples
        --------
        >>> result = T2Utils.follow_stream(1, payload_format='hexdump', direction='B')
        >>> print(result)
        """
        if not filename:
            raise RuntimeError("Input file != None is required")

        if direction:
            if direction not in ('A', 'B'):
                raise RuntimeError(f"Invalid value for 'direction' parameter: '{direction}'")
            direction = f'"{direction}"'

        if output_format in (0, 'payload_only'):
            output_format = 0
        elif output_format in (1, 'info'):
            output_format = 1
        elif output_format in (2, 'json'):
            output_format = 2
        elif output_format in (3, 'reconstruct'):
            output_format = 3
        else:
            raise RuntimeError(f"Invalid value for 'output_format' parameter: '{output_format}'")

        if output_format == 3 and direction is None:
            raise RuntimeError("Payload reconstruction (output format 3 or 'reconstruct') "
                               "requires a direction ('A' or 'B').")

        if payload_format in (0, 'ascii'):
            payload = 0
        elif payload_format in (1, 'hexdump'):
            payload = 1
        elif payload_format in (2, 'raw', 'binary'):
            payload = 2
        elif payload_format in (4, 'bytearray'):
            if output_format == 1:
                raise RuntimeError("'payload_format' 4 or 'bytearray' cannot be specified with "
                                   "'output_format' 1 or 'info'")
            payload = 2
            colors = False
        elif payload_format in (3, 'base64'):
            payload = 3
        else:
            raise RuntimeError(f"Invalid value for 'payload_format' parameter: '{payload_format}'")

        prog = (
            'follow_stream('
            f'{flow},'
            f'{output_format},'
            f'{direction if direction else 0},'
            f'{payload},'
            f'{0 if reassembly else 1},'
            f'{0 if colors else 1}'
            ')'
        )

        result = T2Utils.tawk(prog, filename)
        if output_format == 0:
            result = result.split('\n') if result else []
        elif output_format == 2:
            result = result.split('\n') if result else []
            result = [json.loads(s) if s else {} for s in result]

        if payload_format in (4, 'bytearray'):
            if output_format == 3:
                result = bytearray.fromhex(result)
            elif output_format == 0:
                result = [bytearray.fromhex(s) for s in result]
            elif output_format == 2:
                for packet in result:
                    packet['payload'] = bytearray.fromhex(packet['payload'])

        return result

    @staticmethod
    def load_plugins(
            plugin: Union[str, List[str]] = None
    ):
        """Load plugins as `T2Plugin` objects.

        The plugins will be available as, e.g., `T2Utils.pluginName`.

        Parameters
        ----------
        plugin : str or list of str, default: None
            Name of the plugin(s) to load.

            `plugin` can be:

            - a plugin name
            - a list of plugin names
            - `None` or 'all' (slow)

        Raises
        ------
        NameError
            If a plugin could not be found.

        Examples
        --------
        >>> T2Utils.load_plugins('arpDecode')
        >>> T2Utils.load_plugins(['arpDecode', 'txtSink'])
        >>> T2Utils.load_plugins()
        >>> T2Utils.arpDecode
        <t2py.T2Plugin.T2Plugin object at 0x16055a370>
        """
        from .T2Plugin import T2Plugin
        all_plugins = T2Utils.valid_plugin_names()
        if isinstance(plugin, list):
            plugins = plugin
        elif not plugin or plugin == 'all':
            plugins = all_plugins
        else:
            plugins = [plugin]
        for p in plugins:
            if p not in all_plugins:
                raise NameError(f'Plugin {p} could not be found')
            setattr(T2Utils, p, T2Plugin(p))

    @staticmethod
    def _tsv_to_list(
            filename: str,
            delimiter: str = '\t'
    ) -> List[Dict[str, Any]]:
        """Convert a tsv/csv file to a python list of JSON objects.

        Parameters
        ----------
        filename : str
            The name of the file to load.

        delimiter : str, default: '\\t'
            The delimiter used to separate columns in the input file.

        Returns
        -------
        list of dict
            A list of dictionary, whose entries are the column names and their associated values.
        """
        data = []
        with open(filename, encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=delimiter)
            reader.fieldnames[0] = reader.fieldnames[0].lstrip('%').strip()
            for flow in reader:
                data.append(flow)
        return data

    @staticmethod
    def to_json_array(
            infile: str,
            delimiter: str = '\t'
    ) -> List[Dict[str, Any]]:
        """Convert a flow or packet file to an array of JSON objects.

        Parameters
        ----------
        infile : str
            Path to a flow or packet file.

        delimiter : str, default: '\\t'
            Field delimiter used in the input file.

        Returns
        -------
        list of dict
            The list of rows contained in `infile`.

            Each row is represented as a dict with the column names as key.

        Raises
        ------
        json.decoder.JSONDecodeError
            If `infile` was a JSON file and the decoding process failed.

        Examples
        --------
        >>> flows = T2Utils.to_json_array('/tmp/file_flows.txt')
        >>> flows
        [{'dir': 'A', 'flowInd': 1, ...}, {'dir': 'B', 'flowInd': 1, ...}, ...]
        """
        data = []
        if not infile.endswith('.json'):
            data = T2Utils._tsv_to_list(infile, delimiter)
        else:
            with open(infile, encoding='utf-8') as f:
                for flow in f:
                    if flow in ('[\n', ']\n'):
                        continue
                    data.append(json.loads(flow.strip(',')))
        return data

    @staticmethod
    def to_pandas(
            infile: str,
            delimiter: str = None
    ) -> "pandas.core.frame.DataFrame":
        """Convert a flow or packet file to pandas `DataFrame`.

        Parameters
        ----------
        infile : str
            Path to a flow or packet file.

        delimiter : str, default: None
            Field delimiter used in the input file.

        Returns
        -------
        pd.DataFrame
            DataFrame holding the tabular data stored in `infile`.

        Examples
        --------
        >>> df = T2Utils.to_pandas('/tmp/file_flows.txt')
        >>> type(df)
        <class 'pandas.core.frame.DataFrame'>
        """
        import pandas as pd
        if infile.endswith('.json'):
            return pd.DataFrame(T2Utils.to_json_array(infile))
        return pd.read_table(infile, delimiter=delimiter)

    @staticmethod
    def to_pdf(
            pcap: str = None,
            flow_file: str = None,
            prefix: str = None,
            config: bool = True,
            reset_config: bool = True,
            open_pdf: bool = False,
            verbose: bool = False
    ):
        """Generate a PDF/LaTeX report from a PCAP or Tranalyzer flow file."

        Parameters
        ----------
        pcap : str, default: None
            PCAP file to analyze.

        file : str, default: None
            Flow file to analyze.

        prefix : str, default: None
            Append 'prefix' to any output file produced.

        config : bool, default: True
            If `True`, configure and build Tranalyzer2 and the plugins as required.

        reset_config : bool, default: True
            If `True`, reset tranalyzer2 and the plugins configuration at the end.

        open_pdf : bool, default: False
            If `True`, automatically open the generated PDF.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        RuntimeError

            - If one of the required parameter (pcap or flow_file) was not specified.
            - If multiple inputs (pcap and flow_file) were specified.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        Notes
        -----
        Equivalent to: `$ t2fm [-b] [-A] [-r pcap|-F file]`.

        Examples
        --------
        >>> T2Utils.to_pdf(pcap='file.pcap')
        >>> T2Utils.to_pdf(flow_file='file_flows.txt')
        """
        if not pcap and not flow_file:
            raise RuntimeError('One of (pcap, flow_file) must be specified.')

        if pcap and flow_file:
            raise RuntimeError('Only one of (pcap, flow_file) must be specified.')

        cmd = [T2Utils.T2FM, '-y']
        # Input
        if pcap:
            cmd.extend(['-r', pcap])
        elif flow_file:
            cmd.extend(['-F', flow_file])
        # Output
        if prefix:
            cmd.extend(['-w', prefix])
        # Options
        if config:
            cmd.append('-b')
        if reset_config:
            cmd.append('--reset')
        if open_pdf:
            cmd.append('-A')
        subprocess.run(cmd, capture_output=not verbose, check=True)

    @staticmethod
    def network_interfaces() -> List[str]:
        """List the names of all available network interfaces.

        Returns
        -------
        list of str
            The list of available network interfaces.

        Examples
        --------
        >>> T2Utils.network_interfaces()
        ['lo0', 'eth0']
        """
        return [iface[1] for iface in socket.if_nameindex()]

    @staticmethod
    def valid_plugin_names() -> List[str]:
        """Return a list of valid plugin names.

        Returns
        -------
        list of str
            The list of valid plugin names.

        Examples
        --------
        >>> T2Utils.valid_plugin_names()
        ['arpDecode', ..., 'tranalyzer2', ...]
        """
        valid_plugins = ['tranalyzer2']
        valid_plugins.extend(T2Utils.plugins())
        return sorted(valid_plugins)
