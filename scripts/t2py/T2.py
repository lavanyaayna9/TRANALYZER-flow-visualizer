#!/usr/bin/env python3

import json
import socket
import threading
import time

from os import makedirs
from os.path import dirname, expanduser, isdir, isfile, join
from typing import Any, Dict, Iterator, List, Union

from .T2Plugin import T2Plugin
from .T2Utils import T2Utils


class T2:

    """Manage several `t2py.T2Plugin` objects and run T2, convert/display flow file, ...

    Parameters
    ----------
    pcap: str, default: None
        Path to a pcap file.

    iface: str, default: None
        Name of a network interface.

    pcap_list : str or list of str, default: None

        - Path to a list of pcap files, e.g., `'/tmp/myPcaps.txt'`.
        - Or list of path to pcap files, e.g., `['file1.pcap', 'file2.pcap']`.

    output_prefix: str, default: None
        If `None`, automatically derived from input.

    save_monitoring: bool, default: False
        Save the monitoring report in a `_monitoring.txt` file.

    packet_mode: bool, default: False
        Activate Tranalyzer2 packet mode.

    plugin_folder: str, default: None
        Path to the plugin folder.

        If `None`, default to `$HOME/.tranalyzer/plugins`.

    loading_list: str, default: None
        Path to a plugin loading list.

    plugins: list of str, default: None,
        A list of plugin names to load.

    output_format: str or list of str, default: None
        Select and configure the sink plugin(s) required to generate the requested output format.

        See also `T2.add_output_format()`.

    bpf: str, default: None
        A BPF filter.

    streaming: bool, default: False
        If `True`, then `T2.stream()` can be used to yield one flow at a time.

    Raises
    ------
    OSError
        If specified interface `iface` does not exist locally.

    RuntimeError
        If more than one input (`pcap`, `pcap_list`, `iface`) is specified.
    """

    plugin_folder: str = None
    """Path to the plugin folder. If `None`, default to `'$HOME/.tranalyzer/plugins'`."""

    def __init__(
            self,
            pcap: str = None,
            iface: str = None,
            pcap_list: Union[str, List[str]] = None,
            output_prefix: str = None,
            save_monitoring: bool = False,
            packet_mode: bool = False,
            plugin_folder: str = None,
            loading_list: str = None,
            plugins: List[str] = None,
            output_format: Union[str, List[str]] = None,
            bpf: str = None,
            streaming: bool = False
    ):

        if sum(bool(i) for i in (pcap, pcap_list, iface)) > 1:
            raise RuntimeError('Only one input (pcap, pcap_list, iface) may be specified')

        if iface and iface not in T2Utils.network_interfaces():
            raise OSError(f'Interface {iface} does not exist locally')

        # Private variables
        self._whitelisted_plugins = []
        self._default_plugin_folder = None
        self._tranalyzer2 = None
        self._plugins = {}
        self._conn = None
        self._streaming = False

        # Input
        self.pcap = pcap
        self.iface = iface
        self.pcap_list = pcap_list

        # Output
        self.output_prefix = output_prefix
        self.save_monitoring = save_monitoring
        self.packet_mode = packet_mode

        # Options
        self.bpf = bpf
        self.plugin_folder = plugin_folder
        self.loading_list = loading_list

        self.streaming = streaming

        if plugins:
            self.add_plugins(plugins)

        if output_format:
            self.add_output_format(output_format)

    def add_output_format(
            self,
            extension: Union[str, List[str]]
    ):
        """Select and configure the sink plugin(s) required to generate the requested output format.

        Parameters
        ----------
        extension : str or list of str
            `extension` may be any of:

            - `'bin'`       -> binSink
            - `'bin.gz'`    -> binSink + `BFS_GZ_COMPRESS = 1`
            - `'csv'`       -> txtSink + `SEP_CHR = ','`
            - `'csv.gz'`    -> txtSink + `SEP_CHR = ','` + `TFS_GZ_COMPRESS = 1`
            - `'json'`      -> jsonSink
            - `'json.gz'`   -> jsonSink + `JSON_GZ_COMPRESS = 1`
            - `'txt'`       -> txtSink
            - `'txt.gz'`    -> txtSink + `TFS_GZ_COMPRESS = 1`
            - `'netflow'`   -> netflowSink
            - `'mysql'`     -> mysqlSink
            - `'sqlite'`    -> sqliteSink
            - `'postgres'`  -> psqlSink
            - `'mongo'`     -> mongoSink
            - `'socket'`    -> socketSink
            - `'streaming'` -> socketSink + `SKS_CONTENT_TYPE = 2`
            - `'pcap'`      -> pcapd

        Raises
        ------
        RuntimeError
            If one of the specified extension is not supported.

        Examples
        --------
        >>> t2 = T2()
        >>> t2.add_output_format(['json.gz', 'txt'])
        """
        if isinstance(extension, list):
            extensions = extension
        else:
            extensions = [extension]
        for ext in extensions:
            if ext == 'bin':
                self.add_plugin('binSink')
            elif ext == 'bin.gz':
                self.add_plugin('binSink')
                self.binSink.BFS_GZ_COMPRESS = 1
            elif ext == 'csv':
                self.add_plugin('txtSink')
                self.txtSink.SEP_CHR = ','
            elif ext == 'csv.gz':
                self.add_plugin('txtSink')
                self.txtSink.SEP_CHR = ','
                self.txtSink.TFS_GZ_COMPRESS = 1
            elif ext == 'txt':
                self.add_plugin('txtSink')
            elif ext == 'txt.gz':
                self.add_plugin('txtSink')
                self.txtSink.TFS_GZ_COMPRESS = 1
            elif ext == 'json':
                self.add_plugin('jsonSink')
            elif ext == 'json.gz':
                self.add_plugin('jsonSink')
                self.jsonSink.JSON_GZ_COMPRESS = 1
            elif ext == 'netflow':
                self.add_plugin('netflowSink')
            elif ext == 'mysql':
                self.add_plugin('mysqlSink')
            elif ext == 'sqlite':
                self.add_plugin('sqliteSink')
            elif ext == 'postgres':
                self.add_plugin('psqlSink')
            elif ext == 'mongo':
                self.add_plugin('mongoSink')
            elif ext == 'socket':
                self.add_plugin('socketSink')
            elif ext == 'pcap':
                self.add_plugin('pcapd')
            elif ext == 'streaming':
                self.streaming = True
            else:
                raise RuntimeError(f"output format '{ext}' not supported")

    @property
    def default_plugin_folder(self) -> str:
        """Path to the default plugin folder, i.e., `$HOME/.tranalyzer/plugins`."""
        if not self._default_plugin_folder:
            self._default_plugin_folder = join(expanduser('~'), '.tranalyzer', 'plugins')
        return self._default_plugin_folder

    @property
    def tranalyzer2(self) -> T2Plugin:
        """`t2py.T2Plugin` object representing Tranalyzer2 (core)."""
        if not self._tranalyzer2:
            self._tranalyzer2 = T2Plugin('tranalyzer2')
        return self._tranalyzer2

    @property
    def loading_list(self):
        """Get or set the path to a plugin loading list.

        In addition, the setter calls the `T2.add_plugin()` function for each plugin listed
        in the file.
        """
        return self._loading_list

    @loading_list.setter
    def loading_list(self, loading_list: str):
        self._whitelisted_plugins.clear()
        self._loading_list = loading_list
        if loading_list:
            directory = dirname(loading_list)
            if not isdir(directory):
                makedirs(directory)
            with open(loading_list, encoding='utf-8') as f:
                for plugin in f:
                    plugin = plugin.strip()
                    if len(plugin) > 0 and not plugin.startswith('#'):
                        self.add_plugin(plugin)
                        self._whitelisted_plugins.append(plugin)

    @property
    def plugins(self) -> Dict[str, T2Plugin]:
        """Dictionary of `t2py.T2Plugin` objects whose key is the plugin name."""
        return self._plugins

    @property
    def t2_exec(self) -> str:
        """Path to the Tranalyzer2 executable."""
        if self.plugin_folder:
            return join(self.plugin_folder, 'bin', 'tranalyzer')
        return join(self.default_plugin_folder, 'bin', 'tranalyzer')

    @property
    def streaming(self):
        """Allow `tranalyzer2` to run in streaming mode.

        Call `T2.stream()` to access flows one by one.
        """
        return self._streaming

    @streaming.setter
    def streaming(self, activate: bool):
        if activate:
            self.add_plugin('socketSink')
            self.socketSink.SKS_CONTENT_TYPE = 2
        self._streaming = activate

    def headers_file(self) -> str:
        """Return the filename of the headers file.

        Returns
        -------
        str
            The filename of the headers file.

        See Also
        --------
        T2.headers : Return Tranalyzer2 `_headers.txt` file contents.
        T2.print_headers : Print the contents of Tranalyzer2 `_headers.txt` file.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'])
        >>> t2.run()
        >>> t2.headers_file()
        '/tmp/file_headers.txt'
        """
        output_prefix = self._output_prefix()
        return output_prefix + '_headers.txt' if output_prefix else None

    def flow_file_json(self) -> str:
        """Return the filename of the JSON flow file.

        Returns
        -------
        str
            The filename of the JSON flow file.

        See Also
        --------
        T2.flows_json : Return Tranalyzer2 `_flows.json` file contents as an array of JSON objects.
        T2.print_flows_json : Print the contents of Tranalyzer2 `_flows.json` file.
        T2.flow_file_txt : Return the filename of the TXT flow file.
        T2.flows_txt : Return Tranalyzer2 `_flows.txt` file contents as an array of JSON objects.
        T2.print_flows_txt : Print the contents of Tranalyzer2 `_flows.txt` file.
        T2.flow_file : Return the filename of the JSON (preferred) or TXT flow file.
        T2.flows : Return Tranalyzer2 `_flows.json` (preferred) or `_flows.txt` file contents as
                   an array of JSON objects.
        T2.print_flows : Print the contents of Tranalyzer2 `_flows.json` (preferred) or
                         `_flows.txt` file.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', output_format='json')
        >>> t2.run()
        >>> t2.flow_file_json()
        '/tmp/file_flows.json'
        """
        output_prefix = self._output_prefix()
        return output_prefix + '_flows.json' if output_prefix else None

    def flow_file_txt(self) -> str:
        """Return the filename of the TXT flow file.

        Returns
        -------
        str
            The filename of the TXT flow file.

        See Also
        --------
        T2.flows_txt : Return Tranalyzer2 `_flows.txt` file contents as an array of JSON objects.
        T2.print_flows_txt : Print the contents of Tranalyzer2 `_flows.txt` file.
        T2.flow_file_json : Return the filename of the JSON flow file.
        T2.flows_json : Return Tranalyzer2 `_flows.json` file contents as an array of JSON objects.
        T2.print_flows_json : Print the contents of Tranalyzer2 `_flows.json` file.
        T2.flow_file : Return the filename of the JSON (preferred) or TXT flow file.
        T2.flows : Return Tranalyzer2 `_flows.json` (preferred) or `_flows.txt` file contents as
                   an array of JSON objects.
        T2.print_flows : Print the contents of Tranalyzer2 `_flows.json` (preferred) or
                         `_flows.txt` file.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', output_format='csv')
        >>> t2.run()
        >>> t2.flow_file_txt()
        '/tmp/file_flows.txt'
        """
        output_prefix = self._output_prefix()
        return output_prefix + '_flows.txt' if output_prefix else None

    def flow_file(self) -> str:
        """Return the filename of the JSON (preferred) or TXT flow file.

        Returns
        -------
        str
            The filename of the flow file.

        See Also
        --------
        T2.flows : Return Tranalyzer2 `_flows.json` (preferred) or `_flows.txt` file contents as
                   an array of JSON objects.
        T2.print_flows : Print the contents of Tranalyzer2 `_flows.json` (preferred) or
                         `_flows.txt` file.
        T2.flow_file_json : Return the filename of the JSON flow file.
        T2.flows_json : Return Tranalyzer2 `_flows.json` file contents as an array of JSON objects.
        T2.print_flows_json : Print the contents of Tranalyzer2 `_flows.json` file.
        T2.flow_file_txt : Return the filename of the TXT flow file.
        T2.flows_txt : Return Tranalyzer2 `_flows.txt` file contents as an array of JSON objects.
        T2.print_flows_txt : Print the contents of Tranalyzer2 `_flows.txt` file.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', output_format=['json', 'txt'])
        >>> t2.run()
        >>> t2.flow_file()
        '/tmp/file_flows.json'
        """
        if 'jsonSink' in self._plugins:
            return self.flow_file_json()

        if 'txtSink' in self._plugins:
            return self.flow_file_txt()

        return None

    def packet_file(self) -> str:
        """Return the filename of the packet file.

        Returns
        -------
        str
            The filename of the packet file.

        See Also
        --------
        T2.packets : Return Tranalyzer2 `_packets.txt` file contents as an array of JSON objects.
        T2.print_packets : Print the contents of Tranalyzer2 `_packets.txt`.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap')
        >>> t2.run(packet_mode=True)
        >>> t2.packet_file()
        '/tmp/file_packets.txt'
        """
        output_prefix = self._output_prefix()
        return output_prefix + '_packets.txt' if output_prefix else None

    def log_file(self) -> str:
        """Return the filename of the log file.

        Returns
        -------
        str
            The filename of the log file.

        See Also
        --------
        T2.log : Return Tranalyzer2 `_log.txt` file contents.
        T2.print_log : Print the contents of Tranalyzer2 `_log.txt` file.
        T2.report : Alias for `T2.log()`.
        T2.print_report : Alias for `T2.print_log()`.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', output_format='txt')
        >>> t2.run()
        >>> t2.log_file()
        '/tmp/file_log.txt'
        """
        output_prefix = self._output_prefix()
        return output_prefix + '_log.txt' if output_prefix else None

    def monitoring_file(self) -> str:
        """Return the filename of the monitoring file.

        Returns
        -------
        str
            The filename of the monitoring file.

        See Also
        --------
        T2.monitoring : Return Tranalyzer2 `_monitoring.txt` file contents.
        T2.print_monitoring : Print the contents of Tranalyzer2 `_monitoring.txt` file.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', output_format='txt', monitoring_file=True)
        >>> t2.run()
        >>> t2.monitoring_file()
        '/tmp/file_monitoring.txt'
        """
        output_prefix = self._output_prefix()
        return output_prefix + '_monitoring.txt' if output_prefix else None

    # ====================================================================== #

    def status(self):
        """Print the current configuration status of Tranalyzer2 and the plugins (sorted by
        plugin numbers).

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', output_format='csv.gz')
        >>> t2.status()
        """
        bold = '\033[1m'
        blue = '\033[0;34m'
        orange = '\033[0;33m'
        reset = '\033[0m'

        def _pending_changes():
            if pending_changes == 0:
                return ''
            return (' '
                    f'{blue}'
                    f'[{pending_changes} change{"s" if pending_changes > 1 else ""} pending]'
                    f'{reset}')

        def _loading_list_status():
            if self.loading_list and plugin_name not in self._whitelisted_plugins:
                return f' {orange}[NOT IN LOADING LIST]{reset}'
            return ''

        if self._tranalyzer2:
            t2 = self.tranalyzer2
            pending_changes = len(t2.changes)
            if pending_changes > 0:
                print(f'{bold}Tranalyzer2{reset}', end='')
                print(f'{blue}{_pending_changes()}{reset}:')
                for name, value in t2.changes.items():
                    print(f'    {name} = {value}')
                print()
        print(bold, 'Plugins:', reset)
        num_plugins = 0
        for plugin_name in sorted(self._plugins, key=lambda name: self._plugins[name].number):
            plugin = self._plugins[plugin_name]
            pending_changes = len(plugin.changes)
            print(f'    {num_plugins+1}: {plugin_name}'
                  f'{_pending_changes()}'
                  f'{_loading_list_status()}')
            if pending_changes > 0:
                for name, value in plugin.changes.items():
                    print(f'            {name} = {value}')
            num_plugins += 1
        if num_plugins == 0:
            print('    None')
        print(f'\n{bold}Tranalyzer options:{reset}')
        if self.pcap:
            print(f'    -r {self.pcap}')
        elif self.iface:
            print(f'    -i {self.iface}')
        elif self.pcap_list:
            if isinstance(self.pcap_list, list):
                print('    -R /tmp/pcap_list.txt')
            else:
                print(f'    -R {self.pcap_list}')
        if self.output_prefix:
            print(f'    -w {self.output_prefix}')
        if self.loading_list:
            print(f'    -b {self.loading_list}')
        if self.plugin_folder:
            print(f'    -p {self.plugin_folder}')
        if self.save_monitoring:
            print('    -m')
        if self.packet_mode:
            print('    -s')
        print('    -l')
        if self.bpf:
            print(f'    BPF filter: {self.bpf}')

    # ====================================================================== #

    def clear_plugins(self):
        """Clear the list of plugins.

        Examples
        --------
        >>> t2 = T2(plugins=['arpDecode', 'basicStats'])
        >>> t2.clear_plugins()
        >>> t2.list_plugins()
        []
        """
        self._remove_dict_entries(list(self._plugins.keys()))
        self._plugins.clear()

    def set_plugins(
            self,
            plugins: List[str] = None
    ):
        """Overwrite the current list of plugins.

        Parameters
        ----------
        plugins : list of str, default: None
            The list of plugins to use.

            If `None`, empty the list of plugins.

        See Also
        --------
        T2.list_plugins : Alphabetically list the currently active plugins.

        Examples
        --------
        >>> t2 = T2()
        >>> t2.set_plugins(['arpDecode', 'basicStats'])
        >>> t2.list_plugins()
        ['arpDecode', 'basicStats']
        >>> type(t2.arpDecode)
        <class 't2py.T2Plugin.T2Plugin'>
        >>> t2.basicStats.description
        'Basic statistics'
        """
        self.clear_plugins()
        if plugins:
            self._plugins = {plugin: T2Plugin(plugin) for plugin in plugins}
            self._add_dict_entries(plugins)

    def add_plugin(
            self,
            plugin: str
    ):
        """Add a plugin to the list of plugins.

        Parameters
        ----------
        plugin : str
            The name of the plugin to add.

        See Also
        --------
        T2.add_plugins : Add a list of plugins to the list of plugins.
        T2.remove_plugin : Remove a plugin from the list of plugins.
        T2.remove_plugins : Remove a list of plugins from the list of plugins.

        Examples
        --------
        >>> t2 = T2()
        >>> t2.add_plugin('arpDecode')
        >>> type(t2.arpDecode)
        <class 't2py.T2Plugin.T2Plugin'>
        >>> t2.arpDecode.number
        '179'
        """
        if plugin not in self._plugins:
            self._plugins[plugin] = T2Plugin(plugin)
            self._add_dict_entry(plugin)

    def add_plugins(
            self,
            plugins: List[str]
    ):
        """Add a list of plugins to the list of plugins.

        Parameters
        ----------
        plugins : list of str
            The list of plugins to add.

        See Also
        --------
        T2.add_plugin : Add a plugin to the list of plugins.
        T2.remove_plugin : Remove a plugin from the list of plugins.
        T2.remove_plugins : Remove a list of plugins from the list of plugins.

        Examples
        --------
        >>> t2 = T2()
        >>> t2.add_plugins(['arpDecode', 'basicStats'])
        >>> type(t2.arpDecode)
        <class 't2py.T2Plugin.T2Plugin'>
        >>> t2.basicStats.description
        'Basic statistics'
        """
        for plugin in plugins:
            self.add_plugin(plugin)

    def remove_plugin(
            self,
            plugin: str
    ):
        """Remove a plugin from the list of plugins.

        Parameters
        ----------
        plugin : str
            The name of the plugin to remove.

        See Also
        --------
        T2.add_plugin : Add a plugin to the list of plugins.
        T2.add_plugins : Add a list of plugins to the list of plugins.
        T2.remove_plugins : Remove a list of plugins from the list of plugins.

        Examples
        --------
        >>> t2 = T2(plugins=['arpDecode', 'basicStats'])
        >>> t2.remove_plugin('arpDecode')
        >>> t2.list_plugins()
        ['basicStats']
        """
        self._remove_dict_entry(plugin)
        self._plugins.pop(plugin)

    def remove_plugins(
            self,
            plugins: List[str]
    ):
        """Remove a list of plugins from the list of plugins.

        Parameters
        ----------
        plugins : list of str
            The list of plugins to remove.

        See Also
        --------
        T2.add_plugin : Add a plugin to the list of plugins.
        T2.add_plugins : Add a list of plugins to the list of plugins.
        T2.remove_plugin : Remove a plugin from the list of plugins.

        Examples
        --------
        >>> t2 = T2(plugins=['arpDecode', 'basicStats', 'tcpFlags'])
        >>> t2.remove_plugins(['arpDecode', 'basicStats'])
        >>> t2.list_plugins()
        ['tcpFlags']
        """
        for plugin in plugins:
            self.remove_plugin(plugin)

    # =========================================================================

    def list_plugins(self):
        """Alphabetically list the loaded plugins.

        Examples
        --------
        >>> t2 = T2(plugins=['arpDecode', 'basicStats', 'tcpFlags'])
        >>> t2.list_plugins()
        ['arpDecode', 'basicStats', 'tcpFlags']
        >>> t2.arpDecode.description
        'Address Resolution Protocol (ARP)'
        """
        return sorted(list(self._plugins.keys()))

    def create_plugin_list(
            self,
            plugins: List[str] = None,
            outfile: str = None,
            verbose: bool = False
    ):
        """Create a loading list of plugins.

        Parameters
        ----------
        plugins : list of str, default: None
            List of plugin names.

            If `None`, use `T2.list_plugins()`.

        outfile : str, default: None
            Name of the file to save.

            If `None`, default to `'plugins.load'` in the plugin folder.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        Examples
        --------
        >>> t2 = T2(plugins=['arpDecode', 'basicStats', 'tcpFlags'])
        >>> t2.create_plugin_list()
        >>> t2.create_plugin_list(outfile='/tmp/myPlugins.txt')
        >>> t2.create_plugin_list(['basicFlow', 'txtSink'])
        >>> t2.create_plugin_list(['basicFlow', 'txtSink'], '/tmp/myPlugins.txt')
        """
        if not outfile:
            if self.plugin_folder:
                outfile = join(self.plugin_folder, 'plugins.load')
            else:
                outfile = join(self.default_plugin_folder, 'plugins.load')
        if not plugins:
            plugins = list(self._plugins.keys())

        T2Utils.create_plugin_list(plugins, outfile, verbose=verbose)
        self.loading_list = outfile

    # =========================================================================

    def build(
            self,
            plugin: Union[str, List[str]] = None,
            plugin_folder: str = None,
            force_rebuild: bool = False,
            debug: bool = False,
            verbose: bool = False
    ):
        """Build Tranalyzer2 and the plugins.

        Parameters
        ----------
        plugin : str or list of str, default: None
            List of plugin names to build or path to a plugin loading list.

            If `None`, use `T2.list_plugins()`.

        plugin_folder : str, default: None
            Path to the plugin folder.

            If `None`, use `T2.plugin_folder`.

        force_rebuild : bool, default: False
            Force the rebuild of the configuration files (`$ t2build -r ...`).

        debug : bool, default: False
            Build the plugin in debug mode.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        See Also
        --------
        T2.clean : Remove files generated by `T2.build()`.

        Examples
        --------
        >>> t2 = T2(plugins=['arpDecode', 'basicStats', 'tcpFlags'])
        >>> t2.build()
        """
        plugin_folder = plugin_folder if plugin_folder else self.plugin_folder
        to_build = plugin if plugin else list(self._plugins.keys())
        if not plugin:
            to_build.append('tranalyzer2')
        T2Utils.build(to_build, plugin_folder, force_rebuild, debug, verbose=verbose)

    def clean(
            self,
            plugin: Union[str, List[str]] = None,
            verbose: bool = False
    ):
        """Clean Tranalyzer2 and the plugins.

        Parameters
        ----------
        plugin : str or list of str, default: None
            List of plugin names to clean, or path to a plugin loading list.

            If `None`, use `T2.list_plugins()`.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        See Also
        --------
        T2.build : Build Tranalyzer2 and the plugins.

        Examples
        --------
        >>> t2 = T2(plugins=['arpDecode', 'basicStats', 'tcpFlags'])
        >>> t2.build()
        >>> t2.clean()
        """
        to_clean = plugin if plugin else list(self._plugins.keys())
        if not plugin:
            to_clean.append('tranalyzer2')
        T2Utils.clean(to_clean, verbose=verbose)

    def unload(
            self,
            plugin: Union[str, List[str]] = None,
            plugin_folder: str = None,
            verbose: bool = False
    ):
        """Remove (unload) plugin(s) from the plugin folder.

        Parameters
        ----------
        plugin : str or list of str, default: None
            `plugin` can be:

            - a single plugin, e.g., `'pluginName'`
            - a list of plugins, e.g., `['pluginName1', 'pluginName2']`
            - a plugin loading list, e.g., `'myPlugins.txt'`
            - `all` to apply the operation to all available plugins
            - If `None`, use `T2.list_plugins()`.

        plugin_folder : str, default: None
            The plugin folder from where the plugin must be unloaded.

            If `None`, use `T2.plugin_folder`.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        Examples
        --------
        >>> t2 = T2(plugins=['arpDecode', 'basicStats', 'tcpFlags'])
        >>> t2.build()
        >>> t2.unload()
        """
        plugin_folder = plugin_folder if plugin_folder else self.plugin_folder
        to_unload = plugin if plugin else list(self._plugins.keys())
        T2Utils.unload(to_unload, plugin_folder, verbose=verbose)

    def apply_changes(
            self,
            verbose: bool = False
    ):
        """Apply/persist the current configuration to the source files.

        Parameters
        ----------
        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        subprocess.CalledProcessError
            If one of the processes exited with a non-zero exit code.

        Examples
        --------
        >>> t2 = T2(output_format='csv.gz')
        >>> t2.apply_changes()
        """
        self.tranalyzer2.apply_changes(verbose=verbose)
        for plugin in self._plugins.values():
            plugin.apply_changes(verbose=verbose)

    def discard_changes(self):
        """Discard all non-committed changes made in this session.

        Examples
        --------
        >>> t2 = T2(plugins=['arpDecode', 'txtSink'])
        >>> t2.arpDecode.MAX_IP = 5
        >>> t2.discard_changes()
        """
        for plugin in self._plugins.values():
            plugin.discard_changes()

    def reset(self):
        """Reset all plugins' flags to their default value.

        Examples
        --------
        >>> t2 = T2(plugins=['arpDecode', 'txtSink'])
        >>> t2.arpDecode.MAX_IP = 5
        >>> t2.apply_config()
        >>> t2.reset()
        >>> t2.apply_config()
        """
        for plugin in self._plugins.values():
            plugin.reset()

    def _setup_streaming(self):
        assert 'socketSink' in self._plugins

        # start socket listener in separate thread
        def _socket_sink_listener(self):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.socketSink.SKS_SERVADD, self.socketSink.SKS_DPORT))
            s.listen(1)
            self._conn, _ = s.accept()
            s.close()

        print('Setting up streaming server'
              f'{self.socketSink.SKS_SERVADD}:{self.socketSink.SKS_DPORT}')
        thread = threading.Thread(target=_socket_sink_listener, args=(self,))
        thread.daemon = True  # stop thread when _socket_sink_listener returns
        thread.start()

    def run(
            self,
            pcap: str = None,
            iface: str = None,
            pcap_list: Union[str, List[str]] = None,
            output_prefix: str = None,
            save_monitoring: bool = False,
            packet_mode: bool = False,
            plugins: List[str] = None,
            plugin_folder: str = None,
            loading_list: str = None,
            bpf: str = None,
            rebuild: bool = False,
            streaming: bool = False,
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
            Path to a list of pcap files, e.g., `'/tmp/myPcaps.txt'` or
            list of path to pcap files, e.g., `['file1.pcap', 'file2.pcap']`.

        output_prefix : str, default: None
            If `None`, automatically derived from input.

        save_monitoring: bool, default: False
            Save the monitoring report in a `_monitoring.txt` file.

        packet_mode : bool, default: False
            Activate Tranalyzer2 packet mode.

        plugin_folder : str, default: None
            Path to the plugin folder.

        plugins : list of str, default: None
            The list of plugins to use.

            If `None`, use `T2.list_plugins()`.

        loading_list : str, default: None
            Path to a plugin loading list.

            If `None`, create one using `T2.list_plugins()`.

        bpf : str, default: None
            A BPF filter.

        rebuild : bool, default, default: False
            Apply the current changes and rebuild Tranalyzer2 and the plugins.

        streaming: bool, default: False
            If `True`, then `T2.stream()` can be used to yield one flow at a time.

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

            - If none or more than one input (`pcap`, `pcap_list`, `iface`) is specified.
            - If socketSink plugin is not loaded or misconfigured when `T2.streaming` is `True`.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        subprocess.TimeoutExpired
            If `timeout` was expired and its value reached.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', output_format='txt')
        >>> t2.build()
        >>> t2.run()
        >>> t2.run(packet_mode=True)
        """
        inputs = (pcap, pcap_list, iface)
        if sum(bool(i) for i in inputs) > 1:
            raise RuntimeError('Only one input (pcap, pcap_list, iface) may be specified')

        inputs += (self.pcap, self.pcap_list, self.iface)
        if not any(bool(i) for i in inputs):
            raise RuntimeError('An input (pcap, pcap_list or iface) is required')

        if pcap:
            self.pcap = pcap
            self.pcap_list = None
            self.iface = None
        elif iface:
            self.pcap = None
            self.pcap_list = None
            self.iface = iface
        elif pcap_list:
            self.pcap = None
            self.pcap_list = pcap_list
            self.iface = None

        if output_prefix:
            self.output_prefix = output_prefix

        if plugin_folder:
            self.plugin_folder = plugin_folder

        if loading_list:
            self.loading_list = loading_list
        elif not plugins:
            plugins = list(self._plugins.keys())

        if save_monitoring:
            self.save_monitoring = save_monitoring

        if packet_mode:
            self.packet_mode = packet_mode

        if bpf:
            self.bpf = bpf

        if streaming or self.streaming:
            if 'socketSink' not in self._plugins:
                raise RuntimeError('socketSink plugin is required for running in streaming mode')

            if (self.socketSink.SKS_SOCKTYPE != 1 or
                    self.socketSink.SKS_CONTENT_TYPE != 2 or
                    self.socketSink.SKS_GZ_COMPRESS != 0):
                raise RuntimeError("Invalid configuration for socketSink in streaming mode: "
                                   "requires 'SKS_SOCKTYPE=1', 'SKS_CONTENT_TYPE=2' and "
                                   "'SKS_GZ_COMPRESS=0'")

            self.streaming = True

        if rebuild:
            if not self.loading_list:
                self.apply_changes()
                self.build()
            else:
                self.tranalyzer2.apply_changes()
                self.tranalyzer2.build()
                with open(self.loading_list, encoding='utf-8') as f:
                    for plugin in f:
                        T2Utils.apply_config(plugin.strip())
                self.build(plugin=self.loading_list)

        def _run_tranalyzer(self):
            T2Utils.run_tranalyzer(
                t2_exec=self.t2_exec,
                pcap=self.pcap,
                iface=self.iface,
                pcap_list=self.pcap_list,
                output_prefix=self.output_prefix,
                log_file=True,
                save_monitoring=self.save_monitoring,
                packet_mode=self.packet_mode,
                plugin_folder=self.plugin_folder,
                bpf=self.bpf,
                loading_list=self.loading_list,
                plugins=plugins,
                timeout=timeout,
                verbose=verbose)

        if not self.streaming:
            _run_tranalyzer(self)
        else:
            self._setup_streaming()
            thread = threading.Thread(target=_run_tranalyzer, args=(self,))
            thread.daemon = True  # stop thread when run_tranalyzer returns
            thread.start()

    # =========================================================================
    # Access _headers.txt, _flows.txt, _packets.txt and _log.txt
    # =========================================================================

    def stream(self) -> Iterator[Dict[str, Any]]:
        """Iterator returning flow by flow.

        Raises
        ------
        RuntimeError

            - If the function was called, without configuring streaming mode first.
            - If socketSink did not open connection.

        Yields
        ------
        dict
            The next flow represented as a dict with the column names as key.

        Examples
        --------
        >>> t2 = T2(streaming=True, plugins=['basicFlow'])
        >>> t2.run(pcap='file.pcap')
        >>> for flow in t2.stream():
        ...     print(f"{flow['srcIP']}:{flow['srcPort']} -> {flow['dstIP']}:{flow['dstPort']}")
        """
        if not self.streaming:
            raise RuntimeError("Calling 'stream' without configuring streaming mode first.")

        if not self._conn:
            time.sleep(2)  # wait for tranalyzer to start and socketSink to connect

        if not self._conn:
            raise RuntimeError('socketSink did not open connection')

        buf = b''
        while True:
            buf += self._conn.recv(1024)
            if not buf:
                break
            lines = buf.split(b'\n')
            for line in lines[:-1]:
                yield json.loads(line)
            buf = lines[-1]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._conn:
            self._conn.close()

    def _load_file(self, filename: str) -> str:
        """Load a headers/flows/packets/log file.

        Parameters
        ----------
        filename : str
            The name of the file to load.
        """
        if not filename or not isfile(filename):
            return None
        data = None
        with open(filename, encoding='utf-8') as f:
            data = f.read()
        return data

    def headers(self) -> str:
        """Return Tranalyzer2 `_headers.txt` file contents.

        Returns
        -------
        str
            The raw contents of the header file.

        Raises
        ------
        RuntimeError
            If the `_headers.txt` file could not be found.

        See Also
        --------
        T2.headers_file : Return the filename of the headers file.
        T2.print_headers : Print the contents of Tranalyzer2 `_headers.txt` file.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'])
        >>> t2.build()
        >>> t2.run()
        >>> t2.headers()
        '# Date: 1628090651.486362 sec (Wed 04 Aug 2021 17:24:11 CEST)...'
        """
        name = self.headers_file()
        if not name or not isfile(name):
            raise RuntimeError('Run Tranalyzer with the txtSink plugin to create a headers file')
        return self._load_file(name)

    def flows_json(self) -> List[Dict[str, Any]]:
        """Return Tranalyzer2 `_flows.json` file contents as an array of JSON objects.

        Returns
        -------
        list of dict
            The list of rows contained in the JSON flow file.

            Each row is represented as a dict with the column names as key.

        Raises
        ------
        RuntimeError
            If the `_flows.json` file could not be found.

        See Also
        --------
        T2.flow_file_json : Return the filename of the JSON flow file.
        T2.flows : Return Tranalyzer2 `_flows.json` (preferred) or `_flows.txt` file contents as
                   an array of JSON objects.
        T2.flows_txt : Return Tranalyzer2 `_flows.txt` file contents as an array of JSON objects.
        T2.flow_file : Return the filename of the JSON (preferred) or TXT flow file.
        T2.flow_file_txt : Return the filename of the TXT flow file.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'jsonSink'])
        >>> t2.build()
        >>> t2.run()
        >>> t2.flows_json()
        [{'dir': 'A', 'flowInd': 1, ...}, {'dir': 'B', 'flowInd': 1, ...}, ...]
        """
        name = self.flow_file_json()
        if not name or not isfile(name):
            raise RuntimeError('Run Tranalyzer with the jsonSink plugin to create '
                               'a JSON flow file')
        return T2Utils.to_json_array(name)

    def flows_txt(
            self,
            delimiter: str = None
    ) -> List[Dict[str, Any]]:
        """Return Tranalyzer2 `_flows.txt` file contents as an array of JSON objects.

        Parameters
        ----------
        delimiter : str, default: None
            The delimiter used to separate columns in the input file.

            If `None`, default to '\\t' if the txtSink plugin is not loaded else to the value of
            `txtSink.SEP_CHR`.

        Returns
        -------
        list of dict
            The list of rows contained in the TXT flow file.

            Each row is represented as a dict with the column names as key.

        Raises
        ------
        RuntimeError
            If the `_flows.txt` file could not be found.

        See Also
        --------
        T2.flow_file_txt : Return the filename of the TXT flow file.
        T2.flows : Return Tranalyzer2 `_flows.json` (preferred) or `_flows.txt` file contents as
                   an array of JSON objects.
        T2.flows_json : Return Tranalyzer2 `_flows.json` file contents as an array of JSON objects.
        T2.flow_file : Return the filename of the JSON (preferred) or TXT flow file.
        T2.flow_file_json : Return the filename of the JSON flow file.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'])
        >>> t2.build()
        >>> t2.run()
        >>> t2.flows_txt()
        [{'dir': 'A', 'flowInd': 1, ...}, {'dir': 'B', 'flowInd': 1, ...}, ...]
        """
        name = self.flow_file_txt()
        if not name or not isfile(name):
            raise RuntimeError('Run Tranalyzer with the txtSink plugin to create a flow file')
        if delimiter is None:
            if 'txtSink' not in self._plugins:
                delimiter = '\t'
            else:
                delimiter = self.txtSink.SEP_CHR.strip('"')
                if delimiter[0] == '\\':
                    if delimiter[1] == 't':
                        delimiter = '\t'
                    elif delimiter[1] == 'n':
                        delimiter = '\n'
                    elif delimiter[1] == 'r':
                        delimiter = '\r'
                    elif delimiter[1] == '\\':
                        delimiter = '\\'
        return T2Utils.to_json_array(name, delimiter)

    def flows(self) -> List[Dict[str, Any]]:
        """Return Tranalyzer2 `_flows.json` (preferred) or `_flows.txt` file contents as
        an array of JSON objects.

        Returns
        -------
        list of dict
            The list of rows contained in the flow file.

            Each row is represented as a dict with the column names as key.

        Raises
        ------
        RuntimeError
            If neither the `_flows.json` nor the `_flows.txt` file could be found.

        See Also
        --------
        T2.flow_file : Return the filename of the JSON (preferred) or TXT flow file.
        T2.flow_file_json : Return the filename of the JSON flow file.
        T2.flow_file_txt : Return the filename of the TXT flow file.
        T2.flows_json : Return Tranalyzer2 `_flows.json` file contents as an array of JSON objects.
        T2.flows_txt : Return Tranalyzer2 `_flows.txt` file contents as an array of JSON objects.
        T2.print_flows : Print the contents of Tranalyzer2 `_flows.json` (preferred) or
                         `_flows.txt` file.
        T2.print_flows_json : Print the contents of Tranalyzer2 `_flows.json` file.
        T2.print_flows_txt : Print the contents of Tranalyzer2 `_flows.json` file.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'])
        >>> t2.build()
        >>> t2.run()
        >>> t2.flows()
        [{'dir': 'A', 'flowInd': 1, ...}, {'dir': 'B', 'flowInd': 1, ...}, ...]
        """
        if 'jsonSink' in self._plugins:
            return self.flows_json()

        if 'txtSink' in self._plugins:
            return self.flows_txt()

        raise RuntimeError('Run Tranalyzer with the txtSink or jsonSink plugin to create '
                           'a flow file')

    def packets(self) -> List[Dict[str, Any]]:
        """Return Tranalyzer2 `_packets.txt` file contents as an array of JSON objects.

        Returns
        -------
        list of dict
            The list of rows contained in the packet file.

            Each row is represented as a dict with the column names as key.

        Raises
        ------
        RuntimeError
            If the `_packets.txt` file could not be found.

        See Also
        --------
        T2.packet_file : Return the filename of the packet file.
        T2.print_packets : Print the contents of Tranalyzer2 `_packets.txt` file.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'], packet_mode=True)
        >>> t2.build()
        >>> t2.run()
        >>> t2.packets()
        [{'pktNo': 1, 'flowInd': 1, ...}, {'pktNo': 2, 'flowInd': 1, ...}, ...]
        """
        name = self.packet_file()
        if not name or not isfile(name):
            raise RuntimeError("Run Tranalyzer with 'packet_mode=True' to create a packet file")
        return T2Utils.to_json_array(name)

    def report(self) -> str:
        """Return Tranalyzer2 `_log.txt` file contents.

        Returns
        -------
        str
            The raw contents of the log file.

        Raises
        ------
        RuntimeError
            If the `_log.txt` file could not be found.

        See Also
        --------
        T2.log_file : Return the filename of the log file.
        T2.log : Alias for `T2.report()`

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'])
        >>> t2.build()
        >>> t2.run()
        >>> t2.report()
        '================================================================================...'
        """
        name = self.log_file()
        if not name or not isfile(name):
            raise RuntimeError("Run Tranalyzer to create a log file")
        return self._load_file(name)

    def log(self) -> str:
        """Return Tranalyzer2 `_log.txt` file contents.

        Returns
        -------
        str
            The raw contents of the log file.

        Raises
        ------
        RuntimeError
            If the `_log.txt` file could not be found.

        See Also
        --------
        T2.report : Alias for `T2.log()`
        T2.log_file : Return the filename of the log file.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'])
        >>> t2.build()
        >>> t2.run()
        >>> t2.log()
        '================================================================================...'
        """
        return self.report()

    def monitoring(self) -> List[Dict[str, Any]]:
        """Return Tranalyzer2 `_monitoring.txt` file contents as an array of JSON objects.

        Returns
        -------
        list of dict
            The list of rows contained in the monitoring file.

            Each row is represented as a dict with the column names as key.

        Raises
        ------
        RuntimeError
            If the `_monitoring.txt` file could not be found.

        See Also
        --------
        T2.monitoring_file : Return the filename of the monitoring file.
        T2.print_monitoring : Print the contents of Tranalyzer2 `_monitoring.txt` file.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'], monitoring_file=True)
        >>> t2.tranalyzer2.MACHINE_REPORT = 1
        >>> t2.tranalyzer2.apply_changes()
        >>> t2.build()
        >>> t2.run()
        >>> t2.monitoring()
        [{'repTyp': 'USR1MR_A', 'sensorID': 666, 'time': ...}, {'repTyp': 'USR1MR_A', ...}, ...]
        """
        name = self.monitoring_file()
        if not name or not isfile(name):
            raise RuntimeError("Run Tranalyzer with 'save_monitoring=True' to create "
                               "a monitoring file")
        return T2Utils.to_json_array(name)

    # =========================================================================
    # Print _headers.txt, _flows.txt, _packets.txt and _log.txt files contents
    # =========================================================================

    def print_headers(self):
        """Print the contents of Tranalyzer2 `_headers.txt` file.

        Raises
        ------
        RuntimeError
            If the header file could not be found.

        See Also
        --------
        T2.headers_file : Return the filename of the headers file.
        T2.headers : Return Tranalyzer2 `_headers.txt` file contents.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'])
        >>> t2.build()
        >>> t2.run()
        >>> t2.print_headers()
        # Date: 1628090651.486362 sec (Wed 04 Aug 2021 17:24:11 CEST)
        # Tranalyzer 0.8.11 (Anteater), Tarantula.
        ...
        """
        name = self.headers_file()
        if not name or not isfile(name):
            raise RuntimeError('Run Tranalyzer with the txtSink plugin to create a headers file')
        with open(name, encoding='utf-8') as f:
            print(f.read())

    def print_flows(self):
        """Print the contents of Tranalyzer2 `_flows.json` (preferred) or `_flows.txt` file.

        Raises
        ------
        RuntimeError
            If the flow file could not be found.

        See Also
        --------
        T2.flow_file : Return the filename of the JSON (preferred) or TXT flow file.
        T2.flows : Return Tranalyzer2 `_flows.json` (preferred) or `_flows.txt` file contents as
                   an array of JSON objects.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'])
        >>> t2.build()
        >>> t2.run()
        >>> t2.print_flows()
        %dir	flowInd	...
        A	1	...
        B	1	...
        ...
        """
        name = self.flow_file()
        if not name or not isfile(name):
            raise RuntimeError('Run Tranalyzer with the txtSink plugin to create a flow file')
        with open(name, encoding='utf-8') as f:
            print(f.read())

    def print_flows_json(self):
        """Print the contents of Tranalyzer2 `_flows.json` file.

        Raises
        ------
        RuntimeError
            If the JSON flow file could not be found.

        See Also
        --------
        T2.flow_file_json : Return the filename of the JSON flow file.
        T2.flows_json : Return Tranalyzer2 `_flows.json` file contents as an array of JSON objects.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'jsonSink'])
        >>> t2.build()
        >>> t2.run()
        >>> t2.print_flows_json()
        {"dir":"A","flowInd":1,...}
        {"dir":"B","flowInd":1,...}
        ...
        """
        name = self.flow_file_json()
        if not name or not isfile(name):
            raise RuntimeError('Run Tranalyzer with the jsonSink plugin to create a JSON flow file')
        with open(name, encoding='utf-8') as f:
            print(f.read())

    def print_flows_txt(self):
        """Print the contents of Tranalyzer2 `_flows.txt` file.

        Raises
        ------
        RuntimeError
            If the flow file could not be found.

        See Also
        --------
        T2.flow_file_txt : Return the filename of the TXT flow file.
        T2.flows_txt : Return Tranalyzer2 `_flows.txt` file contents as an array of JSON objects.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'])
        >>> t2.build()
        >>> t2.run()
        >>> t2.print_flows_txt()
        %dir	flowInd	...
        A	1	...
        B	1	...
        ...
        """
        name = self.flow_file_txt()
        if not name or not isfile(name):
            raise RuntimeError('Run Tranalyzer with the txtSink plugin to create a flow file')
        with open(name, encoding='utf-8') as f:
            print(f.read())

    def print_packets(self):
        """Print the contents of Tranalyzer2 `_packets.txt` file.

        Raises
        ------
        RuntimeError
            If the packet file could not be found.

        See Also
        --------
        T2.packet_file : Return the filename of the packet file.
        T2.packets : Return Tranalyzer2 `_packets.txt` file contents as an array of JSON objects.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'])
        >>> t2.build()
        >>> t2.run(packet_mode=True)
        >>> t2.print_packets()
        %pktNo	flowInd	...
        1	1	...
        2	1	...
        ...
        """
        name = self.packet_file()
        if not name or not isfile(name):
            raise RuntimeError("Run Tranalyzer with 'packet_mode=True' plugin to create "
                               "a packet file")
        with open(name, encoding='utf-8') as f:
            print(f.read())

    def print_log(self):
        """Print the contents of Tranalyzer2 `_log.txt` file.

        Raises
        ------
        RuntimeError
            If the log file could not be found.

        See Also
        --------
        T2.print_log : Alias for `T2.print_report()`.
        T2.log_file : Return the filename of the log file.
        T2.log : Return Tranalyzer2 `_log.txt` file contents.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'])
        >>> t2.build()
        >>> t2.run()
        >>> t2.print_log()
        """
        name = self.log_file()
        if not name or not isfile(name):
            raise RuntimeError("Run Tranalyzer to create a log file")
        with open(name, encoding='utf-8') as f:
            print(f.read())

    def print_report(self):
        """Print the contents of Tranalyzer2 `_log.txt` file.

        Raises
        ------
        RuntimeError
            If the log file could not be found.

        See Also
        --------
        T2.print_report : Alias for `T2.print_log()`.
        T2.log_file : Return the filename of the log file.
        T2.log : Return Tranalyzer2 `_log.txt` file contents.
        T2.report : Alias for `T2.log()`.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'])
        >>> t2.build()
        >>> t2.run()
        >>> t2.print_report()
        """
        self.print_log()

    def print_monitoring(self):
        """Print the contents of Tranalyzer2 `_monitoring.txt` file.

        Raises
        ------
        RuntimeError
            If the monitoring file could not be found.

        See Also
        --------
        T2.monitoring_file : Return the filename of the monitoring file.
        T2.monitoring : Return Tranalyzer2 `_monitoring.txt` file contents.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'])
        >>> t2.tranalyzer2.MACHINE_REPORT = 1
        >>> t2.tranalyzer2.apply_changes()
        >>> t2.build()
        >>> t2.run()
        >>> t2.print_monitoring()
        %repTyp	sensorID	...
        USR1MR_A	666	...
        USR1MR_A	666	...
        ...
        """
        name = self.monitoring_file()
        if not name or not isfile(name):
            raise RuntimeError("Run Tranalyzer with 'save_monitoring=True' to create "
                               "a monitoring file")
        with open(name, encoding='utf-8') as f:
            print(f.read())

    # =========================================================================

    def follow_stream(
            self,
            flow: int,
            output_format: Union[int, str] = 2,
            direction: str = None,
            payload_format: Union[int, str] = 4,
            reassembly: bool = True,
            colors: bool = True
    ) -> Union[str, List[str], List[bytearray], List[Dict[str, Any]]]:
        """Return the reassembled payload of the flow with specified `index` and `direction`.

        Parameters
        ----------
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

            - If the `_packets.txt` file could not be found.
            - If `output_format` or `payload_format` was out of bound.
            - If `direction` was not `'A'`, `'B'` or `None`.
            - If `output_format` was 3 or `'reconstruct'` and `direction` was not `'A'` or `'B'`.
            - If `payload_format` was 4 or `'bytearray'` and `output_format` was 1 or `'info'`.

        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        See Also
        --------
        t2py.T2Utils.T2Utils.follow_stream : Call `tawk` `follow_stream()` function with
                                             the specified options.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap',
        ... plugins=['basicFlow', 'basicStats', 'tcpFlags', 'txtSink'],
        ... packet_mode=True)
        >>> t2.tranalyzer2.SPKTMD_PCNTH = 1
        >>> t2.tranalyzer2.apply_changes()
        >>> t2.build()
        >>> t2.run()
        >>> t2.follow_stream(1, direction='B')
        [...,{"flow": 1, "packet": 125, ..., "payload": bytearray(b'226 Transfer complete.\\r\\n')},
        ...]
        """
        name = self.packet_file()
        if not name or not isfile(name):
            raise RuntimeError("Run Tranalyzer with 'packet_mode=True' to create a packet file")
        return T2Utils.follow_stream(name, flow, output_format, direction,
                                     payload_format, reassembly, colors)

    # =========================================================================

    def to_pandas(
            self,
            infile: str = None,
            delimiter: str = None
    ) -> "pandas.core.frame.DataFrame":
        """Convert the flow file or `infile` to pandas `DataFrame`.

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

        Raises
        ------
        RuntimeError
            If `infile` could not be found.

        Examples
        --------
        >>> t2 = T2(pcap='/tmp/file.pcap', plugins=['basicFlow', 'txtSink'])
        >>> t2.build()
        >>> t2.run()
        >>> df = t2.to_pandas()
        >>> type(df)
        <class 'pandas.core.frame.DataFrame'>
        """
        infile = infile if infile else self.flow_file()
        if not infile:
            raise RuntimeError('Run Tranalyzer with the txtSink or jsonSink plugin to create '
                               'a flow file')
        return T2Utils.to_pandas(infile, delimiter)

    # =========================================================================
    # Private functions
    # =========================================================================

    def _output_prefix(self) -> str:
        """Return the output prefix (derived from Tranalyzer2 input if not set).

        Returns
        -------
        str
            The output_prefix.
        """
        if self.output_prefix:
            if not isdir(self.output_prefix) or not self.pcap:
                return self.output_prefix
            filename = self.pcap.split('/')[-1]
            if '.' in filename:
                return join(self.output_prefix, '.'.join(filename.split('.')[:-1]))
            return join(self.output_prefix, filename)

        if self.pcap:
            if '.' in self.pcap:
                return '.'.join(self.pcap.split('.')[:-1])
            return self.pcap

        return None

    def _add_dict_entry(self, plugin: str):
        if plugin not in self.__dict__:
            self.__dict__[plugin] = self._plugins[plugin]

    def _add_dict_entries(self, plugins: List[str]):
        for plugin in plugins:
            self._add_dict_entry(plugin)

    def _remove_dict_entry(self, plugin: str):
        if plugin in self.__dict__:
            del self.__dict__[plugin]

    def _remove_dict_entries(self, plugins: List[str]):
        for plugin in plugins:
            self._remove_dict_entry(plugin)
