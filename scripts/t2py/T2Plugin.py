#!/usr/bin/env python3

import sys

from typing import Any, Dict, List, Union

from .T2Utils import T2Utils


class T2Plugin:

    """Class representing a Tranalyzer plugin.

    Parameters
    ----------
    name : str
        The name of the plugin.

    config : str, default: None
        The name of the config file to load.

    Raises
    ------
    NameError
        If the plugin could not be found.
    """

    def __init__(
            self,
            name: str,
            config: str = None
    ):
        if name not in T2Utils.valid_plugin_names():
            raise NameError(f'Plugin {name} could not be found')
        self._name = name
        self._description = None
        self._number = None
        flags = T2Utils.list_config(name)
        self._default = None
        self._flags = dict.fromkeys(flags)
        self._modified_flags = {}
        for flag in self._flags:
            self._flags[flag] = T2Utils.get_config_from_source(name, flag)
            self._add_dict_entry(flag, self._flags[flag])
        self.config_file = config
        if config:
            self.load_config(config)

    @property
    def config_file(self) -> str:
        """The configuration file where changes will be persisted in this session.

        `None` means the changes are persisted directly into the source files,
        e.g., `src/pluginName.h`.
        """
        return self._config_file

    @config_file.setter
    def config_file(self, config: str) -> str:
        self._config_file = config

    @property
    def name(self) -> str:
        """The name of the plugin."""
        return self._name

    @property
    def description(self) -> str:
        """The description of the plugin."""
        if not self._description:
            self._description = T2Utils.plugin_description(self.name)
        return self._description

    @property
    def number(self) -> str:
        """The number of the plugin."""
        if not self._number:
            self._number = T2Utils.plugin_number(self.name)
        return self._number

    @property
    def flags(self) -> List[str]:
        """The list of configuration flags available for the plugin."""
        return list(self._flags.keys())

    @property
    def default(self) -> Dict[str, Any]:
        """The list of configuration flags and their default values."""
        if not self._default:
            self._default = dict.fromkeys(self.flags)
            for flag in self.flags:
                self._default[flag] = T2Utils.get_default(self.name, flag)
        return self._default

    @property
    def changes(self) -> Dict[str, Any]:
        """The list of configuration flags modified but not yet persisted."""
        return self._modified_flags

    def discard_changes(self):
        """Discard all non-committed changes made in this session.

        Examples
        --------
        >>> arpDecode = T2Plugin('arpDecode')
        >>> arpDecode.MAX_IP = 5
        >>> arpDecode.changes
        {'MAX_IP': 5}
        >>> arpDecode.discard_changes()
        >>> arpDecode.changes
        {}
        """
        for flag in list(self._modified_flags):
            self._set_config(flag, T2Utils.get_config_from_source(self.name, flag))
        self._modified_flags.clear()

    def status(self):
        """Print the current configuration status of the plugin.

        Examples
        --------
        >>> arpDecode = T2Plugin('arpDecode')
        >>> arpDecode.MAX_IP = 5
        >>> arpDecode.status()
        1 change pending:
            MAX_IP = 5
        """
        pending_changes = len(self.changes)
        if pending_changes == 0:
            print('No changes pending')
        else:
            blue_text = '\033[0;34m{} change{} pending:\033[0m'
            print(blue_text.format(pending_changes, "s" if pending_changes > 1 else ""))
        for name, value in sorted(self.changes.items()):
            print(f'    {name} = {value}')

    def diff(
            self,
            base: str = None
    ) -> Dict[str, Any]:
        """Compare the current configuration with the default configuration.

        Parameters
        ----------
        base : str, default: None
            The base configuration to use for comparison.

            Currently, only `'default'` is supported.

        Returns
        -------
        dict
            The flags differing from `base` as keys, the current value as values.

        Raises
        ------
        NotImplementedError
            When trying to compare the current configuration with base other than `'default'`.

        Examples
        --------
        >>> arpDecode = T2Plugin('arpDecode')
        >>> arpDecode.MAX_IP = 5
        >>> arpDecode.apply_changes()
        >>> arpDecode.diff()
        {'MAX_IP': 5}
        """
        if base and base != 'default':
            raise NotImplementedError(
                "Comparing configuration with other than 'default' currently not implemented")
        changes = {}
        for flag, value in self._flags.items():
            if not self._values_equal(value, self.default[flag]):
                changes[flag] = value
        return changes

    def load_config(
            self,
            config: str
    ):
        """Load a config file.

        Parameters
        ----------
        config : str
            The name of the config file to load.

        Examples
        --------
        >>> arpDecode = T2Plugin('arpDecode')
        >>> arpDecode.load_config('/tmp/arpDecode.config')
        """
        with open(config, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') or len(line) == 0:
                    continue
                key_val = line.split('=')
                self._set_config(key_val[0].strip(), key_val[1].strip())

    def generate_config(
            self,
            outfile: str = None,
            verbose: bool = False
    ):
        """Generate a config file with the default values.

        Parameters
        ----------
        outfile : str, default: None
            The name of the config file to generate.

            If `None`, use `'pluginName.config'` in the plugin home folder.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        Examples
        --------
        >>> arpDecode = T2Plugin('arpDecode')
        >>> arpDecode.generate_config('/tmp/arpDecode.config')
        """
        T2Utils.generate_config(self.name, outfile, verbose=verbose)

    def save_config(
            self,
            outfile: str = None,
            verbose: bool = False
    ):
        """Generate a config file with the current modified values.

        Parameters
        ----------
        outfile : str, default: None
            The name of the config file to save.

            If `None`, use `'pluginName.config'` in the plugin home folder.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        subprocess.CalledProcessError
            If one of the processes exited with a non-zero exit code.

        Examples
        --------
        >>> arpDecode = T2Plugin('arpDecode')
        >>> arpDecode.MAX_IP = 5
        >>> arpDecode.save_config('/tmp/arpDecode.config')
        """
        if not outfile and self.config_file:
            outfile = self.config_file
        self.generate_config(outfile, verbose=verbose)
        for flag, value in self.changes.items():
            T2Utils.set_config(self.name, flag, value, outfile=outfile, verbose=verbose)

    def reset(
            self,
            name: Union[str, List[str]] = None
    ):
        """Reset flags to their default value.

        Parameters
        ----------
        name : str or list of str, default: None
            `name` can be:

            - a single flag, e.g., `'MY_FLAG'`.
            - a list of flags, e.g., `['MY_FLAG1', 'MY_FLAG2']`.
            - `None` to reset all flags.

        Raises
        ------
        NameError
            If a flag does not exist for this plugin.

        See Also
        --------
        T2Plugin.apply_changes : Apply the current modifications to the plugin.
        T2Plugin.set_default : Alias for `T2Plugin.reset()`

        Notes
        -----
        `T2Plugin.apply_changes()` must be called later to apply the changes.

        Examples
        --------
        >>> arpDecode = T2Plugin('arpDecode')
        >>> arpDecode.MAX_IP = 5
        >>> arpDecode.reset('MAX_IP')
        >>> arpDecode.apply_changes()
        """
        if not name:
            self.reset(self.flags)
        elif isinstance(name, list):
            for n in name:
                if n not in self.flags:
                    raise NameError(f"Flag '{n}' does not exist for {self.name} plugin")
                if n in self._modified_flags:
                    del self._modified_flags[n]
                self._set_config(n, self.default[n])
        elif name not in self.flags:
            raise NameError(f"Flag '{name}' does not exist for {self.name} plugin")
        else:
            if name in self._modified_flags:
                del self._modified_flags[name]
            self._set_config(name, self.default[name])

    def get_default(
            self,
            name: str
    ) -> Any:
        """Get the default value for the configuration flag `name`.

        Parameters
        ----------
        name : str
            The name of the flag to get the default value from.

        Raises
        ------
        NameError
            If the flag `name` does not exist for this plugin.

        Examples
        --------
        >>> arpDecode = T2Plugin('arpDecode')
        >>> arpDecode.get_default('MAX_IP')
        10
        """
        if name not in self.flags:
            raise NameError(f"Flag '{name}' does not exist for {self.name} plugin")
        return self.default[name]

    def set_default(
            self,
            name: Union[str, List[str]] = None
    ):
        """Reset flags to their default value.

        Parameters
        ----------
        name : str or list of str, default: None
            `name` can be:

            - a single flag, e.g., `'MY_FLAG'`.
            - a list of flags, e.g., `['MY_FLAG1', 'MY_FLAG2']`.
            - `None` to reset all flags.

        Raises
        ------
        NameError
            If a flag does not exist for this plugin.

        See Also
        --------
        T2Plugin.apply_changes : Apply the current modifications to the plugin.
        T2Plugin.reset : Alias for `T2Plugin.set_default()`

        Notes
        -----
        `T2Plugin.apply_changes()` must be called later to apply the changes.

        Examples
        --------
        >>> arpDecode = T2Plugin('arpDecode')
        >>> arpDecode.MAX_IP = 5
        >>> arpDecode.set_default('MAX_IP')
        >>> arpDecode.apply_changes()
        """
        self.reset(name)

    def list_config(self) -> List[str]:
        """List the configuration flags available for the plugin.

        Returns
        -------
        list of str
            The list of configuration flags available for the plugin.

        See Also
        --------
        T2Plugin.flags : The list of configuration flags available for the plugin.

        Examples
        --------
        >>> arpDecode = T2Plugin('arpDecode')
        >>> arpDecode.list_config()
        ['MAX_IP']
        """
        return self.flags

    def apply_changes(
            self,
            outfile: str = None,
            verbose: bool = False
    ):
        """Apply the current modifications to the plugin.

        Parameters
        ----------
        outfile : str, default: None

            - If `None`, edit the sources directly.
            - Else apply the config to `outfile`, e.g., `'myPlugin.config'`.

        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        subprocess.CalledProcessError
            If one of the processes exited with a non-zero exit code.

        Examples
        --------
        >>> arpDecode = T2Plugin('arpDecode')
        >>> arpDecode.MAX_IP = 5
        >>> arpDecode.apply_changes()
        """
        if self._modified_flags:
            for flag_name, flag_value in self._modified_flags.items():
                T2Utils.set_config(self.name, flag_name, flag_value, outfile=outfile,
                                   verbose=verbose)
                self._flags[flag_name] = flag_value
            self._modified_flags.clear()

    def build(
            self,
            plugin_folder: str = None,
            force_rebuild: bool = False,
            debug: bool = False,
            verbose: bool = False
    ):
        """Build the plugin.

        Parameters
        ----------
        plugin_folder : str, default: None
            Path to the plugin folder.

            If `None`, default to `'$HOME/.tranalyzer/plugins'`.

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
        T2Plugin.clean : Remove files generated by `T2Plugin.build()`.

        Examples
        --------
        >>> arpDecode = T2Plugin('arpDecode')
        >>> arpDecode.build()
        """
        T2Utils.build(self.name, plugin_folder, force_rebuild, debug, verbose)

    def clean(
            self,
            verbose: bool = False
    ):
        """Remove files generated by `T2Plugin.build()`.

        Parameters
        ----------
        verbose : bool, default: False

            - If `True`, print the output (`stdout` and `stderr`) of the command.
            - If `False`, do not print anything.

        Raises
        ------
        subprocess.CalledProcessError
            If the process exited with a non-zero exit code.

        See Also
        --------
        T2Plugin.build : Build the plugin.

        Examples
        --------
        >>> arpDecode = T2Plugin('arpDecode')
        >>> arpDecode.build()
        >>> arpDecode.clean()
        """
        T2Utils.clean(self.name, verbose=verbose)

    def unload(
            self,
            plugin_folder: str = None,
            verbose: bool = False
    ):
        """Remove (unload) the plugin from the plugin folder.

        Parameters
        ----------
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

        Examples
        --------
        >>> arpDecode = T2Plugin('arpDecode')
        >>> arpDecode.unload()
        """
        T2Utils.unload(self.name, plugin_folder, verbose=verbose)

    # =========================================================================
    # Private functions
    # =========================================================================

    def _values_equal(self, val1: Any, val2: Any):
        """Compare two values for equality, handling synonym values, such as `'yes'`/1 and `'no'`/0.

        Parameters
        ----------
        val1, val2 : Any
            The values to compare.

        Returns
        -------
        bool
            `True` if `val1` and `val2` are equal, `False` otherwise.
        """
        return (
            (val1 in ['yes', 1] and val2 in ['yes', 1]) or
            (val1 in ['no', 0] and val2 in ['no', 0]) or
            (val1 == val2)
        )

    def _set_config(self, name: str, value: Any):
        """Set the value for the configuration flag `name`.

        Parameters
        ----------
        name : str
            The name of the flag to set.

        value : Any
            The new value for the flag `name`.

        Raises
        ------
        NameError
            If the flag `name` does not exist for this plugin.

        See Also
        --------
        T2Plugin.apply_changes : Apply the current modifications to the plugin.

        Notes
        -----
        `T2Plugin.apply_changes()` must be called later to apply the changes.
        """
        if name not in self.flags:
            raise NameError(f"Flag '{name}' does not exist for {self.name} plugin")

        source = str(T2Utils.get_config(self.name, name, infile=self.config_file))
        if value == 'no':
            if source != '0':
                self._modified_flags[name] = 0
                self._add_dict_entry(name, 0)
            elif name in self._modified_flags:
                del self._modified_flags[name]
        elif value == 'yes':
            if source != '1':
                self._modified_flags[name] = 1
                self._add_dict_entry(name, 1)
            elif name in self._modified_flags:
                del self._modified_flags[name]
        elif str(value) != source:
            self._modified_flags[name] = value
            self._add_dict_entry(name, value)
        else:
            if name in self._modified_flags:
                del self._modified_flags[name]
            self._add_dict_entry(name, self._flags[name])

    def __setattr__(self, name: str, value: Any):
        super().__setattr__(name, value)
        try:
            if name in self.flags:
                self._set_config(name, value)
        except (KeyError, AttributeError):
            if not name.startswith('_'):
                _printerr(f"Flag '{name}' does not exist for {self.name} plugin")

    def _add_dict_entry(self, flag: str, value):
        self.__dict__[flag] = value

# ============================================================================ #


def _printerr(msg: str):
    """Print a message in red to `stderr`.

    Parameters
    ----------
    msg : str
        The message to print.
    """
    print(f'\033[91m{msg}\033[0m', file=sys.stderr)
