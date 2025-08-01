# Introduction

Python package `t2py` can be used to control and operate Tranalyzer2.
It can be used as an alternative to [t2conf](https://tranalyzer.com/tutorial/configuration), [t2build](https://tranalyzer.com/tutorial/building) and [other scripts](https://tranalyzer.com/tutorial/cheatsheet#list-of-tranalyzer2-scripts-and-utilities).

# Caveats

This library is still experimental and at an early stage of development.
As such, the [API](https://tranalyzer.com/tutorial/t2pydoc/index.html) may be subject to change.

Bug reports, feature requests, feedback and suggestions are welcome and can be addressed directly to [Andy](https://tranalyzer.com/contact).

# Dependencies

## Optional Dependencies

The following dependencies are only required for specific operations:

* [pandas](https://pandas.pydata.org) is only required for the `T2.to_pandas()` and `T2Utils.to_pandas()` functions.
* [pdoc3](https://pdoc3.github.io/pdoc) is only required to generate the [API documentation](https://tranalyzer.com/tutorial/t2pydoc/index.html) as HTML.

```bash
$ python3 -m pip install pandas pdoc3
```

# Getting Started

```python
$ export PYTHONPATH="$PYTHONPATH:/path/to/t2py/"
$ python3
>>> from t2py import T2, T2Plugin, T2Utils
```

# Available Modules

`t2py` provides the following modules:

* [T2Utils](https://tranalyzer.com/tutorial/t2pydoc/T2Utils.html) : provide wrappers around Tranalyzer2 scripts and utilities.
* [T2Plugin](https://tranalyzer.com/tutorial/t2pydoc/T2Plugin.html): represent a Tranalyzer2 plugin.
* [T2](https://tranalyzer.com/tutorial/t2pydoc/T2.html): manage a session (set of plugins, configuration changes, flow file, ...).

The following sections simply list the available variables and methods.
For more details and examples, refer to the [t2py API](https://tranalyzer.com/tutorial/t2pydoc/index.html).

## T2Utils.py: simple wrapper around Tranalyzer2 scripts and utilities

For more details, refer to the [t2py.T2Utils API](https://tranalyzer.com/tutorial/t2pydoc/T2Utils.html).

```python
>>> from t2py import T2Utils

# Read-Only Properties

>>> T2Utils.T2HOME    # -> str
>>> T2Utils.T2PLHOME  # -> str

>>> T2Utils.T2BUILD   # -> str
>>> T2Utils.T2CONF    # -> str
>>> T2Utils.T2FM      # -> str
>>> T2Utils.T2PLUGIN  # -> str
>>> T2Utils.TAWK      # -> str

# Static Functions

>>> T2Utils.apply_config(
...     plugin: str,
...     infile: str = None,
...     verbose: bool = False
... )
>>> T2Utils.build(
...     plugin: Union[str, List[str]],
...     plugin_folder: str = None,
...     force_rebuild: bool = False,
...     debug: bool = False,
...     verbose: bool = False
... )
>>> T2Utils.clean(
...     plugin: Union[str, List[str]],
...     verbose: bool = False
... )
>>> T2Utils.create_pcap_list(
...     pcaps: List[str],
...     outfile: str = None
... )
>>> T2Utils.create_plugin_list(
...     plugins: List[str],
...     outfile: str = None,
...     verbose: bool = False
... )
>>> T2Utils.follow_stream(
...     filename: str,
...     flow: int,
...     output_format: Union[int, str] = 2,
...     direction: str = None,
...     payload_format: Union[int, str] = 4,
...     reassembly: bool = True,
...     colors: bool = True
... ) -> Union[str, List[str], List[bytearray], List[Dict[str, Any]]]
>>> T2Utils.generate_config(
...     plugin: str,
...     outfile: str = None,
...     verbose: bool = False
... )
>>> T2Utils.get_config(
...     plugin: str,
...     name: str,
...     infile: str = None
... ) -> Any
>>> T2Utils.get_config_from_source(
...     plugin: str,
...     name: str
... ) -> Any
>>> T2Utils.get_default(
...     plugin: str,
...     name: str
... ) -> Any
>>> T2Utils.list_config(
...     plugin: str
... ) -> List[str]
>>> T2Utils.list_plugins(
...     infile: str = None
... ) -> List[str]
>>> T2Utils.load_plugins(
...     plugin: Union[str, List[str]] = None
... )
>>> T2Utils.network_interfaces() -> List[str]
>>> T2Utils.plugin_description(
...     plugin: str
... ) -> str
>>> T2Utils.plugin_number(
...     plugin: str
... ) -> str
>>> T2Utils.plugins(
...     category: Union[str, List[str]] = None
... ) -> List[str]
>>> T2Utils.reset_config(
...     plugin: Union[str, List[str]],
...     name: Union[str, List[str]] = None,
...     outfile: str = None,
...     verbose: bool = False
... )
>>> T2Utils.run_tranalyzer(
...     pcap: str = None,
...     iface: str = None,
...     pcap_list: Union[str, List[str]] = None,
...     output_prefix: str = None,
...     log_file: bool = False,
...     monitoring_file: bool = False,
...     packet_mode: bool = False,
...     plugin_folder: str = None,
...     loading_list: str = None,
...     plugins: List[str] = None,
...     bpf: str = None,
...     t2_exec: str = None,
...     timeout: int = None,
...     verbose: bool = False
... )
>>> T2Utils.set_config(
...     plugin: str,
...     flag_name: Union[str, Dict[str, Any]],
...     flag_value: Any = None,
...     outfile: str = None,
...     verbose: bool = False
... )
>>> T2Utils.set_default(
...     plugin: Union[str, List[str]],
...     name: Union[str, List[str]] = None,
...     outfile: str = None,
...     verbose: bool = False
... )
>>> T2Utils.t2_exec(
...     debug: bool = False
... ) -> str
>>> T2Utils.tawk(
...     program: str = None,
...     filename: str = None,
...     options: List[str] = None
... ) -> str
>>> T2Utils.to_json_array(
...     infile: str,
...     delimiter: str = '\t'
... ) -> List[Dict[str, Any]]
>>> T2Utils.to_pandas(
...     infile: str,
...     delimiter: str = None
... ) -> pandas.core.frame.DataFrame
>>> T2Utils.to_pdf(
...     pcap: str = None,
...     flow_file: str = None,
...     prefix: str = None,
...     config: bool = True,
...     reset_config: bool = True,
...     open_pdf: bool = True,
...     verbose: bool = False
... )
>>> T2Utils.unload(
...     plugin: Union[str, List[str]],
...     plugin_folder: str = None,
...     verbose: bool = False
... )
>>> T2Utils.valid_plugin_names() -> List[str]
```

## T2Plugin.py: represent a plugin

For more details, refer to the [t2py.T2Plugin API](https://tranalyzer.com/tutorial/t2pydoc/T2Plugin.html).

```python
>>> from t2py import T2Plugin

# Constructor

>>> myPlugin = T2Plugin(
...     name: str,
...     config: str = None
... )

# Read-Only Properties

>>> myPlugin.changes      # -> Dict[str, Any]
>>> myPlugin.default      # -> Dict[str, Any]
>>> myPlugin.description  # -> str
>>> myPlugin.flags        # -> List[str]
>>> myPlugin.name         # -> str
>>> myPlugin.number       # -> str

# Read/Write Properties

>>> myPlugin.config_file  # -> str, default: None

# Functions

>>> myPlugin.apply_changes(
...     outfile: str = None,
...     verbose: bool = False
... )
>>> myPlugin.build(
...     plugin_folder: str = None,
...     force_rebuild: bool = False,
...     debug: bool = False,
...     verbose: bool = False
... )
>>> myPlugin.clean(
...     verbose: bool = False
... )
>>> myPlugin.diff(
...     base: str = None
... ) -> Dict[str, Any]
>>> myPlugin.discard_changes()
>>> myPlugin.generate_config(
...     outfile: str = None,
...     verbose: bool = False
... )
>>> myPlugin.get_default(
...     name: str
... ) -> Any
>>> myPlugin.list_config() -> List[str]
>>> myPlugin.load_config(
...     config: str
... )
>>> myPlugin.reset(
...     name: Union[str, List[str]] = None
... )
>>> myPlugin.save_config(
...     outfile: str = None,
...     verbose: bool = False
... )
>>> myPlugin.set_default(
...     name: Union[str, List[str]] = None
... )
>>> myPlugin.status()
>>> myPlugin.unload(
...     plugin_folder: str = None,
...     verbose: bool = False
... )

# In addition, configuration flags can be accessed as follows:

>>> myPlugin.MY_PLUGIN_FLAG
>>> myPlugin.MY_PLUGIN_FLAG = myNewValue
```

## T2.py: manage several plugins and run T2, convert/display flow file, ...

For more details, refer to the [t2py.T2 API](https://tranalyzer.com/tutorial/t2pydoc/T2.html).

```python
>>> from t2py import T2

# Constructor

>>> t2 = T2(
...     pcap: str = None,
...     iface: str = None,
...     pcap_list: Union[str, List[str]] = None,
...     output_prefix: str = None,
...     monitoring_file: bool = False,
...     packet_mode: bool = False,
...     plugin_folder: str = None,
...     loading_list: str = None,
...     plugins: List[str] = None,
...     output_format: Union[str, List[str]] = None,
...     bpf: str = None,
...     streaming: bool = False
... )

# Read-Only Properties

>>> t2.default_plugin_folder  # -> str
>>> t2.plugins                # -> Dict[str, T2Plugin]
>>> t2.t2_exec                # -> str
>>> t2.tranalyzer2            # -> T2Plugin

# Read/Write Properties

>>> t2.plugin_folder          # -> str
>>> t2.loading_list           # -> str
>>> t2.streaming              # -> bool

# Functions

>>> t2.add_output_format(
...     extension: Union[str, List[str]]
... )
>>> t2.add_plugin(
...     plugin: str
... )
>>> t2.add_plugins(
...     plugins: List[str]
... )
>>> t2.apply_changes(
...     verbose: bool = False
... )
>>> t2.build(
...     plugin: Union[str, List[str]] = None,
...     plugin_folder: str = None,
...     force_rebuild: bool = False,
...     debug: bool = False,
...     verbose: bool = False
... )
>>> t2.clean(
...     plugin: Union[str, List[str]] = None,
...     verbose: bool = False
... )
>>> t2.clear_plugins()
>>> t2.create_plugin_list(
...     plugins: List[str] = None,
...     outfile: str = None,
...     verbose: bool = False
... )
>>> t2.discard_changes()
>>> t2.flow_file() -> str
>>> t2.flow_file_json() -> str
>>> t2.flow_file_txt() -> str
>>> t2.flows() -> List[Dict[str, Any]]
>>> t2.flows_json() -> List[Dict[str, Any]]
>>> t2.flows_txt(
...     delimiter: str = None
... ) -> List[Dict[str, Any]]
>>> t2.follow_stream(
...     flow: int,
...     output_format: Union[int, str] = 2,
...     direction: str = None,
...     payload_format: Union[int, str] = 4,
...     reassembly: bool = True,
...     colors: bool = True
... ) -> Union[str, List[str], List[bytearray], List[Dict[str, Any]]]
>>> t2.headers() -> str
>>> t2.headers_file() -> str
>>> t2.list_plugins()
>>> t2.log() -> str
>>> t2.log_file() -> str
>>> t2.monitoring_file() -> str
>>> t2.monitoring() -> List[Dict[str, Any]]
>>> t2.packet_file() -> str
>>> t2.packets() -> List[Dict[str, Any]]
>>> t2.print_flows()
>>> t2.print_flows_json()
>>> t2.print_flows_txt()
>>> t2.print_headers()
>>> t2.print_log()
>>> t2.print_monitoring()
>>> t2.print_packets()
>>> t2.print_report()
>>> t2.remove_plugin(
...     plugin: str
... )
>>> t2.remove_plugins(
...     plugins: List[str]
... )
>>> t2.report() -> str
>>> t2.reset()
>>> t2.run(
...     pcap: str = None,
...     iface: str = None,
...     pcap_list: Union[str, List[str]] = None,
...     output_prefix: str = None,
...     packet_mode: bool = False,
...     plugins: List[str] = None,
...     plugin_folder: str = None,
...     loading_list: str = None,
...     bpf: str = None,
...     rebuild: bool = False,
...     streaming: bool = False,
...     timeout: int = None,
...     verbose: bool = False
... )
>>> t2.set_plugins(
...     plugins: List[str] = None
... )
>>> t2.status()
>>> t2.stream() -> Iterator[Dict[str, Any]]
>>> t2.to_pandas(
...     infile: str = None,
...     delimiter: str = None
... ) -> pandas.core.frame.DataFrame
>>> t2.unload(
...     plugin: Union[str, List[str]] = None,
...     plugin_folder: str = None,
...     verbose: bool = False
... )

# In addition, each plugin is accessible as a T2Plugin object:

>>> t2.myPlugin
```

# Tutorials

Refer to the [t2py - Control and Operate T2 with Python](https://tranalyzer.com/tutorial/t2py) tutorial.

# Getting Help

For the complete documentation with examples, refer to the [t2py API](https://tranalyzer.com/tutorial/t2pydoc/index.html).

To list the variables and functions available, run one of the following commands:

```python
>>> dir(T2)
>>> dir(T2Plugin)
>>> dir(T2Utils)
```

The documentation for each module can be accessed as follows:

```python
>>> help(T2)
>>> help(T2Plugin)
>>> help(T2Utils)
```

# Subject to Change

This library is still experimental and at an early stage of development.
As such, the [API](https://tranalyzer.com/tutorial/t2pydoc/index.html) may be [subject to change](https://tranalyzer.com/tutorial/t2py#subject-to-change).

Below is a list of functions or properties which may be removed in a future version.

Feel free to [send us bug reports, feature requests, feedback and suggestions!](https://tranalyzer.com/contact)

## T2Plugin

* The `list_config()` function may be removed as the same result can be obtained with the `flags` property.
* The `set_default()` function may be removed as the same result can be obtained with the `reset()` function.
* The `get_default()` function may be removed as the same result can be obtained with the `default` property.

## T2

* Only one of the `log()`/`report()` function may be kept.
* Only one of the `print_log()`/`print_report()` function may be kept.
* The `clear_plugins()` function may be removed and replaced with the `remove_plugins()` with `plugins = None` or `plugins = []`.
* The `unload()` function may be modified to only allow unloading of all the plugins in the session (a single plugin can be unloaded with `T2Plugin unload()` function).
* The `flows()`, `flows_txt()` and `flows_json()` may become `flows(extension: str = None)`.
* The `add_plugin()` and `add_plugins()` functions may be merged.
* The `remove_plugin()` and `remove_plugins()` functions may be merged.
* The behavior of the `headers()`, `log()` and `report()` functions may be changed to that of `print_headers()`, `print_log()` and `print_report()` respectively.
* The `print_flows()`, `print_flows_json()`, `print_flows_txt()`, `print_headers()`, `print_log()`, `print_packets()` and `print_report()` functions may be removed.

# Bug Reports, Feature Requests, Feedback and Suggestions

Feel free to [send us bug reports, feature requests, feedback and suggestions](https://tranalyzer.com/contact)!
