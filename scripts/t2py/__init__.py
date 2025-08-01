#!/usr/bin/env python3

"""
Python package `t2py` can be used to control and operate Tranalyzer2.

`t2py` provides the following modules:

`T2`: manage a session (set of plugins, configuration changes, flow file, ...).

`T2Plugin`: represent a Tranalyzer2 plugin.

`T2Utils`: provide wrappers around Tranalyzer2 scripts and utilities.
"""

from .T2Utils import T2Utils
from .T2Plugin import T2Plugin
from .T2 import T2
