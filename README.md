Tranalyzer2 Installation Procedure
==================================

For the most up-to-date information, refer to the following links:

* [Installation on Linux/macOS](https://tranalyzer.com/tutorial/installation)
* [Installation on Windows 10](https://tranalyzer.com/tutorial/windowsinstall)
* [Many more tutorials](https://www.tranalyzer.com/tutorials)

The information below summarizes briefly the installation steps.

Getting the Latest Version
--------------------------

1. Download the latest version of Tranalyzer2
   [here](https://tranalyzer.com/download/tranalyzer/tranalyzer2-0.9.3lmw3.tar.gz)

2. Extract the content of the downloaded archive:

   ```bash
   $ tar xzf tranalyzer2-0.9.3lmw3.tar.gz
   ```

Installation - The Easy Way
---------------------------

Go into tranalyzer2 root folder and run the `setup.sh` script:

```bash
$ cd tranalyzer2-0.9.3
$ ./setup.sh
```

Open a new terminal and you are now ready to use Tranalyzer!
Start learning how [here](https://tranalyzer.com/tutorial/basicanalysis).

Installation - The Detailed Way
-------------------------------

If you are a more advanced user, you can run the commands performed by the `setup.sh` script manually as follows:

### Dependencies

* **Ubuntu/Kali:**

  ```bash
  $ sudo apt-get install autoconf autoconf-archive automake libbsd-dev libpcap-dev libreadline-dev libtool make meson zlib1g-dev
  ```

* **Arch/Manjaro:**

  ```bash
  $ sudo pacman -S autoconf autoconf-archive automake bash-completion gcc libpcap libtool make meson pkgconf zlib
  ```

* **Gentoo:**

  ```bash
  $ sudo emerge autoconf autoconf-archive automake bash-completion libpcap libtool meson zlib
  ```

* **openSUSE:**

  ```bash
  $ sudo zypper install autoconf autoconf-archive automake gcc libbsd-devel libpcap-devel libtool meson readline-devel zlib-devel
  ```

* **Red Hat/Fedora/CentOS** (If the `dnf` command could not be found, try with `yum` instead):

  ```bash
  $ sudo dnf install autoconf autoconf-archive automake bzip2 libbsd-devel libpcap-devel libtool meson readline zlib-devel
  ```

* **macOS** (using [Homebrew](https://brew.sh) package manager):

  ```bash
  $ brew install autoconf autoconf-archive automake libpcap libtool meson readline zlib
  ```

Note that `meson` is optional, but recommended as it is much faster than the autotools (`autoconf`, `automake`, ...).

### Aliases

This step will give you access to all aliases (`t2`, `t2build`, ...) used in the tutorials.

1. Go to the root folder of Tranalyzer

   ```bash
   $ cd tranalyzer2-0.9.3
   ```

2. Save this location in the variable `$T2HOME`:

   ```bash
   $ T2HOME="$PWD"
   $ echo $T2HOME
   /home/user/tranalyzer2-0.9.3
   ```

3. The file `$T2HOME/scripts/t2_aliases` provides a set of aliases and functions which facilitate working with Tranalyzer. To access them, copy the code below. This will identify your terminal configuration file and then modify it.

   ```bash
   TOADD="$(cat << EOF
   if [ -f "$T2HOME/scripts/t2_aliases" ]; then
       . "$T2HOME/scripts/t2_aliases" # Note the leading '.'
   fi
   EOF
   )"
   if [ -f "$HOME/.bashrc" ]; then
       echo "$TOADD" >> "$HOME/.bashrc"
       source "$HOME/.bashrc"
       echo "Aliases installed in $HOME/.bashrc"
   elif [ -f "$HOME/.zshrc" ]; then
       echo "$TOADD" >> "$HOME/.zshrc"
       source "$HOME/.zshrc"
       echo "Aliases installed in $HOME/.zshrc"
   elif [ -f "$HOME/.bash_profile" ]; then
       echo "$TOADD" >> "$HOME/.bash_profile"
       source "$HOME/.bash_profile"
       echo "Aliases installed in $HOME/.bash_profile"
   else
       echo "No standard terminal configuration file found."
   fi
   ```

### Compilation (using aliases installed in step 2)

To build Tranalyzer2 and the plugins, run one of the following commands:

* Tranalyzer2 and a default set of plugins:

  ```bash
  $ t2build
  ```

* Tranalyzer2 and all the plugins:

  ```bash
  $ t2build -a
  ```

* Tranalyzer2 and a custom set of plugins (listed in `plugins.build`):

  ```bash
  $ t2build -b
  ```

* Tranalyzer2 and a custom set of plugins (listed in `myplugins.txt`):

  ```bash
  $ t2build -b myplugins.txt
  ```

* To build a specific plugin:

  ```bash
  $ t2build pluginName
  ```

  (Note that completion is available, so if you type `t2build <tab>`, you will see a list of all the plugins and if you type `t2build http<tab>` it will automatically complete the command to `t2build httpSniffer`).

* To build several plugins:

  ```bash
  $ t2build pluginName1 pluginName2
  ```

* To install Tranalyzer2 in `/usr/local/bin` and the man page in `/usr/local/man/man1`:

  ```bash
  $ t2build -i
  ```

  (Note that root rights are required for the installation.)

* For the full list of options accepted by the scripts:

  ```bash
  $ t2build --help
  ```

### Compilation (without using aliases installed in step 2)

To build Tranalyzer2 and the plugins, run one of the following commands (make sure that `$T2HOME` points to the root folder of Tranalyzer, i.e., where the `README.md` and `ChangeLog` files are located):

* Tranalyzer2 and a default set of plugins:

  ```bash
  $ cd $T2HOME
  $ ./autogen.sh
  ```

* Tranalyzer2 and all the plugins:

  ```bash
  $ cd $T2HOME
  $ ./autogen.sh -a
  ```

* Tranalyzer2 and a custom set of plugins (listed in `plugins.build`):

  ```bash
  $ cd $T2HOME
  $ ./autogen.sh -b
  ```

* Tranalyzer2 and a custom set of plugins (listed in `myplugins.txt`):

  ```bash
  $ cd $T2HOME
  $ ./autogen.sh -b myplugins.txt
  ```

* For finer control of which plugins to build, either run `./autogen.sh` from every folder you want to build:

  ```bash
  $ cd "$T2HOME/plugins/pluginName"
  $ ./autogen.sh
  ```

  Or run `./autogen.sh pluginName` from the root folder of Tranalyzer2:

  ```bash
  $ cd "$T2HOME"
  $ ./autogen.sh pluginName
  ```

  (Note that you can specify more than one plugin name, e.g., `./autogen.sh httpSniffer txtSink`)

* To install Tranalyzer2 in `/usr/local/bin` and the man page in `/usr/local/man/man1`:

  ```bash
  $ ./autogen.sh -i
  ```

  (Note that root rights are required for the installation.)

* For the full list of options accepted by the scripts, run:

  ```bash
  $ ./autogen.sh --help
  ```

Documentation
-------------

Tranalyzer2 core and every plugin come with their own documentation found in the `doc/` subfolder, e.g., `tranalyzer2/doc/tranalyzer2.pdf`.
The full documentation of Tranalyzer2 and all the locally available plugins can be built by running `make` in `$T2HOME/doc` and accessed by running `evince doc/documentation.pdf` (Replace `evince` with your preferred PDF viewer). Note that if the `setup.sh` script was used or `t2_aliases` was installed, then the `t2doc` function can be used to access the documentation as follows:

* Full documentation:

  ```bash
  $ t2doc
  ```

* Tranalyzer2 core documentation:

  ```bash
  $ t2doc tranalyzer2
  ```

* Scripts documentation:

  ```bash
  $ t2doc scripts
  ```

* Plugin documentation, e.g., basicFlow:

  ```bash
  $ t2doc basicFlow
  ```

Copyright
---------

Copyright (c) 2008-2024 by Tranalyzer Development Team
