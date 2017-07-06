

# Stækka Metasploit - Extenting Metasploit

This Msf plugin extends Metasploit for some missing features and modules
allowing interaction with other/custom exploits/ways of getting shell access.
The current focus here is Linux/Unix support.

# Core features


* TTY support: starting a shell from Metasploit allowing interaction with TTY support and session migration into Metasploit. This allows custom ways of gaining a shell (private non-metasploit exploits) and to use this shell as Metasploit session for executing post exploitation modules. There is also another SSH module for using a TTY shell while interacting with the session.

* Performance hacks:  For improving performance caching has been added allowing to cache command output of often used commands (like `uname`) or files. For searching files it is possible to run "find" once and to store the results. This can be re-used for many search requests (find all files with `*shadow*`, find all suid files, ...etc). For recursive downloads tar can be used which speeds up downloads.

# Installing

Setting environment and loading it for further usage (can be any shell profile/startup)
```
export STAEKKA_PATH=$HOME/.staekka/
echo 'export STAEKKA_PATH=$HOME/.staekka/' >>$HOME/.profile
```

Copy it into installation directory
```
cp -r staekka  $STAEKKA_PATH
```

Copy Metasploit plugins
```
mkdir -p $HOME/.msf4/plugins/
cp  $STAEKKA_PATH/plugins/staekka.rb $HOME/.msf4/plugins/
cp  $STAEKKA_PATH/plugins/info_path.rb $HOME/.msf4/plugins/
```

Installation of dependencies (gem installation without root required)
```
gem install --user bindata
gem install --user minitar
gem install --user ruby-termios
```

Or installation of dependencies via bundler
```
cd  $STAEKKA_PATH
bundle install
```

# Usage

``
$ export STAEKKA_PATH=$HOME/.staekka/
$ cd ../metasploit-framework/
$ ./msfconsole
msf > load staekka
msf > use auxiliary/shell/interactive
msf auxiliary(interactive) > info
```

# Modules

## New sessions:
* auxiliary/shell/interactive     This module executes a command (shell) you can interact with. You can add this shell session to mfs sessions
* auxiliary/shell/ssh_session     Login using SSH with TTY support
* auxiliary/shell/offline_audit   This module allows to perform tests/audits with pre-collected data

## Post exploitation - Linux/Unix:
* post/unix/general/secure_delete   Overwriting and deleting files and directories (anti-forensic)
* post/unix/general/updatedb        Creating an updatedb for faster file searches and perform searches
* post/unix/general/download        Downloading files faster transfering them via HTTP(s)
* post/unix/general/upload          Uploading files faster transfering them via HTTP(s)
* post/unix/general/shell2ssh       Starting a new ssh server using a custom config and start an extra SSH session

## Post exploitation - Analyse
* post/unix/gather/download_interessting  Download interesting files based on a file list and regex
* post/unix/gather/enum_history           Download and analyse history files
* post/unix/gather/enum_logfiles          Download and analyse log files

## Post exploitation - Logs
* post/unix/general/logs/dump_lastlog     Dump lastlog log files as text
* post/unix/general/logs/dump_utmp        Dump utmp log files as text
* post/unix/general/logs/clear_lastlog    Clear lastlog logfiles
* post/unix/general/logs/clear_utmp       Clear utmp log files
* post/unix/general/logs/clear_syslog     Clear syslog like (text) log files

## Post exploitation - Analyse Linux
* post/linux/gather/protection/kernel     Check for kernel extra hardenings
* post/linux/gather/protection/binaries   Check for kernel extra hardenings



# Name: stækka

Stækka: Icelandic word for (enlarge/expand/grow).
This plugin extends Metasploit for some features.

# Bugs
## Ruby/Readline ##
Sometimes msfconsole shows "\r"
Fix: Use the system Readline library instead of RbReadline
```
msfconsole -L
```



