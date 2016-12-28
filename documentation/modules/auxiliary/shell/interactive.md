interactive by default opens a shell (if no other command is configured)
providing you an interactive shell with tty support on your system. This shell
can be used for launing non-metasploit exploits or doing other steps manually.
When finished you can enter a magic string and get back to your metasploit
console. The shell will be handled as session within metasploit providing
possibility of various post modules.

## Module Options

**CMD**

By default CMD will be the default shell (environment variable $SHELL).

**INTERACTIVE**

Setting INTERACtiVE to true will start the interactive modus by executing the
module. Interacting at any time can be done by calling session -i SESSION.

**LOGFILE**

By default a logfile (option LOGFILE) whill be created in /tmp storing every
input/output (like a keylogger).

**STOP**

Option STOP can customize the magic string for returning to metasploit. By
default it is #__stop__

**LOGTERMINAL**

Start a terminal (xterm) with 'tail -f logfile' for watching the PTY - can be
used as show effect or for debugging


## Scenario
Launing your private non-metasploit module for getting a shell and use the
features of metasploit for this shell.
```
msf auxiliary(interactive) > set CMD zsh
CMD => zsh
msf auxiliary(interactive) > set INTERACTIVE true
INTERACTIVE => true
msf auxiliary(interactive) > run

[*] Logfile: /tmp/__log_1_27443
[*] Pty I/O session 3 opened (local -> PTY: zsh) at 2000-01-01 10:11:56 +0200
end this shell with "#__stop__"
oooo% echo do something
do something
oooo% ./expoit
zsh: no such file or directory: ./expoit
oooo% echo #__stop__

Stopping interactive
[*] Auxiliary module execution completed
msf auxiliary(interactive) > sessions

Active sessions
===============

  Id  Type        Information  Connection
  --  ----        -----------  ----------
  1   shell unix  PTY:         local -> PTY: zsh (::1)
```


