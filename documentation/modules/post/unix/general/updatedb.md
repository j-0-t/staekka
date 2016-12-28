Search files based on defined strings and/or permissions. For performance reasons updatedb and caching featured can be used.

## Module Options

**FIND**

A string to search for files. Can be a regex.

**LS**

Returns (a cached) output of ls -l FILE

**PERMS**

Define special permissions to search for. Example: -rws--x--x

**CACHE**

Cache search results so that thez can be reused by other search requests (speeds up other modules). This option should be a string as caching key to be used for storing (and reading) cached results.

**READ_CACHE**

Read results from cache (stored in a previous search request or stored by another module).

**SESSION**

Which session to use, which can be viewed with `sessions -l`

**SUID**

Find all SUID files

**TESTMODE**

For testing: use a pre-definded updatedb file (for not running updatedb - which takes a while)

**UPDATEDB_FILE**

Use a custom updatedb file

**WORLD_WRITEABLE**

Find all world writeable files


## Scenario
```
msf post(updatedb) > set FIND sshd
FIND => sshd
msf post(updatedb) > set SUID true
SUID => true
msf post(updatedb) > options

Module options (post/unix/general/updatedb):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   CACHE                             no        a token to cache the results of the search
   FIND             sshd             no        A string to search for files (regex is ok)
   LS                                no        cached "ls -l" of a file
   PERMS                             no        Find all files with special permissions
   READ_CACHE                        no        a token to read cached results
   SESSION          1                yes       The session to run this module on.
   SUID             true             no        Find all SUID files
   TESTMODE         true             no        Load a pre-defined test database (for testing)
   UPDATEDB_FILE                     no        Path to a local pre-created updatedb file (created with "find")
   WORLD_WRITEABLE                   no        Find all world writeable files


[*] Found files for sshd:
[*] /etc/init.d/sshd
[*] /etc/conf.d/sshd
[*] /etc/pam.d/sshd
[*] /etc/ssh/sshd_config
[*] /usr/sbin/sshd
[*] /usr/lib64/systemd/system/sshd.socket
[*] /usr/lib64/systemd/system/sshd.service
[*] /usr/lib64/systemd/system/sshd@.service
[*] /usr/share/man/cat5/sshd_config.5.bz2
[*] /usr/share/man/cat8/sshd.8.bz2
[*] /usr/share/doc/openssh-5.9_p1-r4/sshd_config.bz2
[*] Suid files:
[*] /sbin/unix_chkpwd
[*] /bin/passwd
[*] /bin/mount
[*] /bin/ping
[*] /bin/ping6
[*] /bin/umount
[*] /bin/su
[*] /usr/sbin/traceroute6
[*] /usr/bin/expiry
[*] /usr/bin/chfn
[*] /usr/bin/gpasswd
[*] /usr/bin/newgrp
[*] /usr/bin/chage
[*] /usr/bin/chsh
[*] /usr/lib64/misc/ssh-keysign
[*] /usr/lib64/misc/glibc/pt_chown
[*] /usr/lib32/misc/glibc/pt_chown
```

