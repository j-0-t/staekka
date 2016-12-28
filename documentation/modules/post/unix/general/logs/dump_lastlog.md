This module dumps lastlog logfiles. Because these logfiles are binary files it tries to guess the right structure and parses it.

## Module Options

**FILES**

Define a special file to dump. If not defined the common path for Linux and Solaris is checked for a lastlog file

**USE_UPDATEDB**

Use or created (if not already created) updatedb for finding logfiles

**SESSION**

Which session to use, which can be viewed with `sessions -l`


## Scenario
```
msf auxiliary(interactive) > use post/unix/general/logs/dump_lastlog
msf post(dump_lastlog) > set SESSION 1
SESSION => 1
msf post(dump_lastlog) > set FILES /tmp/logfile_lastlog
FILES => /tmp/logfile_lastlog
msf post(dump_lastlog) > run

[*] root             pts/1      localhost:20.0   2000-01-01 22:47:10 +0100
bin                                          **Never logged in**
daemon                                       **Never logged in**
adm                                          **Never logged in**
lp                                           **Never logged in**
...

```
