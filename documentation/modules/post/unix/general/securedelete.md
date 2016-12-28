Overwriting and deleting files.

The following tools can be used:
* shred (usually installed)
* dd (usually installed)
* wipe
* srm
* bcwipe

## Module Options

**RFILE**

The path to the file(s) you want to wipe

**SESSION**

Which session to use, which can be viewed with `sessions -l`

## Scenario
```
msf post(secure_delete) > set SESSION 1
SESSION => 1
msf post(secure_delete) > set VERBOSE true
VERBOSE => true
msf post(secure_delete) > set RFILE /tmp/secretfile
RFILE => /tmp/secretfile
msf post(secure_delete) > run

[*] Wipe command: chattr -R +sS -u  /tmp/secretfile; find /tmp/secretfile -type f -exec  shred -f -u -z -n 3 -v {} \; ; rm -rf /tmp/secretfile; sync
chattr: Operation not supported while setting flags on /tmp/secretfile
shred: /tmp/secretfile: pass 1/4 (random)...
shred: /tmp/secretfile: pass 2/4 (random)...
shred: /tmp/secretfile: pass 3/4 (random)...
shred: /tmp/secretfile: pass 4/4 (000000)...
shred: /tmp/secretfile: removing
shred: /tmp/secretfile: renamed to /tmp/0000000000
shred: /tmp/0000000000: renamed to /tmp/000000000
shred: /tmp/000000000: renamed to /tmp/00000000
shred: /tmp/00000000: renamed to /tmp/0000000
shred: /tmp/0000000: renamed to /tmp/000000
shred: /tmp/000000: renamed to /tmp/00000
shred: /tmp/00000: renamed to /tmp/0000
shred: /tmp/0000: renamed to /tmp/000
shred: /tmp/000: renamed to /tmp/00
shred: /tmp/00: renamed to /tmp/0
shred: /tmp/secretfile: removed
[*] /tmp/secretfile is deleted
[*] Post module execution completed
msf post(secure_delete) >
```
