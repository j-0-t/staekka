Searchs, downloads and analyses history files. By default a pre-defined list of common history files is used. There is an option to use a short list or to use a custom list.

Checks:
* check if history file is a symlink (sometimes a link to /dev/null)
* search for passwords based on common signatures
* search for (password?) hashes
* search for "hacking" signatures
* search for interessting signatures (URLs/X11/...)
* search for possible passwords by filtering out valid commands

## Module Options

**FASTCHECK**

Do only check most common history files (faster check)

**FILES**

Define a custom list of files to check. Can be defined as full path files or ~/ for a file to check in every home directory.

**USE_UPDATEDB**

Use or created (if not already created) updatedb


**SESSION**

Which session to use, which can be viewed with `sessions -l`

## Scenario


