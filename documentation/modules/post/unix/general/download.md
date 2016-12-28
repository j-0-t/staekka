Downloading files faster via HTTP. This module starts a local web server and uploads files using wget or curl to the metasploit session system.
This module can speed up file upload and avoid various issues with uploading big files using the "normal" upload.
Attention: on text files sometimes there is no newline at end of file appended, so the uploaded file differs to original file.

## Module Options

**LFILE**

Where to store the uploaded file on the local system

**RFILE**

Remote file/path to download

**SRVHOST**

IP of the local web server. The module usus this IP to connect for downloading the file

**SRVPORT**

The port of the local web server.

**SESSION**

Which session to use, which can be viewed with `sessions -l`


**URIPATH**

The URI to use for this module (default is random)

**SSL**

Start using SSL (https) for encrypted connections.
Attention: SSL cert is generated on the fly and NOT checked. Therefore it is possible to man in the middle here!

## Scenario
```
msf post(download) > set SRVHOST 127.0.0.1
SRVHOST => 127.0.0.1
msf post(download) > set SRVPORT 8443
SRVPORT => 8443
msf post(download) > set SESSION 1
SESSION => 1
msf post(download) > set LFILE /tmp/downloaded_file
LFILE => /tmp/downloaded_file
msf post(download) > set RFILE /bin/bash
RFILE => /bin/bash
msf post(download) > set SSL true
SSL => true
msf post(download) > run

[*] Using URL: https://127.0.0.1:8443/24xEh22t1Ed
[*] Using URL: https://127.0.0.1:8443/xCpzcitoLeOyZwY
[*] Server stopped.
[*] Post module execution completed
msf post(download) > sessions  -i 1 -c "md5sum /bin/bash /tmp/downloaded_file"
[*] Running 'md5sum /bin/bash /tmp/downloaded_file' on shell session 1 (::1)
md5sum /bin/bash /tmp/downloaded_file
be774712af8a58858476aca86e50ea77  /bin/bash
be774712af8a58858476aca86e50ea77  /tmp/downloaded_file

```

