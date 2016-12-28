Uploading files faster via HTTP. This module starts a local web server and downloads files using wget or curl from the metasploit session.
This module can speed up file upload and avoid various issues with uploading big files using the "normal" upload.

## Module Options

**LFILE**

The local file you want to upload

**RFILE**

Remote file/path to save the file

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
msf post(upload) > set LFILE /etc/passwd
LFILE => /etc/passwd
msf post(upload) > set RFILE /tmp/uploaded_passwd
RFILE => /tmp/uploaded_passwd
msf post(upload) > set SESSION 1
SESSION => 1
msf post(upload) > set SRVHOST 192.168.1.3
SRVHOST => 192.168.1.3
msf post(upload) > set SRVPORT 8443
SRVPORT => 8443
msf post(upload) > run

[*] Using URL: http://192.168.1.3:8443/Uum6QeJ
[*] Using URL: http://192.168.1.3:8443/S4Lm3qt00oQzgWB
[*] Server stopped.
[*] Post module execution completed
msf post(upload) >
```

