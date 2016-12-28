This module dumps UTMP/WTMP logfiles. Because these logfiles are binary files it tries to guess the right structure and parses it.

## Module Options

**FILES**

Define a special file to dump. If not defined typical log file locations are checked

**USE_UPDATEDB**

Use or created (if not already created) updatedb for finding logfiles

**SESSION**

Which session to use, which can be viewed with `sessions -l`


## Scenario
```
msf post(dump_utmp) > set SESSION 1
SESSION => 1
msf post(dump_utmp) > set FILES /tmp/logfile_utmp_1
FILES => /tmp/logfile_utmp_1
msf post(dump_utmp) > run

[*] ==========================================
ut_type              [user process                            ]
ut_pid               [14039                                   ]
ut_line              [pts/0                                   ]
ut_id                [808416116                               ]
ut_user              [litxxxxx                                ]
ut_host              [128-000-00-00.ip.xxxxxxxxxxx.com        ]
ut_exit              [0                                       ]
ut_tv_sec            [2000-01-01 16:56:41 +0100               ]
ut_tv_usec           [0                                       ]
ut_session           [990921                                  ]
ut_addr_v6           [IPv4 127.127.127.0                      ]
unused               [                                        ]

==========================================
ut_type              [dead process                            ]
ut_pid               [14039                                   ]
ut_line              [pts/0                                   ]
ut_id                [0                                       ]
ut_user              [                                        ]
ut_host              [                                        ]
ut_exit              [0                                       ]
ut_tv_sec            [2000-01-01 17:00:14 +0100               ]
ut_tv_usec           [0                                       ]
ut_session           [51583                                   ]
ut_addr_v6           [none                                    ]
unused               [                                        ]

==========================================
ut_type              [user process                            ]
ut_pid               [7751                                    ]
ut_line              [pts/0                                   ]
ut_id                [808416116                               ]
ut_user              [loxxxxxx                                ]
ut_host              [dsxx-127-127-127-127.pools.xxxxxxip.net ]
ut_exit              [0                                       ]
ut_tv_sec            [2000-01-10 19:20:32 +0100               ]
ut_tv_usec           [0                                       ]
ut_session           [433397                                  ]
ut_addr_v6           [IPv4 127.00.127.127                     ]
unused               [                                        ]

```
