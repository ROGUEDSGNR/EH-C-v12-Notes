# Reserved Ports Table

### Table 3.1: Reserved Ports Table

| Name            | Port/Protocol      | Description                                  |
| --------------- | ------------------ | -------------------------------------------- |
| echo            | 7/tcp, udp         | echo                                         |
| discard         | 9/tcp, udp         | sink null                                    |
| systat          | 11/tcp             | Users                                        |
| daytime         | 13/tcp, udp        | daytime                                      |
| netstat         | 15/tcp, udp        | netstat                                      |
| qotd            | 17/tcp, udp        | Quote                                        |
| chargen         | 19/tcp, udp        | ttytst source                                |
| ftp-data        | 20/tcp             | ftp data transfer                            |
| ftp             | 21/tcp             | ftp                                          |
| ssh             | 22/tcp             | Secure Shell                                 |
| telnet          | 23/tcp             | telnet                                       |
| SMTP            | 25/tcp             | Email server                                 |
| time            | 37/tcp, udp        | Timeserver                                   |
| rlp             | 39/tcp, udp        | resource location                            |
| domain          | 53/tcp, udp        | domain name server                           |
| sql*net         | 66/tcp             | Oracle SQL*net                               |
| bootps          | 67/udp             | bootp server                                 |
| bootpc          | 68/udp             | bootp client                                 |
| tftp            | 69/udp             | Trivial File Transfer                        |
| gopher          | 70/tcp             | gopher server                                |
| finger          | 79/tcp             | Finger                                       |
| www-http        | 80/tcp             | WWW                                          |
| www-https       | 80/tcp             | WWW                                          |
| kerberos        | 88/tcp, udp        | Kerberos                                     |
| pop2            | 109/tcp            | PostOffice V.2                               |
| pop3            | 110/tcp            | PostOffice V.3                               |
| sunrpc          | 111/tcp, udp       | RPC 4.0 portmapper                           |
| auth/ident      | 113/tcp            | Authentication Service                       |
| audionews       | 116/udp            | Audio News Multicast                         |
| nntp            | 119/tcp            | Usenet Network News Transfer                 |
| ntp             | 123/udp            | Network Time Protocol                        |
| netbios-ns      | 137/tcp, udp       | NETBIOS Name Service                         |
| netbios-dgm     | 138/tcp, udp       | NETBIOS Datagram Service                     |
| netbios-ssn     | 139/tcp            | NETBIOS Session Service                      |
| imap            | 143/tcp            | Internet Message Access Protocol             |
| sql-net         | 150/tcp            | SQL-NET                                      |
| sqlsrv          | 156/tcp            | SQL Service                                  |
| snmp            | 161/tcp, udp       | SNMP                                         |
| snmp-trap       | 162/tcp, udp       | SNMP Trap                                    |
| cmip-man        | 163/tcp            | CMIP/TCP Manager                             |
| cmip-agent      | 164/tcp, udp       | CMIP/TCP Agent                               |
| irc             | 194/tcp, udp       | Internet Relay Chat                          |
| at-rtmp         | 201/tcp, udp       | AppleTalk Routing Maintenance                |
| at-nbp          | 202/tcp, udp       | AppleTalk Name Binding                       |
| at-3            | 203/tcp, udp       | AppleTalk                                    |
| at-echo         | 204/tcp, udp       | AppleTalk Echo                               |
| at-5            | 205/tcp, udp       | AppleTalk                                    |
| at-zis          | 206/tcp, udp       | AppleTalk Zone Information                   |
| at-7            | 207/tcp, udp       | AppleTalk                                    |
| at-8            | 208/tcp, udp       | AppleTalk                                    |
| ipx             | 213/tcp, udp       | Novell                                       |
| imap3           | 220/tcp            | Interactive Mail Access Protocol v3          |
| aurp            | 387/tcp, udp       | AppleTalk Update-Based Routing Protocol      |
| netware-ip      | 396/tcp, udp       | Novell Netware over IP                       |
| rmt             | 411/tcp            | Remote mt                                    |
| kerberos-ds     | 445/tcp, udp       | Microsoft DS                                 |
| isakmp          | 500/tcp            | ISAKMP/IKE                                   |
| fcp             | 510/tcp            | First Class Server                           |
| exec            | 512/tcp            | BSD rexecd(8)                                |
| comsat/biff     | 512/udp            | Used by mail system to notify users          |
| login           | 513/tcp            | BSD rlogind(8)                               |
| who             | 513/udp            | whod BSD rwhod(8)                            |
| shell           | 514/tcp            | cmd BSD rshd(8)                              |
| syslog          | 514/udp            | BSD syslogd(8)                               |
| printer         | 515/tcp, udp       | spooler BSD lpd(8)                           |
| talk            | 517/tcp            | BSD talkd(8)                                 |
| ntalk           | 518/udp            | SunOS talkd(8)                               |
| netnews         | 532/tcp, udp       | Readnews                                     |
| uucp            | 540/tcp            | uucpd BSD uucpd(8)                           |
| klogin          | 543/tcp            | Kerberos Login                               |
| kshell          | 544/tcp            | Kerberos Shell                               |
| ekshell         | 545/tcp            | krcmd Kerberos encrypted remote shell +kfall |
| pcserver        | 600/tcp            | ECD Integrated PC board srvr                 |
| mount           | 635/tcp, udp       | NFS Mount Service                            |
| pcnfs           | 640/tcp            | PC-NFS DOS Authentication                    |
| bnfs            | 650/tcp            | BW-NFS DOS Authentication                    |
| flexlm          | 744/tcp, udp       | Flexible License Manager                     |
| kerberos-adm    | 749/tcp, udp       | Kerberos Administration                      |
| kerberos        | 750/tcp, udp       | kdc Kerberos authentication                  |
| kerberos_master | 751/tcp, udp       | Kerberos authentication                      |
| krb_prop        | 754/tcp            | Kerberos slave propagation                   |
| applix          | 999/tcp            | Applix                                       |
| socks           | 1080/tcp           | Socks Proxy                                  |
| kpop            | 1109/tcp           | Pop with Kerberos                            |
| ms-sql-s        | 1433/tcp           | Microsoft SQL Server                         |
| ms-sql-m        | 1434/tcp           | Microsoft SQL Monitor                        |
| pptp            | 1723/tcp           | pptp                                         |
| nfs             | 2049/tcp, udp      | Network File System                          |
| eklogin         | 2105/tcp           | Kerberos encrypted rlogin                    |
| rkinet          | 2110/tcp           | Kerberos remote kinit                        |
| kx              | 2111/tcp           | X over Kerberos                              |
| kauth           | 2120/tcp           | Remote kauth                                 |
| lyskom          | 4894/tcp           | LysKOM (conference system)                   |
| sip             | 5060/tcp           | Session Initiation Protocol                  |
| sip             | 5060/udp           | Session Initiation Protocol                  |
| x11             | 6000-6063/tcp, udp | X Window System                              |
| irc             | 6667/tcp           | Internet Relay Chat                          |