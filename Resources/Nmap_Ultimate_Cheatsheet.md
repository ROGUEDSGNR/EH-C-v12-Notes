# Nmap Cheatsheet

## Basic Syntax

`nmap [Scan Type(s)] [Options] {target specification}`



## Scan Types and Commands

| Command       | Description                                  | Example                         | Use-Case                                    |
| ------------- | -------------------------------------------- | ------------------------------- | ------------------------------------------- |
| `-sS`         | TCP SYN scan (default and most popular scan) | `nmap -sS <target>`             | Quick and stealthy scan to check open ports |
| `-sT`         | TCP connect scan                             | `nmap -sT <target>`             | Useful when SYN scan isn't an option        |
| `-sU`         | UDP scan                                     | `nmap -sU <target>`             | Scan for open UDP ports                     |
| `-sP` / `-sn` | Ping scan                                    | `nmap -sn <target>`             | Determine which hosts are up                |
| `-sA`         | TCP ACK scan                                 | `nmap -sA <target>`             | Map out firewall rulesets                   |
| `-sW`         | TCP Window scan                              | `nmap -sW <target>`             | Detect open ports via TCP window size       |
| `-sM`         | TCP Maimon scan                              | `nmap -sM <target>`             | Bypass firewalls and packet filters         |
| `-sN`         | TCP Null scan                                | `nmap -sN <target>`             | Scan with no flags set (stealthy)           |
| `-sF`         | TCP FIN scan                                 | `nmap -sF <target>`             | Stealthy scan using FIN flag                |
| `-sX`         | TCP Xmas scan                                | `nmap -sX <target>`             | Stealthy scan with FIN, PSH, URG flags      |
| `-sI`         | Idle scan                                    | `nmap -sI <zombie IP> <target>` | Scan without revealing your IP              |
| `-sO`         | IP protocol scan                             | `nmap -sO <target>`             | Identify IP protocols supported by target   |
| `-sV`         | Version detection                            | `nmap -sV <target>`             | Detect service versions                     |
| `-sC`         | Script scan using default scripts            | `nmap -sC <target>`             | Perform a script scan using default scripts |

## Target Specification

| Command               | Description                                | Example                          | Use-Case                                           |
| --------------------- | ------------------------------------------ | -------------------------------- | -------------------------------------------------- |
| `<target>`            | Single target (IP or hostname)             | `nmap 192.168.1.1`               | Scan a single host                                 |
| `<target1> <target2>` | Multiple targets                           | `nmap 192.168.1.1 192.168.1.2`   | Scan multiple specific hosts                       |
| `range`               | IP range                                   | `nmap 192.168.1.1-254`           | Scan a range of IP addresses                       |
| `CIDR`                | Network with CIDR notation                 | `nmap 192.168.1.0/24`            | Scan an entire subnet                              |
| `-iL`                 | Input from list of hosts                   | `nmap -iL list.txt`              | Scan hosts listed in a file                        |
| `-iR`                 | Scan a random set of hosts                 | `nmap -iR 100`                   | Scan random hosts (useful for internet-wide scans) |
| `--exclude`           | Exclude hosts/networks                     | `nmap --exclude 192.168.1.1`     | Exclude specific hosts from scan                   |
| `--excludefile`       | Exclude list of hosts/networks from a file | `nmap --excludefile exclude.txt` | Exclude hosts listed in a file                     |

## Scan Options

| Command               | Description                                                             | Example                               | Use-Case                                    |
| --------------------- | ----------------------------------------------------------------------- | ------------------------------------- | ------------------------------------------- |
| `-p`                  | Scan specific ports                                                     | `nmap -p 22,80,443 <target>`          | Scan specific ports                         |
| `-p-`                 | Scan all 65535 ports                                                    | `nmap -p- <target>`                   | Scan all ports on a target                  |
| `-F`                  | Fast scan (limited number of ports)                                     | `nmap -F <target>`                    | Quick scan of the most common ports         |
| `--top-ports`         | Scan top N most common ports                                            | `nmap --top-ports 100 <target>`       | Scan top N common ports                     |
| `-r`                  | Scan ports consecutively (do not randomize)                             | `nmap -r <target>`                    | Scan ports in order                         |
| `--version-intensity` | Set version detection intensity (0 to 9)                                | `nmap --version-intensity 5 <target>` | Adjust detail level of version detection    |
| `-A`                  | Enable OS detection, version detection, script scanning, and traceroute | `nmap -A <target>`                    | Comprehensive scan for detailed information |

## Output Options

| Command      | Description                                       | Example                          | Use-Case                                     |
| ------------ | ------------------------------------------------- | -------------------------------- | -------------------------------------------- |
| `-oN`        | Normal output to file                             | `nmap -oN output.txt <target>`   | Save results in a human-readable format      |
| `-oX`        | XML output to file                                | `nmap -oX output.xml <target>`   | Save results in XML format                   |
| `-oG`        | Grepable output to file                           | `nmap -oG output.gnmap <target>` | Save results in a grepable format            |
| `-oA`        | Output in all formats (normal, XML, and grepable) | `nmap -oA output <target>`       | Save results in all formats                  |
| `-v` / `-vv` | Increase verbosity level                          | `nmap -v <target>`               | Increase output verbosity                    |
| `-d`         | Increase debugging level                          | `nmap -d <target>`               | Increase debugging level for troubleshooting |

## Timing and Performance

| Command                 | Description                                      | Example                                     | Use-Case                                             |
| ----------------------- | ------------------------------------------------ | ------------------------------------------- | ---------------------------------------------------- |
| `-T0` to `-T5`          | Set timing template (0 - paranoid, 5 - insane)   | `nmap -T4 <target>`                         | Adjust scan speed to balance stealth and performance |
| `--min-hostgroup`       | Set minimum number of hosts to scan in parallel  | `nmap --min-hostgroup 10 <target>`          | Control parallel host scanning                       |
| `--max-hostgroup`       | Set maximum number of hosts to scan in parallel  | `nmap --max-hostgroup 50 <target>`          | Control parallel host scanning                       |
| `--min-parallelism`     | Set minimum number of probes to send in parallel | `nmap --min-parallelism 10 <target>`        | Control parallel probe sending                       |
| `--max-parallelism`     | Set maximum number of probes to send in parallel | `nmap --max-parallelism 100 <target>`       | Control parallel probe sending                       |
| `--min-rtt-timeout`     | Set minimum RTT timeout                          | `nmap --min-rtt-timeout 100ms <target>`     | Control minimum RTT timeout                          |
| `--max-rtt-timeout`     | Set maximum RTT timeout                          | `nmap --max-rtt-timeout 1000ms <target>`    | Control maximum RTT timeout                          |
| `--initial-rtt-timeout` | Set initial RTT timeout                          | `nmap --initial-rtt-timeout 500ms <target>` | Set initial RTT timeout                              |
| `--max-retries`         | Set maximum number of retries                    | `nmap --max-retries 3 <target>`             | Limit the number of retries                          |
| `--host-timeout`        | Set maximum time for host scan                   | `nmap --host-timeout 60m <target>`          | Limit scan time per host                             |
| `--scan-delay`          | Set delay between probes                         | `nmap --scan-delay 100ms <target>`          | Add delay between probes for stealth                 |
| `--max-scan-delay`      | Set maximum delay between probes                 | `nmap --max-scan-delay 1s <target>`         | Limit delay between probes                           |

## Firewalls/IDS Evasion and Spoofing

| Command                | Description                            | Example                                       | Use-Case                                   |
| ---------------------- | -------------------------------------- | --------------------------------------------- | ------------------------------------------ |
| `-f`                   | Fragment packets                       | `nmap -f <target>`                            | Bypass simple packet filters and firewalls |
| `-D`                   | Decoy scan                             | `nmap -D RND:10 <target>`                     | Hide scan source using decoy addresses     |
| `-S`                   | Spoof source address                   | `nmap -S 192.168.1.2 <target>`                | Use a different source IP address          |
| `-e`                   | Use specified interface                | `nmap -e eth0 <target>`                       | Specify network interface to use           |
| `-g` / `--source-port` | Use given source port                  | `nmap -g 53 <target>`                         | Use a specific source port                 |
| `--data-length`        | Append random data to sent packets     | `nmap --data-length 50 <target>`              | Evade detection by varying packet sizes    |
| `--ip-options`         | Send packets with specified ip options | `nmap --ip-options "A" <target>`              | Use IP options for packet customization    |
| `--ttl`                | Set IP time-to-live field              | `nmap --ttl 64 <target>`                      | Set custom TTL values                      |
| `--spoof-mac`          | Spoof MAC address                      | `nmap --spoof-mac 00:11:22:33:44:55 <target>` | Use a different MAC address                |

## NSE (Nmap Scripting Engine)

| Command             | Description                     | Example                                                                  | Use-Case                              |
| ------------------- | ------------------------------- | ------------------------------------------------------------------------ | ------------------------------------- |
| `--script`          | Select script(s) to run         | `nmap --script=default <target>`                                         | Run specific NSE scripts              |
| `--script-args`     | Provide arguments to scripts    | `nmap --script=http-brute --script-args http-brute.path=/admin <target>` | Pass arguments to scripts             |
| `--script-trace`    | Show all data sent and received | `nmap --script-trace --script=default <target>`                          | Debug scripts by tracing network data |
| `--script-updatedb` | Update script database          | `nmap --script-updatedb`                                                 | Refresh NSE script database           |
| `--script-help`     | Show help about scripts         | `nmap --script-help http-brute`                                          | Get help for a specific script        |

## Additional Options

| Command | Description          | Example            | Use-Case                |
| ------- | -------------------- | ------------------ | ----------------------- |
| `-6`    | Enable IPv6 scanning | `nmap -6 <target>` | Scan targets using IPv6 |
