# Footprinting and Reconnaissance | Attack Phase 1

> #TLDR 
> Footprinting is the initial phase in assessing the security posture of a target organization's IT infrastructure. By conducting footprinting and reconnaissance, one can collect extensive information about a computer system, network, and any connected devices. Essentially, footprinting creates a security profile blueprint for an organization and should be executed systematically.

---

# Info Obtained in Footprinting
###### #Objectives

| Organization Information                             | Network Information                              | System Information                |
| ---------------------------------------------------- | ------------------------------------------------ | --------------------------------- |
| Employee details                                     | Domain and sub-domains                           | Web server OS                     |
| Telephone numbers                                    | Network blocks (IP ranges)                       | Location of web servers           |
| Branch and location details                          | Network topology, trusted routers, and firewalls | Publicly available email adresses |
| Background of the organization                       | IP adresses of reachable systems                 | Usernames and passwords           |
| Web technologies                                     | Whois records                                    |                                   |
| News articles, press releases, and related documents | DNS records                                      |                                   |
[[Footprinting Checklist]]

---

# Footprinting Methodology

## Footprinting Techniques

| Technique                                    | Sub-techniques                                      |
| -------------------------------------------- | --------------------------------------------------- |
| Footprinting through Search Engines          | Advanced Google Hacking Techniques                  |
|                                              | Google Hacking Database and Google Advanced Search  |
|                                              | Video, Meta, FTP, and IoT Search Engines            |
|                                              |                                                     |
| Footprinting through Web Services            | People Search Services                              |
|                                              | Financial Services and Job Sites                    |
|                                              | Deep and Dark Web Footprinting                      |
|                                              | Competitive Intelligence and Business Profile Sites |
|                                              | Monitor Alerts and Online Reputation                |
|                                              | Groups, Forums, Blogs, and NNTP Usenet Newsgroups   |
|                                              | Public Source Code Repositories                     |
|                                              |                                                     |
| Footprinting through Social Networking Sites | Social Engineering                                  |
|                                              | Social Media Sites                                  |
|                                              | Analyzing Social Network Graphs                     |
|                                              |                                                     |
| Website Footprinting                         | Web Spidering and Website Mirroring                 |
|                                              | Internet Archive                                    |
|                                              | Extract Links, Wordlist, and Metadata               |
|                                              | Monitor Web Page Updates and Website Traffic        |
|                                              |                                                     |
| Email Footprinting                           | Track Email Communication                           |
|                                              | Analyze Email Header                                |
|                                              |                                                     |
| Whois Footprinting                           | Whois Lookup                                        |
|                                              | IP Geolocation Lookup                               |
|                                              |                                                     |
| DNS Footprinting                             | DNS Interrogation                                   |
|                                              | Reverse DNS Lookup                                  |
|                                              |                                                     |
| Network Footprinting                         | Locate Network Range                                |
|                                              | Traceroute                                          |
|                                              |                                                     |
| Footprinting through Social Engineering      | Eavesdropping                                       |
|                                              | Shoulder Surfing                                    |
|                                              | Dumpster Diving                                     |
|                                              | Impersonation                                       |


---

# #Tools 

## Geolocation

**Ping target to get IP** then use a web service such as [IPVoid](https://www.ipvoid.com/), [Check-Host](https://check-host.net/ip-info), or [IP-Address](https://www.ip-adress.com/).

## Footprinting Through Search Engines

- [Google Advanced Search Operators | Google Hacking Database ](https://www.exploit-db.com/google-hacking-database)
	Not really hacking Google (duh!), rather than taking advantage of granular search to find potentially interesting publicly listed exploitable assets.

Objectives
- Gather information using advanced Google hacking techniques
- Gather information from video search engines
- Gather information from FTP search engines
- Gather information from IoT search engines

| Search Operator | Purpose                                                                                 |
| --------------- | --------------------------------------------------------------------------------------- |
| [cache:]        | Displays the web pages stored in the Google cache                                       |
| [link:]         | Lists web pages that have links to the specified web page                               |
| [related:]      | Lists web pages that are similar to the specified web page                              |
| [info:]         | Presents some information that Google has about a particular web page                   |
| [site:]         | Restricts the results to those websites in the given domain                             |
| [allintitle:]   | Restricts the results to those websites containing all the search keywords in the title |
| [intitle:]      | Restricts the results to documents containing the search keywords in the title          |
| [allinurl:]     | Restricts the results to those containing all the search keywords in the URL            |
| [inurl:]        | Restricts the results to documents containing the search keyword in the URL             |
| [location:]     | Finds information for a specific location                                               |

Others:

- [YouTube Metadata Tool](https://mattw.io/youtube-metadata/): Collects details of a video, its uploader, playlist, and its creator or channel.
- [TinEye Reverse Image Search](https://tineye.com)

---

## Domains and Sub-domains Enumeration
- [Netcraft](https://www.netcraft.com/tools/)
- [Sublist3r](https://github.com/aboul3la/Sublist3r)

---

## FTP Search Engines
- [Search FTPs](https://www.searchftps.net/)
- [Freeware Web](https://www.freewareweb.com/)

---

## IoT Search Engines
- [Shodan](https://www.shodan.io/)
- [Censys](https://search.censys.io/)

---

## Individuals/Employee Recon - theHarvester
> Gathers emails, subdomains, hosts, employee names, open ports, and banners from public sources like search engines and PGP key servers.

```sh
theHarvester -d evilcorp -l 200 -b linkedin
```
- `-d`: specifies the domain or company name (e.g., evilcorp)
- `-l`: number of results to retrieve
- `-b`: data source (e.g., LinkedIn)


---

## Deep and Dark Web Searching

- [The Hidden Wiki](http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki)
- [FakeID](http://ymvhtqya23wqpez63gyc3ke4svju3mqsby2awnhd3bk2e65izt7baqad.onion) for creating fake passports
- [Cardshop](http://s57divisqlcjtsyutxjz2ww77vlbwpxgodtijcsrgsuts4js5hnxkhqd.onion) for selling cards with good balances
- [ExoneraTor](https://metrics.torproject.org)
- [OnionLand Search Engine](https://onionlandsearchengine.com)

---

## Information from Various Social Networking Sites

- [Sherlock](https://github.com/sherlock-project/sherlock): Python-based tool to gather information about a target person on social networking sites.

```sh
python3 sherlock.py username
```

- [Social Searcher](https://www.social-searcher.com/)
- [Followerwonk](https://followerwonk.com/analyze): Explore and grow your social graph, and analyse Twitter analytics.

---

## Gather Information about a Target Website

- [Photon](https://github.com/s0md3v/Photon): Crawl a target URL for information like URLs, email addresses, social media accounts, files, secret keys, and subdomains.

```sh
python3 photon.py -u example.com -o output
```

- [Central Ops](https://centralops.net/co/): Free online network scanner for domains and IP addresses, DNS records, traceroute, nslookup, whois searches.
- [CeWL](https://github.com/digininja/CeWL)
- [Whois](https://whois.domaintools.com/)
- [IP2Location](https://www.ip2location.com )

---
## DNS Footprinting
> HOSTNAME 2 IP

| Record Type | Description                                      |
| ----------- | ------------------------------------------------ |
| A           | Points to a host’s IP address                    |
| MX          | Points to domain’s mail server                   |
| NS          | Points to host’s name server                     |
| CNAME       | Canonical naming allows aliases to a host        |
| SOA         | Indicate authority for a domain                  |
| SRV         | Service records                                  |
| PTR         | Maps IP address to a hostname                    |
| RP          | Responsible person                               |
| HINFO       | Host information record includes CPU type and OS |
| TXT         | Unstructured text records                        |

- [nslookup](http://www.kloth.net/services/nslookup.php)
- [DNS Dumpster](https://dnsdumpster.com/)
- [Broadband Search Network Tools](https://www.broadbandsearch.net/network-tools)
- [YouGetSignal](https://www.yougetsignal.com/)
- [SecurityTrails](https://securitytrails.com/)

---
## Reverse DNS Lookup
>IP 2 HOSTNAME - you can get all the websites hosted on determined server

- [dnsrecon](https://github.com/darkoperator/dnsrecon)

---
## Locate the Network Range
>  Traceroute analysis maps network topology by identifying the IP addresses of intermediate devices, such as routers and firewalls, between a source and its destination. It uses the ICMP protocol and the Time to Live (TTL) field in the IP header to determine the path to the target host within the network.

- **ICMP**: The default protocol for traceroute, commonly used in Unix/Linux systems. It sends ICMP Echo Request messages and waits for ICMP Echo Reply messages. It's straightforward but can be blocked by firewalls. Less reliable in environments with strict security policies that block or rate-limit ICMP traffic.
- **TCP**: Traceroute can use TCP packets, typically sending TCP SYN packets to a specific port (often port 80 for HTTP). This method is more likely to pass through firewalls and reach the target since TCP is often allowed for web traffic. Generally considered more reliable for traceroute because it is less likely to be filtered by firewalls and has built-in mechanisms for ensuring packet delivery.
- **UDP**: Used by traceroute implementations, particularly in Windows (tracert). It sends UDP packets to high-numbered ports and expects ICMP Port Unreachable messages in response when the target is reached. More reliable than ICMP in some cases but less so than TCP. Some firewalls may block high-numbered ports or UDP traffic, making it less dependable.

- `tracert` (Windows)
- `traceroute` (Linux)

---

## Footprinting through Social Engineering
>Non-technical approached attack

#### Social engineers attempt to gather
- Credit card details and social security number 
- Usernames and passwords 
- Security products in use 
- Operating systems and software versions 
- Network layout information 
- IP addresses and names of servers
#### Social engineering techniques include
- Eavesdropping 
- Shoulder surfing 
- Dumpster diving 
- Impersonation

---
## More tools
### Recon-ng
>Recon-ng is a web reconnaissance framework with independent modules and database interaction for open-source web-based reconnaissance. 
>	https://github.com/lanmaster53/recon-ng/wiki

#### Maltego
>Maltego is a footprinting tool used to gather maximum information for ethical hacking, computer forensics, and pentesting.
>	https://docs.maltego.com/support/home

---

#### OSINT Framework
- [OSINT Framework](https://osintframework.com/)
	- (T) - Indicates a link to a tool that must be installed and run locally
	- (D) - Google dork
	- (R) - Requires registration
	- (M) - Indicates a URL that contains the search term and the URL itself must be edited manually


---

### OSRFramework

> OSRFramework is a set of libraries for Open Source Intelligence tasks, including username checking, DNS lookups, information leaks research, and more.

#### domainfy
Check domain information:

```sh
domainfy -n [Domain Name] -t all
```
- `-n`: specifies a nickname or a list of nicknames to be checked.
- `-t`: specifies a list of top-level domains where the nickname will be searched.

#### searchfy
Check for the existence of a given user on different social networking platforms.

```sh
searchfy -q "target user name or profile name"
```

 usufy.py – Checks for a user profile on up to 290 different platforms
 mailfy.py – Check for the existence of a given email
 searchfy.py – Performs a query on the platforms in OSRFramework
 domainfy.py – Checks for the existence of domains
 phonefy.py – Checks for the existence of a given series of phones
 entify.py – Uses regular expressions to extract entities


---

- Recon-Dog https://github.com/s0md3v/ReconDog
- FOCA https://github.com/ElevenPaths/FOCA
- Grecon https://github.com/TebbaaX/GRecon
- Th3Inspector https://github.com/Moham3dRiahi/Th3inspector
- Raccoon https://github.com/evyatarmeged/Raccoon
- Orb https://github.com
- BillCipher https://github.com/bahatiphill/BillCipher

---

# [Footprinting Countermeasures](https://github.com/ROGUEDSGNR/EH-C-v12-Notes/blob/main/02.1-Footprinting_Countermeasures.md)

