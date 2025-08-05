
# OSINT Notes

## SOC Puppets

Sock Puppets are decoy or burner accounts created for ethical hacking/OSINT investigations without revealing the true identity.

### Blogs to Create Effective Sock Puppets
- [Creating an Effective Sock Puppet for OSINT Investigations – Introduction](https://web.archive.org/web/20210125191016/https://jakecreps.com/2018/11/02/sock-puppets/)
- [The Art Of The Sock – Secjuice](https://www.secjuice.com/the-art-of-the-sock-osint-humint/)
- [Reddit - My process for setting up anonymous sockpuppet accounts](https://www.reddit.com/r/OSINT/comments/dp70jr/my_process_for_setting_up_anonymous_sockpuppet/)

### Tools
- Name Generator: [Fake Name Generator](https://www.fakenamegenerator.com/)
- AI Profile Picture: [This Person Does Not Exist](https://www.thispersondoesnotexist.com/)
- Virtual Cards: [Privacy.com](https://privacy.com/join/LADFC)

## Search Engine Google Dorks

Example queries:
- site:exampleuniversity.edu department of electrical engineering
- "professor" AND "cybersecurity" AND "research" site:researchportal.edu
- "mentor" AND "cybersecurity" site:mentorship.org
- site:targetcompany.com password
- site:targetcompany.com pass filetype:pdf OR filetype:docx OR filetype:xlsx
- "target name" inurl:password

Use [Google Advanced Search](https://www.google.com/advanced_search) for GUI-based refining.

## Reverse Image Search

- [Google Images](https://images.google.com)
- [Yandex](https://yandex.com)
- [TinEye](https://tineye.com)

## View EXIF Metadata

- [Jimpl](https://jimpl.com/)
- exiftool <img> (Linux/Kali)

## Physical Location OSINT

- [Google Maps Satellite View](https://maps.google.com)
- [GeoGuessr Practice](https://www.geoguessr.com/)
- [Geo OSINT Blog](https://somerandomstuff1.wordpress.com/2019/02/08/geoguessr-the-top-tips-tricks-and-techniques/)

## Email OSINT

- Google name + role + company
- Confirm with LinkedIn
- Use [Hunter.io](https://hunter.io/), [Phonebook.cz](https://phonebook.cz/), [VoilaNorbert](https://www.voilanorbert.com/)
- Verify: [Verify-Email](https://tools.verifyemailaddress.io/), [Email Checker](https://email-checker.net/validate)

## Breached Data OSINT

- [DeHashed](https://dehashed.com/)
- [Scylla.sh](https://scylla.sh/)
- [WeLeakInfo](https://weleakinfo.to/v2/)
- [SnusBase](https://snusbase.com/)
- [HaveIBeenPwned](https://haveibeenpwned.com/)

## Username & Account Enumeration

- [NameChk](https://namechk.com/)
- [WhatsMyName](https://whatsmyname.app/)
- [NameCheckup](https://namecheckup.com/)

## People Search

- [WhitePages](https://www.whitepages.com/)
- [TruePeopleSearch](https://www.truepeoplesearch.com/)
- [PeekYou](https://peekyou.com/)
- [Spokeo](https://www.spokeo.com/)
- [411](https://www.411.com/)
- [That'sThem](https://thatsthem.com/)

## Voter Records OSINT

- [VoterRecords](https://www.voterrecords.com/)

## Phone Number OSINT

- [TrueCaller](https://www.truecaller.com/)
- [CallerID Test](https://calleridtest.com/)
- [Infobel](https://infobel.com/)

## Discovering Birthdates

Use Google:
"Heath Adams Birthday"

## Resume Hunting

Google Dorks:
- "John Doe" resume filetype:pdf
- site:linkedin.com "John Doe"

## Twitter OSINT

Examples:
- from:username
- to:username
- @username
- geocode:lat,long,distance
- filter:media, filter:links

- [Twitter Advanced Search](https://twitter.com/search-advanced)
- Tools: [OSINT Twitter Tools](https://github.com/rmdir-rp/OSINT-twitter-tools)

## Facebook OSINT

- [Sowdust](https://sowsearch.info/)
- [IntelligenceX](https://intelx.io/tools?tab=facebook)

## Instagram OSINT

- Hashtags, tagged photos, mutuals
- Tools: [imginn.com](https://imginn.com/)
- Google Dorks: site:instagram.com "username"

## Snapchat OSINT

- [Snap Maps](https://map.snapchat.com/)

## Reddit OSINT

- site:reddit.com "username"
- Tools: Pushshift, RedditSearch.io

## LinkedIn OSINT

- Work history, education, connections
- Mutuals, skill endorsements

## Business OSINT (for tcm-sec.com)

- [OpenCorporates](https://opencorporates.com/)
- [AIHIT](https://www.aihitdata.com/)
- Scrape employee data from LinkedIn
- Job Descriptions reveal tools & infra used

## Website OSINT

- [BuiltWith](https://builtwith.com/)
- [VirusTotal](https://www.virustotal.com/)
- [SpyOnWeb](https://spyonweb.com/)
- [crt.sh](https://crt.sh/)
- [dnsdumpster](https://dnsdumpster.com/)
- [Shodan](https://shodan.io)
- [Wayback Machine](https://web.archive.org/)

## Wireless OSINT

- [WiGLE](https://wigle.net/)

## Kali Tools

### Email & Breach Data
- [DeHashed API](https://github.com/hmaverickadams/DeHashed-API-Tool)

### Username OSINT
sudo apt install sherlock
sherlock targetname

### Phone Number OSINT
bash <( curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install )
phoneinfoga scan -n <number>

### Social Media Tools
- [OSINT Social Media Tools](https://github.com/osintambition/Social-Media-OSINT-Tools-Collection)

## OSINT Automation

whois tcm-sec.com
subfinder -d tcm-sec.com
assetfinder tcm-sec.com
amass enum -d tcm-sec.com
cat domains.txt | sort -u | httprobe -s -p https:443
gowitness file -f ./alive.txt -P ./pics --no-http

This markdown was created for OSINT operations with a focus on tcm-sec.com.
