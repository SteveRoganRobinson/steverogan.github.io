# ===============================
# TCPDUMP COMMAND REFERENCE
# ===============================

# List available interfaces
tcpdump -D

# Capture packets from loopback interface with Hex + ASCII
sudo tcpdump -i lo -X

# Capture packets from loopback interface in ASCII only
sudo tcpdump -i lo -A

# ===============================
# INTERFACE + FILTER COMMANDS
# ===============================

# Default capture on <network interface>
sudo tcpdump -i <network interface>

# Capture without resolving DNS or service names
sudo tcpdump -i <network interface> -n

# Capture packets to/from a specific host
sudo tcpdump -i <network interface> -n host <ip address>

# Filter by source IP
sudo tcpdump -i <network interface> -n src <ip address>

# Filter by destination IP
sudo tcpdump -i <network interface> -n dst <ip address>

# Capture packets from/to an entire network
sudo tcpdump -i <network interface> -n net <network>/CIDR

# Capture packets by specific port
sudo tcpdump -i <network interface> -n port <port number>

# Filter by source port
sudo tcpdump -i <network interface> -n src port <port number>

# Source IP and source port combination
sudo tcpdump -i <network interface> -n src <ip address> and src port <port number>

# Exclude a specific port
sudo tcpdump -i <network interface> -n src <ip address> and not port <port number>

# Complex filter with source, destination, and port exclusion
sudo tcpdump -i <network interface> -n 'src <ip address> and dst <ip address> and not (port <port number> or port <port number>)'

# ICMP traffic only (e.g., ping)
sudo tcpdump -i <network interface> -n icmp

# UDP traffic only
sudo tcpdump -i <network interface> -n udp

# TCP traffic only
sudo tcpdump -i <network interface> -n tcp

# ARP traffic only
sudo tcpdump -i <network interface> -n arp

# ===============================
# WRITE & READ PCAP FILES
# ===============================

# Save packets to a file
sudo tcpdump -i <network interface> -n -w ~/Desktop/output.pcap

# Read packets from a saved pcap file
sudo tcpdump -i <network interface> -n -r ~/Desktop/output.pcap

# Count packets in a capture file
tcpdump -r <file.pcap> --count

# Read only first N packets from capture
tcpdump -r <file.pcap> -c <number>

# Read without timestamps
tcpdump -r <file.pcap> -t

# Show timestamps in raw seconds
tcpdump -r <file.pcap> -tt

# Show timestamps as delta between packets
tcpdump -r <file.pcap> -ttt

# Show full readable date and time
tcpdump -r <file.pcap> -tttt

# ===============================
# PCAP INVESTIGATION SAMPLES
# ===============================

# Show packets with timestamps
tcpdump -tt -r <file.pcap>

# Filter HTTP GET/POST requests on port 80
tcpdump -r <file.pcap> -tt port 80 | grep -E "GET|POST"

# Look for malicious .exe files
tcpdump -r <file.pcap> -tt port 80 | grep -E "<filename>.exe"

# Extract payload for deeper analysis (N lines after match)
tcpdump -r <file.pcap> -tt -A | grep -E "<filename>.exe" -A <number> | less

# ===============================
# IP & PORT STATISTICS
# ===============================

# Count unique source IPs in TCP traffic
tcpdump -tt -r <file.pcap> -n tcp | cut -d " " -f 3 | cut -d "." -f 1-4 | sort | uniq -c | sort -nr

# Count unique destination IPs in TCP traffic
tcpdump -tt -r <file.pcap> -n tcp | cut -d " " -f 5 | cut -d "." -f 1-4 | sort | uniq -c | sort -nr

# Count ports used by a specific source-destination pair
tcpdump -tt -r <file.pcap> -n tcp and src <ip address> and dst <ip address> | cut -d " " -f 3 | cut -d "." -f 5 | sort | uniq -c | sort -nr

# ===============================
# BEHAVIORAL + MALWARE SIGNS
# ===============================

# Detect GET/POST requests between suspected hosts
tcpdump -tt -r <file.pcap> src <ip address> and dst <ip address> | grep -E "GET|POST"

# Extract ASCII content between suspected hosts
tcpdump -tt -r <file.pcap> src <ip address> and dst <ip address> -c <number> -A

# Detect known malicious User-Agent
tcpdump -tt -r <file.pcap> | grep "User-Agent: <malicious-agent>"

# Capture all traffic to/from specific malicious IP
tcpdump -tt -r <file.pcap> host <ip address>

# Search for exposed credentials
tcpdump -tt -r <file.pcap> host <ip address> -A | grep -i 'user\|pass\|login' | grep -v User-Agent

# Look for suspicious filename patterns
tcpdump -tt -r <file.pcap> host <ip address> -A | grep "filename"

# Look for Telegram links (C2 indicator)
tcpdump -tt -r <file.pcap> | grep "t.me"

# Scan for DLL file mentions
tcpdump -tt -r <file.pcap> | grep dll -A <number>

# ===============================
# ANALYSIS CHECKLIST
# ===============================

# - Inspect all GET and POST requests
# - Look for unknown or suspicious User-Agents
# - Trace IPs with repeated malicious behavior
# - Check for .exe, .dll, or hidden file references
# - Look for Telegram links or C2 indicators
# - Decode any suspicious URL and check with VirusTotal

