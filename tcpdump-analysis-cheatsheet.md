# TCPDUMP COMMAND REFERENCE

## Interface Commands

- **List available interfaces**  
  `tcpdump -D`

- **Capture packets from loopback interface with Hex + ASCII**  
  `sudo tcpdump -i lo -X`

- **Capture packets from loopback interface in ASCII only**  
  `sudo tcpdump -i lo -A`

---

## Interface + Filter Commands

- **Capture on a specific interface**  
  `sudo tcpdump -i <network interface>`

- **Capture only TCP packets**  
  `sudo tcpdump -i <network interface> tcp`

- **Capture only UDP packets**  
  `sudo tcpdump -i <network interface> udp`

- **Capture traffic from a specific IP address**  
  `sudo tcpdump -i <network interface> host <ip address>`

- **Capture traffic from a specific source IP address**  
  `sudo tcpdump -i <network interface> src <ip address>`

- **Capture traffic to a specific destination IP address**  
  `sudo tcpdump -i <network interface> dst <ip address>`

- **Capture traffic to or from a specific IP**  
  `sudo tcpdump -i <network interface> host <ip address>`

---

## Port-Based Filtering

- **Capture traffic on port 80 (HTTP)**  
  `sudo tcpdump -i <network interface> port 80`

- **Capture traffic from source port 443 (HTTPS)**  
  `sudo tcpdump -i <network interface> src port 443`

- **Capture traffic to destination port 53 (DNS)**  
  `sudo tcpdump -i <network interface> dst port 53`

---

## Writing to and Reading from Files

- **Capture and write to file**  
  `sudo tcpdump -i <network interface> -w capture.pcap`

- **Read from a .pcap file**  
  `tcpdump -r capture.pcap`

---

## Additional Options

- **Limit captured packets to 100**  
  `sudo tcpdump -i <network interface> -c 100`

- **Display with timestamps**  
  `sudo tcpdump -tttt -i <network interface>`

- **Show only packet headers (no payload)**  
  `sudo tcpdump -i <network interface> -v`

- **Show more packet details**  
  `sudo tcpdump -i <network interface> -vv`

- **Show full packet details**  
  `sudo tcpdump -i <network interface> -vvv`
