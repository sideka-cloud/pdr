# PDR
PowerShell Detection and Response

<h3>How to Install</h3>

Clone repository > then copy file pdr.ps1 and pdr.xml to C:\

Edit in the section
$threshold = 6 -> maximum number of failed rdp logins; if more than 6, then it will be automatically blocked
$rdpPort = 3389 -> RDP port, please adjust it
In the PDR.ps1 file, if there is 1 IP address detected to be carrying out a brute force rdp attack, then the IP that will be blocked is 1 subnet /24. For example, if the IP that carries out the attack is 192.168.10.100, then the IP that will be blocked is the subnet 192.168.10.0/24 in other words, there will be 256 IPs that will be blocked

Open Task Scheduler > Import Task > import file pdr.xml > select pdr and Run


