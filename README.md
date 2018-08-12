# SMBetray
Version 1.0.0. This tool is a PoC to demonstrate the ability of an attacker to intercept and modify insecure SMB connections, as well as compromise some secured SMB connections if credentials are known. 

# Background
Released at Defcon26 at "SMBetray - Backdooring and Breaking Signatures"

In SMB connections, the security mechanisms protecting the integrity of the data passed between the server and the client are known as SMB signing and encryption. The signatures are based on keys derived from information obtained in cleartext during the authentication phase, as well the user's password. If the password of the user is known, an attacker can re-create the SessionBaseKey and all other SMB keys and leverage them to modify SMB packets, and re-sign them so that they are treated as valid and legitimate packets by the server and client. Additionally, signing is disabled by default on everything except for domain controllers, so the need to break the signatures is often not needed. 

This goal of this tool is to switch the aim of MiTM on SMB from attacking the server through relayed connections, to attacking the client through malicious files and backdoored/replaced data when the oppertunity strikes. Finally, since encryption is rarely ever used, at the bare minimum this tool allows for the stealing of files passed in cleartext over the network - which can prove useful for system enumeration, or damaging if the data intercepted is sensitive in nature (PCI, PII, etc).

More background info and demos can be found here http://quickbreach.io/2018/08/12/smbetray-backdooring-and-breaking-signatures/

# Installation
Requires a system using iptables

	sudo bash install.sh 

# Usage
First, run a bi-directional arp-cache poisoning attack between your victim, and their gateway or destination network shares, eg:

	sudo arpspoof -i <iface> -c both -t <target_ip> -r <gateway_ip>

Then run smbetray with some attack modules 

	sudo ./smbetray.py --passive ./StolenFilesFolder --lnkSwapAll "powershell -noP -sta -w 1 -enc AABCAD....(etc)" -I eth0

# Demo
A demo of the tool can be found here: quickbreach.io

# Features
- Passively download any file sent over the wire in cleartext
- Downgrade clients to NTLMv2 instead of Kerberos
- Inject files into directories when view by a client
- Replace all files with a LNK with the same name to execute a provided command upon clicking
- Replace only executable files with a LNK with the same name to execute a provided command upon clicking
- Replace files with extension X with the contents of the file with extension X in the local provided directory
- Replace files with the case-insensitive name X with the contents of the file sharing hte same name in the provided directory 


# Notice:
More information to come - currently the tool does not support SMBv1 only connections, which is not a problem 99% of the time. The code is ugly, but it has a great personality.
