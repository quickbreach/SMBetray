# SMBetray
Version 1.0.0. This tool is a PoC to demonstrate the ability of an attacker to intercept and modify insecure SMB connections, as well as compromise some secured SMB connections if credentials are known. 

# Background
Released at Defcon26 at "SMBetray: Backdooring and Breaking Signatures". (Details will be uploaded to blog later: quickbreach.io)

# Installation
Requires a system using iptables
	sudo bash install.sh 

# Usage
	./smbetray.py --help

# Features
- Passively download any file sent over the wire in cleartext
- Downgrade clients to NTLMv2 instead of Kerberos
- Inject files into directories when view by a client
- Replace all files with a LNK with the same name to execute a provided command upon clicking
- Replace only executable files with a LNK with the same name to execute a provided command upon clicking
- Replace files with extension X with the contents of the file with extension X in the local provided directory
- Replace files with the case-insensitive name X with the contents of the file sharing hte same name in the provided directory 


# Notice:
More information to come - currently the tool does not support SMBv1 only connections, which is not a problem 99% of the time. 
