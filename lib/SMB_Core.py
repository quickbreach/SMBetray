import random
import string
import traceback
import logging
import struct
from impacket.smb3structs import SMB2Packet, SMB2_DIALECT_311, SMB2_DIALECT_302, SMB2_DIALECT_30, SMB2_DIALECT_21, SMB2_DIALECT_002
from impacket.smb import NewSMBPacket, SMB_DIALECT

from impacket import ntlm
from binascii import hexlify
from impacket import crypto
import copy
import os
import hmac
import hashlib

import time
import calendar
import struct
from Crypto.Hash import MD4

class SystemInfo(object):
	SUPPORTED_DIALECTS 			= []

	# For when the system is acting as the SMB server
	SIGNATURES_ENABLED	= False
	ENCRYPTION_ENABLED 	= False
	SIGNATURES_REQUIRED	= False
	ENCRYPTION_REQUIRED	= False
	NTLM_SUPPORTED		= False
class FileRequestStruct(object):
	FILE_NAME 				= ""
	FILE_GUID 				= ""
	FILE_BYTE_SIZE 			= 0
	FILE_BYTES_CAPUTRED 	= 0

	DOWNLOADED 				= False
	LOCAL_OUT_FILE 			= ""

	IS_INJECTED_FILE 		= False
	IS_BACKDOOR_TARGET 		= False
	LOCAL_FILE_PATH 		= ""

	


class PoppedCreds:
	def __init__(self, username = "", password = "(unknown)", domain = "", lm_hash = "", nt_hash = ""):
		self.username 	= username
		self.password 	= password
		self.domain 	= domain
		self.lm_hash 	= lm_hash
		self.nt_hash 	= nt_hash	# Raw, not the hexlified version
		if(nt_hash == ""):
			hash_obj 		= MD4.new()
			hash_obj.update(password.encode("utf-16le"))
			self.nt_hash 	= hash_obj.digest()
		self.NTResponse = hmac.new(self.nt_hash, self.username.upper().encode('utf-16le') + self.domain.encode('utf-16le')).digest()
	def __hash__(self):
		return hash((self.username, self.password, self.domain, self.nt_hash, self.NTResponse))
class NTLMV2_Struct(object):
	NEGOTIATE_INFO 		= ntlm.NTLMAuthNegotiate()
	CHALLENGE_INFO 		= ntlm.NTLMAuthChallenge()
	RESPONSE_INFO 		= ntlm.NTLMAuthChallengeResponse()

	def getNtProofString(self):
		#
		return self.RESPONSE_INFO['ntlm'][:16]
	def getBasicData(self):
		responseServerVersion 	= self.RESPONSE_INFO['ntlm'][16]
		hiResponseServerVersion = self.RESPONSE_INFO['ntlm'][17]
		aTime 					= self.RESPONSE_INFO['ntlm'][24:32]
		clientChallenge 		= self.RESPONSE_INFO['ntlm'][32:40]
		serverChallenge 		= self.CHALLENGE_INFO['challenge']
		serverName				= self.RESPONSE_INFO['ntlm'][44:]
		basicData = responseServerVersion + hiResponseServerVersion + '\x00' * 6 + aTime + clientChallenge + '\x00' * 4 + serverName
		return basicData
	def getExtended(self):
		#
		return (self.RESPONSE_INFO['flags'] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY == ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
	def getExchangedKey(self):
		return self.RESPONSE_INFO['session_key']

	# Returns DOMAIN/USERNAME
	def getUser(self):
		return self.RESPONSE_INFO['domain_name'].decode("utf-16-le").encode("utf-8").upper() + "/" + self.RESPONSE_INFO['user_name'].decode("utf-16-le").encode("utf-8").upper()

	# NtProofString		= HMAC_MD5(NTResponse, basicData)

# A keyring easily managing for SMB session, signing, sealing, etc. keys as well as kerberos session keys
class SMBKey:
	def __init__(self, sessionBaseKey = "", dialect = SMB2_DIALECT_30, kerbSessionKey = "", kerbServiceSessionKey = ""):
		self.SESSION_BASE_KEY 		= sessionBaseKey[:16]
		self.DIALECT 				= dialect
		self.SERVER_SIGNING_KEY 	= ""
		self.CLIENT_SIGNING_KEY 	= ""

		self.SERVER_ENCRYPTION_KEY 	= ""
		self.SERVER_DECRYPTION_KEY 	= ""

		self.CLIENT_ENCRYPTION_KEY 	= ""
		self.CLIENT_DECRYPTION_KEY 	= ""
		self.APPLICATION_KEY 		= ""

		self.KERBEROS_SESSION_KEY 			= kerbSessionKey 		# The users AS-REP KerberosSessionKey
		self.KERBEROS_SERVICE_SESSION_KEY	= kerbServiceSessionKey	# The ServiceSessionKey from the TGS

		if(self.KERBEROS_SERVICE_SESSION_KEY != ""):
			self.SESSION_BASE_KEY = self.KERBEROS_SERVICE_SESSION_KEY[:16]

		self.generateKeys()
	def setDialect(self, dialect):
		self.DIALECT = dialect
		self.generateKeys()
	def generateKeys(self):
		# SMB2 and earlier don't use a KDF
		if(self.DIALECT in [SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21]):
			self.SERVER_SIGNING_KEY 	= self.SESSION_BASE_KEY
			self.CLIENT_SIGNING_KEY 	= self.SESSION_BASE_KEY
			self.SERVER_ENCRYPTION_KEY	= self.SESSION_BASE_KEY
			self.SERVER_DECRYPTION_KEY	= self.SESSION_BASE_KEY
			self.CLIENT_ENCRYPTION_KEY	= self.SESSION_BASE_KEY
			self.CLIENT_DECRYPTION_KEY	= self.SESSION_BASE_KEY
			self.APPLICATION_KEY 		= self.SESSION_BASE_KEY
			return

		if(self.DIALECT in [SMB2_DIALECT_30, SMB2_DIALECT_302, SMB2_DIALECT_311]):
			self.CLIENT_SIGNING_KEY 	= crypto.KDF_CounterMode(self.SESSION_BASE_KEY, "SMB2AESCMAC\x00", "SmbSign\x00", 128)
			self.SERVER_SIGNING_KEY 	= crypto.KDF_CounterMode(self.SESSION_BASE_KEY, "SMB2AESCMAC\x00", "SmbSign\x00", 128)

			self.CLIENT_ENCRYPTION_KEY  = crypto.KDF_CounterMode(self.SESSION_BASE_KEY, "SMB2AESCCM\x00", "ServerIn \x00", 128)
			self.CLIENT_DECRYPTION_KEY	= crypto.KDF_CounterMode(self.SESSION_BASE_KEY, "SMB2AESCCM\x00", "ServerOut \x00", 128)
			
			self.SERVER_ENCRYPTION_KEY  = self.CLIENT_DECRYPTION_KEY
			self.SERVER_DECRYPTION_KEY  = self.CLIENT_ENCRYPTION_KEY

			self.APPLICATION_KEY 		= crypto.KDF_CounterMode(self.SESSION_BASE_KEY, "SMB2APP\x00", "SmbRpc\x00", 128)
			return	
	
	# Generate the appropriate signature,
	# per the dialect specifications,
	# using the appropriate key
	def sign(self, packet, as_client = True):
		# NT LM 0.12
		if self.DIALECT == SMB_DIALECT:
			packet['SecurityFeatures'] = '\x00' * 8
			# TODO: Add contingency for when a a SigningChallengeResponse is used
			# # https://msdn.microsoft.com/en-us/library/cc246343.aspx
			z = hashlib.md5()
			if as_client:
				z.update(self.CLIENT_SIGNING_KEY)
			else:
				z.update(self.SERVER_SIGNING_KEY)
			z.update(str(packet))
			return z.digest()[:8]
		# 2.0.2, 2.1.0
		if self.DIALECT in [SMB2_DIALECT_002, SMB2_DIALECT_21]:
			packet['Signature'] = '\x00' * 16
			if as_client:
				return hmac.new(self.CLIENT_SIGNING_KEY, str(packet), hashlib.sha256).digest()[:16]
			else:
				return hmac.new(self.SERVER_SIGNING_KEY, str(packet), hashlib.sha256).digest()[:16]
		# 3.0.0, 3.0.2, 3.1.1
		if self.DIALECT in [SMB2_DIALECT_30, SMB2_DIALECT_302, SMB2_DIALECT_311]:
			packet['Signature'] = '\x00' * 16
			if as_client:
				return crypto.AES_CMAC(self.CLIENT_SIGNING_KEY, str(packet), len(str(packet)))
			else:
				return crypto.AES_CMAC(self.SERVER_SIGNING_KEY, str(packet), len(str(packet)))
	def __str__(self):
		data = "SessionKey: \t" + hexlify(self.SESSION_BASE_KEY) + "\n"
		data += "ServerSigningKey: \t" + hexlify(self.CLIENT_SIGNING_KEY) + "\n"
		data += "ClientSigningKey: \t" + hexlify(self.SERVER_SIGNING_KEY) + "\n"
		data += "krbSessionKey: \t" + hexlify(self.KERBEROS_SESSION_KEY) + "\n"
		data += "krbServiceSessionKey: \t" + hexlify(self.KERBEROS_SERVICE_SESSION_KEY) + "\n"
		return data
	def __hash__(self):
		combined = str(str(self.SESSION_BASE_KEY) + str(self.CLIENT_SIGNING_KEY) + str(self.SERVER_SIGNING_KEY) + str(self.KERBEROS_SESSION_KEY))
		killer = hashlib.md5()
		killer.update(combined)
		self.checksum = hexlify(killer.digest())
		return hash(self.checksum)


class SMB_Core(object):
	# Share the self.info dict from the MiTMModule
	def __init__(self, data, MiTMModuleConfig = dict()):
		# Stateful variables
		self.info 					= data 				# The EasySharedMemory object passed from the SMBetray MiTMModule
		self.MiTMModuleConfig 		= MiTMModuleConfig 	# The same MiTMModuleConfig from the parent MiTMModule, loaded by the MiTMServer
		self.SMB1_DIALECT_INDEX 	= -1 	# Used by negotiateReq_StripSMBDialects and negotiateResp_StripSMBDialects
		self.DIALECT 				= None 	# To be replaced with the impacket.smb.SMB dialect settled on (eg SMB_DIALECT)
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
		self.PREAUTH_PACKET_STACK 	= []	# A list of SMB2Packets to calculate the preauth integerity hash in case SMB3.1.1 is used
		self.KNOWN_KEY 				= None 	# To be replaced with an SMBKey if we have the creds & crack the session key
		self.NTLMV2_DATASTORE 		= []	# Stores all captured NTLMv2 negotiate, challenge, and challenge response messages (for hashes and for session key cracking)
		self.CREDS_DATASTORE 		= []	# Stores all of the domains/users/passwords from the popped-credentials file

		# File injection variables
		self.INJECTION_ACTIVE 		= False # If a client requested a 'fake file' that we injected, then we don't forward their request to the server - instead, an SMB Echo request
		self.INJECTION_REQ_DATA 	= dict()# A dict of SMB packets (message_id is their key) to be parsed by the fullMasquaradeServer 
		self.INJECTED_FILE_TRACKER 	= dict()# A list of full paths to files we have injected into directories. This keeps track for when we recieve a request for one
		self.INJECT_FILE_LIBRARY 	= dict()# Just a list of FileRequestStructs of the injected files
		


		


	# Split up "Stacked" SMB headers and parse them seperately. 
	# This is for when SMB2 uses the "NextCommand" option (aka ChainOffset)
	def splitSMBChainedMessages(self, data):
		try:
			smbMessages = []
			# SMB v1
			if(data[4:8] == '\xff\x53\x4d\x42'):
				z 		= 4
				nx 		= data.find('\xff\x53\x4d\x42', z + 1)
				while nx > -1:
					smbMessages.append(NewSMBPacket(data = data[z:nx]))
					z 		= nx
					nx 		= data.find('\xff\x53\x4d\x42', z + 1)
				# Required after the last iteration to get the remaining data 
				smbMessages.append(NewSMBPacket(data = copy.deepcopy(data[z:])))
				return smbMessages

			# SMB v2
			elif(data[4:8] == '\xfe\x53\x4d\x42'):
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
			logging.error("[SMB_Core::splitSMBChainedMessages] " + str(traceback.format_exc()))
			return data
	def restackSMBChainedMessages(self, SMBPacketList):
		try:
			# Takes in a list of NewSMBPacket or SMB2Packets	
			if SMBPacketList[0].__class__.__name__ == 'SMB2Packet':	
				reStacked = ""
				for i in range(0, len(SMBPacketList)):
					if(i < len(SMBPacketList) - 1):
						SMBPacketList[i]['NextCommand'] = len(str(SMBPacketList[i])) + ((8 - (len(str(SMBPacketList[i])) % 8)) % 8)
						SMBPacketList[i]['Data'] = SMBPacketList[i]['Data'] + str('\x00' * ((8 - (len(str(SMBPacketList[i])) % 8)) % 8)) #Padding
					else:
						SMBPacketList[i]['NextCommand'] = 0
					reStacked += str(SMBPacketList[i])
				netbios = struct.pack('>i', len(str(reStacked)))
				# Return the ready-to-send packet
				return str(netbios) + str(reStacked)

			if SMBPacketList[0].__class__.__name__ == 'NewSMBPacket':
				# SMBv1 Uses ANDX to chain messages

				# TODO: fix this
				reStacked = ""
				for i in range(0, len(SMBPacketList)):
					reStacked += str(SMBPacketList[i])
				netbios = struct.pack('>i', len(str(reStacked)))
				# Return the ready-to-send packet
				return str(netbios) + str(reStacked)

		except Exception, e:
			logging.error("[SMB_Core::restackSMBChainedMessages] " + str(traceback.format_exc()))
			return SMBPacketList

	# Returns a list of supported dialects as constants,
	# such as SMB_DIALECT and SMB2_DIALECT_302
	def getServerSupportedDialects(self, ip, port = 445):
		'''Connects to the specified server on the provided port(445 default) and enumeratesSMBKey the supported dialects'''
		dialects = [SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, SMB2_DIALECT_302 ]#, SMB2_DIALECT_311]
		
		# Check SMBv1
		try:
			# Build a generic SMBv1 negotiate packet and only show support for SMBv1
			smb 	= NewSMBPacket(data = unhexlify("ff534d4272000000001845680000000000000000000000000000ed4300000100000e00024e54204c4d20302e3132000200"))
			rawData = str(smb)
			netbios = struct.pack('>i', len(str(rawData)))
			rpkt 	= str(netbios) + str(rawData)
			# Connect through
			client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			client.connect((ip, port))
			client.sendall(rpkt)
			response = client.recv(999999)
			client.close()
			del(client)
		except Exception, e:
			# It's not supported, bummer
			dialects.remove(SMB_DIALECT)
		else:
			# SMB1 is supported, cool
			pass

		# Check SMB 2.0.2
		try:
			# Generic smb2 packet
			smbHeader = SMB2Packet(unhexlify("fe534d42400001000000000000001f0000000000000000000000000000000000fffe000000000000000000000000000000000000000000000000000000000000"))
			
			# Here's a generic negotiate protocol request
			# - just modify the client GUID to prevent
			# AV/IDS fingerprinting
			negProto = SMB2Negotiate(unhexlify("24000500010000007f000000cb78cd146438e7119168000c291232a370000000020000000202100200030203110300000100260000000000010020000100c8c31f28d43563c829b9070423e96a98701ac3ec788a3ac01573ee03d07d942600000200060000000000020002000100"))
			

			negProto['Dialects'] = [SMB2_DIALECT_002, 0, 0, 0, 0, 0]
			negProto['ClientGuid'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
			rawData = str(smbHeader) + str(negProto)
			netbios = struct.pack('>i', len(str(rawData)))
			rpkt = str(netbios) + str(rawData)
			
			# Connect through
			client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			client.connect((ip, port))
			client.sendall(rpkt)
			response = client.recv(999999)
			client.close()
			del(client)

			# See if the protocol is supported
			resp = SMB2Packet(response[4:])
			if(resp['Status'] != 0):
				raise
			else:
				pass
		except Exception, e:
			# It's not supported
			dialects.remove(SMB2_DIALECT_002)
		else:
			# SMB 2.0.2 is supported
			pass

		# Check SMB 2.1.0
		try:
			# Generic smb2 packet
			smbHeader = SMB2Packet(unhexlify("fe534d42400001000000000000001f0000000000000000000000000000000000fffe000000000000000000000000000000000000000000000000000000000000"))
			
			# Here's a generic negotiate protocol request
			# - just modify the client GUID to prevent
			# AV/IDS fingerprinting
			negProto = SMB2Negotiate(unhexlify("24000500010000007f000000cb78cd146438e7119168000c291232a370000000020000000202100200030203110300000100260000000000010020000100c8c31f28d43563c829b9070423e96a98701ac3ec788a3ac01573ee03d07d942600000200060000000000020002000100"))
			

			negProto['Dialects'] = [SMB2_DIALECT_21, 0, 0, 0, 0, 0]
			negProto['ClientGuid'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
			rawData = str(smbHeader) + str(negProto)
			netbios = struct.pack('>i', len(str(rawData)))
			rpkt = str(netbios) + str(rawData)
			
			# Connect through
			client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			client.connect((ip, port))
			client.sendall(rpkt)
			response = client.recv(999999)
			client.close()
			del(client)

			# See if the protocol is supported
			resp = SMB2Packet(response[4:])
			if(resp['Status'] != 0):
				raise
			else:
				pass
		except Exception, e:
			# It's not supported
			dialects.remove(SMB2_DIALECT_21)
		else:
			# SMB 2.1.0 is supported
			pass

		# Check SMB 3.0
		try:
			# Generic smb2 packet
			smbHeader = SMB2Packet(unhexlify("fe534d42400001000000000000001f0000000000000000000000000000000000fffe000000000000000000000000000000000000000000000000000000000000"))
			
			# Here's a generic negotiate protocol request
			# - just modify the client GUID to prevent
			# AV/IDS fingerprinting
			negProto = SMB2Negotiate(unhexlify("24000500010000007f000000cb78cd146438e7119168000c291232a370000000020000000202100200030203110300000100260000000000010020000100c8c31f28d43563c829b9070423e96a98701ac3ec788a3ac01573ee03d07d942600000200060000000000020002000100"))
			

			negProto['Dialects'] = [SMB2_DIALECT_30, 0, 0, 0, 0, 0]
			negProto['ClientGuid'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
			rawData = str(smbHeader) + str(negProto)
			netbios = struct.pack('>i', len(str(rawData)))
			rpkt = str(netbios) + str(rawData)
			
			# Connect through
			client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			client.connect((ip, port))
			client.sendall(rpkt)
			response = client.recv(999999)
			client.close()
			del(client)

			# See if the protocol is supported
			resp = SMB2Packet(response[4:])
			if(resp['Status'] != 0):
				raise
			else:
				pass
		except Exception, e:
			# It's not supported
			dialects.remove(SMB2_DIALECT_30)
		else:
			# SMB 2.1.0 is supported
			pass

		# Check SMB 3.0.2
		try:
			# Generic smb2 packet
			smbHeader = SMB2Packet(unhexlify("fe534d42400001000000000000001f0000000000000000000000000000000000fffe000000000000000000000000000000000000000000000000000000000000"))
			
			# Here's a generic negotiate protocol request
			# - just modify the client GUID to prevent
			# AV/IDS fingerprinting
			negProto = SMB2Negotiate(unhexlify("24000500010000007f000000cb78cd146438e7119168000c291232a370000000020000000202100200030203110300000100260000000000010020000100c8c31f28d43563c829b9070423e96a98701ac3ec788a3ac01573ee03d07d942600000200060000000000020002000100"))
			

			negProto['Dialects'] = [SMB2_DIALECT_302, 0, 0, 0, 0, 0]
			negProto['ClientGuid'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
			rawData = str(smbHeader) + str(negProto)
			netbios = struct.pack('>i', len(str(rawData)))
			rpkt = str(netbios) + str(rawData)
			
			# Connect through
			client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			client.connect((ip, port))
			client.sendall(rpkt)
			response = client.recv(999999)
			client.close()
			del(client)

			# See if the protocol is supported
			resp = SMB2Packet(response[4:])
			if(resp['Status'] != 0):
				raise
			else:
				pass
		except Exception, e:
			# It's not supported
			dialects.remove(SMB2_DIALECT_302)
		else:
			# SMB 2.1.0 is supported
			pass

		'''
		# Check SMB 3.1.1
		try:
			# Generic smb2 packet
			smbHeader = SMB2Packet(unhexlify("fe534d42400001000000000000001f0000000000000000000000000000000000fffe000000000000000000000000000000000000000000000000000000000000"))
			
			# Here's a generic negotiate protocol request
			# - just modify the client GUID to prevent
			# AV/IDS fingerprinting
			negProto = SMB2Negotiate(unhexlify("24000500010000007f000000cb78cd146438e7119168000c291232a370000000020000000202100200030203110300000100260000000000010020000100c8c31f28d43563c829b9070423e96a98701ac3ec788a3ac01573ee03d07d942600000200060000000000020002000100"))
			

			negProto['Dialects'] = [SMB2_DIALECT_311, 0, 0, 0, 0, 0]
			negProto['ClientGuid'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
			rawData = str(smbHeader) + str(negProto)
			netbios = struct.pack('>i', len(str(rawData)))
			rpkt = str(netbios) + str(rawData)
			
			# Connect through
			client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			client.connect((ip, port))
			client.sendall(rpkt)
			response = client.recv(999999)
			client.close()
			del(client)

			# See if the protocol is supported
			resp = SMB2Packet(response[4:])
			if(resp['Status'] != 0):
				raise
			else:
				pass
		except Exception, e:
			# It's not supported
			dialects.remove(SMB2_DIALECT_311)
		else:
			# SMB 2.1.0 is supported
			pass
		'''


		return dialects

	# Repeats the SMB1 action in getServerSupportedDialects.
	# I carved this out of getServerSupportedDialects so that
	# it only executes this one critical check during a time sensitive
	# negotiation operation
	def checkServerSupportSMB1(self, ip, port = 445):
		# Check SMBv1
		try:
			# Build a generic SMBv1 negotiate packet and only show support for SMBv1
			smb 	= NewSMBPacket(data = unhexlify("ff534d4272000000001845680000000000000000000000000000ed4300000100000e00024e54204c4d20302e3132000200"))
			rawData = str(smb)
			netbios = struct.pack('>i', len(str(rawData)))
			rpkt 	= str(netbios) + str(rawData)
			# Connect through
			client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			client.connect((ip, port))
			client.sendall(rpkt)
			response = client.recv(999999)
			client.close()
			del(client)
		except Exception, e:
			# It's not supported, bummer
			return False
		else:
			return True

	# Connects to the target on SMB1 and SMB2.
	# Checks and fills out all of the items in the SystemInfo
	# class
	def profileServer_SMB1(self, ip, port = 445):
		# Checkout SMB1 support & security requirements
		logging.debug("Inspecting SMBv1 support on " + self.MiTMModuleConfig['target_ip'])

		# Build a generic SMBv1 negotiate packet and only show support for SMBv1
		smb 	= NewSMBPacket(data = unhexlify("ff534d4272000000001845680000000000000000000000000000ed4300000100000e00024e54204c4d20302e3132000200"))
		rawData = str(smb)
		netbios = struct.pack('>i', len(str(rawData)))
		rpkt 	= str(netbios) + str(rawData)

		# If the connection resets - they don't support it
		try:
			# Connect through
			client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			client.connect((self.MiTMModuleConfig['target_ip'], self.MiTMModuleConfig['target_port']))
			client.sendall(rpkt)
			response = client.recv(999999)
			client.close()
			del(client)
		except:
			# If they dropped the connection, SMB1 is disabled
			logging.debug(self.MiTMModuleConfig['target_ip'] + " does not support SMBv1 :(")
			# Remove it from the supported dialects list, if it was even there
			if SMB_DIALECT in self.SERVER_INFO.SUPPORTED_DIALECTS:
				self.SERVER_INFO.SUPPORTED_DIALECTS.remove(SMB_DIALECT)
				return
		else:
			# No way dude
			logging.debug(self.MiTMModuleConfig['target_ip'] + " supports SMBv1!")
			self.SERVER_INFO.SUPPORTED_DIALECTS.append(SMB_DIALECT)

		# Checkout the security
		resp 		= NewSMBPacket(data = response[4:])
		respData 	= SMBCommand(resp['Data'][0])
		dialectData = SMBNTLMDialect_Parameters(respData['Parameters'])
		authData 	= SPNEGO_NegTokenInit(respData['Data'][16:])

		# Give it to me straight doc
		if dialectData['SecurityMode'] & SMB.SECURITY_SIGNATURES_ENABLED:
			logging.debug("Server supports SMB signing")
			self.SERVER_INFO.SERVER_SIGNATURES_ENABLED = True
		if dialectData['SecurityMode'] & SMB.SECURITY_SIGNATURES_REQUIRED:
			logging.debug("Server requires signatures :(")
			self.SERVER_INFO.SERVER_SIGNATURES_REQUIRED = True
		else:
			logging.debug("Server does not require signatures!")


		# Check if NTLM auth is supported
		if spnego.TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider'] in authData['MechTypes']:
			logging.debug("Server supports NTLM auth!")
			self.SERVER_INFO.SERVER_NTLM_SUPPORTED = True
		else:
			self.SERVER_INFO.SERVER_NTLM_SUPPORTED = False

	pass
