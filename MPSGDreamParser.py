#!/usr/bin/env python

# Pentesting XML Parser - A parser to convert NMAP and Nessus output into pentest friendly files.
#
# Description:
#   Performs conversion of a valid NMAP .xml output file
#   or Tenable Nessus .xml report file into into
#   pentesting friendly output files formatted depending 
#   on the given options.
#
# Author:
#   Jessa (@manicPxiSIEMGirl)
#
###########################################################

###########################################################
#
# To Do:
#  1) smb version nmap scan parse
#  2) smb signing nmap scan parse
#  3) Clean up writing to host file creation
#  4) Hostname only host files
#  4) Host file sorting?
#  5) Nessus Parsing for csv
#  6) ADExplorer Parsing for bloodhound
#
###########################################################

import xml.etree.ElementTree as ET
import codecs
import sys
import argparse
import os.path

class convert:
	def __init__(self, inputFile, inputType, outputLocation, outputType, verbose):
		self.__inputFile = inputFile
		self.__inputType = inputType
		self.__outputLocation = outputLocation
		self.__outputType = outputType
		self.__hostname = ''
		self.__ip = ''
		self.__id = ''
		self.__protocol = ''
		self.__port = ''
		self.__service = ''
		self.__verbose = verbose

	def identifyID(self):
		try:
			if self.__hostname is None:
				self.__id = self.__ip
			else:
				try:
					testHostname = str(self.__hostname).split(".")
					if(testHostname[2] is None):
						self.__id = self.__ip
					else:
						self.__id = self.__hostname
				except:
					self.__id = self.__ip
		except:
			self.__id = self.__ip
			sys.exit(1)

	def outputPingSweepToSubnetFile(self):
		try:
			subnetSTR = str(self.__ip).split(".")
			subnet= subnetSTR[0] + "." + subnetSTR[1] + "." + subnetSTR[2] + ".0/24"
		except:
			print("invalid ip address"+self.__ip)
			return None
		count = 0
		try:
			f = open(self.__outputLocation, "r")
			for line in f:
				if line == subnet + "\n":
					count = 1
					break
			f.close()
		except:
			count = 0
		if count == 0:
			f = open(self.__outputLocation, "a")
			f.write(subnet + "\n")
			f.close()
		count = 0
			
	def outputPortScanToTXTHostFile(self):
		try:
			count = 0
			
			#Printers
			if int(self.__port) == 21 and int(self.__port) == 83 and int(self.__port) == 9100 or int(self.__port) == 161 and int(self.__port) == 80 or int(self.__port) == 161 and int(self.__port) == 443 or int(self.__port) == 139 or int(self.__port) == 21 and int(self.__port) == 23 and int(self.__port) == 23: 
				try:
					f = open(self.__outputLocation+'printerHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'printerHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0

			#SMB / Windows
			if self.__port == '445':
				try:
					f = open(self.__outputLocation+'smbHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'smbHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0

			#MSSQL
			if self.__port == '1433':
				try:
					f = open(self.__outputLocation+'mssqlHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'mssqlHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0

			#MySQL
			if self.__port == '3306':
				try:
					f = open(self.__outputLocation+'mysqlHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'mysqlHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0

			#Postgres
			if self.__port == '1432':
				try:
					f = open(self.__outputLocation+'postgresHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'postgresHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0

			#Oracle
			if self.__port == '1521':
				try:
					f = open(self.__outputLocation+'oracleHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'oracleHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0

			#SSH
			if self.__port == '22':
				try:
					f = open(self.__outputLocation+'sshHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'sshHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0
			
			#telnet
			if self.__port == '23':
				try:
					f = open(self.__outputLocation+'telnetHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'telnetHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0

			#FTP
			if self.__port == '21':
				try:
					f = open(self.__outputLocation+'ftpHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'ftpHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0

			#VNC
			if self.__port == '5900' or self.__port == '5800' :
				try:
					f = open(self.__outputLocation+'vncHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'vncHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0
			
			#SNMP
			if self.__port == '161':
				try:
					f = open(self.__outputLocation+'snmpHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'snmpHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0
			
			#X11
			if int(self.__port) >= 6000 and int(self.__port) <= 6063:
				try:
					f = open(self.__outputLocation+'x11HostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'x11HostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0
			
			#Web
			if int(self.__port) == 80 or int(self.__port) == 81 or int(self.__port) == 443 or int(self.__port) == 8000 or int(self.__port) == 8008 or int(self.__port) == 8080 or int(self.__port) == 8081 or int(self.__port) == 8443 or int(self.__port) == 9000 or int(self.__port) == 9080:
				try:
					f = open(self.__outputLocation+'webHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'webHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0

			#DNS
			if self.__port == '53':
				try:
					f = open(self.__outputLocation+'dnsHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'dnsHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0

			#RDP
			if self.__port == '3389':
				try:
					f = open(self.__outputLocation+'rdpHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'rdpHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0
					
			#MongoDB
			if self.__port == '27017':
				try:
					f = open(self.__outputLocation+'mongodbHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'mongodbHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0			
				
			#VoIP
			if int(self.__port) == 5060 or int(self.__port) == 5061 or int(self.__port) == 5068 or int(self.__port) >= 8500:
				try:
					f = open(self.__outputLocation+'voipHostsAll.txt', "r")
					for line in f:
						if line == self.__id + "\n":
							count=count+1
					f.close()
				except:
					count = 0
				if count == 0:
					f = open(self.__outputLocation+'voipHostsAll.txt', "a")
					f.write(self.__id + "\n")
					f.close()
				count = 0

			#All hosts
			try:
				f = open(self.__outputLocation+'_HostsAll.txt', "r")
				for line in f:
					if line == self.__id + "\n":
						count=count+1
				f.close()
			except:
				count = 0
			if count == 0:
				f = open(self.__outputLocation+'_HostsAll.txt', "a")
				f.write(self.__id + "\n")
				f.close()
			count = 0

		except:
			print("error with files and stuff. This shouldn't happen. How did you do that? I blame Harry")
			sys.exit(1)

	def outputOutboundPortScanFile(self):
		try:
			hostname = self.__hostname
			ip = self.__ip
			protocol = self.__protocol
			port = self.__port
			service = self.__service
			f = open(self.__outputLocation + ".csv", "a")
			writeString = hostname+","+ip+","+protocol+","+port+","+service+"\n"
			f.write(writeString)
			f.close()
		except:
			print("failed in csv creation")
			sys.exit(1)

		try:
			port = self.__port
			f = open(self.__outputLocation + ".txt", "a")
			writeString = port+"\n"
			f.write(writeString)
			f.close()
		except:
			print("failed in txt creation")
			sys.exit(1)

	def outputPortScanToCSVFile(self):
		try:
			hostname = self.__hostname
			ip = self.__ip
			protocol = self.__protocol
			port = self.__port
			service = self.__service
			f = open(self.__outputLocation, "a")
			writeString = hostname+","+ip+","+protocol+","+port+","+service+"\n"
			f.write(writeString)
			f.close()
		except:
			sys.exit(1)

	def convert(self):
		try:
			if self.__verbose == True:
				print("Attempting to parse xml input file root...")
			tree = ET.parse(self.__inputFile)
			root = tree.getroot()
		except:
			print('Input file not found. Please ensure the file is a valid .xml file stored in ',self.__inputFile)
			sys.exit(1)

		try:
			#Port Scans
			if self.__inputType == 'port':
				hostnameSTR = '-'
				for host in root.findall('host'):
					if self.__verbose == True:
						print("## Host ##")
					ipaddress = host.find('address')
					if self.__verbose == True:
						print('       # IP:',ipaddress.attrib)
					try:
						hostnames = host.find('hostnames')
						hostname = hostnames.find('hostname')
						hostnameSTR = str(hostname.attrib).split("'")
					except:
						hostnameSTR = ['{', 'name', ': ', '-', 'type', ': ', '-', '}']
					if self.__verbose == True:
						print('       # Hostname:',hostnameSTR)
					for port in host.iter('port'):
						try:
							service = port.find('service')
							serviceSTR = str(service.attrib).split("'")
						except:
							serviceSTR = ['{', 'name', ': ', 'Unknown', '}']
						ipSTR = str(ipaddress.attrib).split("'")
						if self.__verbose == True:
							print(ipSTR)
						if self.__verbose == True:
							print(hostnameSTR)
						portSTR = str(port.attrib).split("'")
						if self.__verbose == True:
							print(portSTR)
						if self.__verbose == True:
							print(serviceSTR)
						if self.__inputType is None:
							self.__inputType = 'port'
						if self.__outputType is None:
							self.__outputType = 'txt'
						if self.__verbose == True:
							print("Done Parsing Attempting to output...")
							
						#Convert Port Scans
						if self.__inputType == 'port':
							if self.__outputType == 'txt':
								self.__hostname = hostnameSTR[3]
								self.__ip = ipSTR[3]
								self.__port = portSTR[7]
								if self.__verbose == True:
									print(self.__hostname, self.__ip, self.__port)
								self.identifyID()
								self.outputPortScanToTXTHostFile()
							else:
								self.__hostname = hostnameSTR[3]
								self.__ip = ipSTR[3]
								self.__protocol = portSTR[3]
								self.__port = portSTR[7]
								self.__service = serviceSTR[3]
								if self.__verbose == True:
									print(self.__hostname, self.__ip, self.__protocol, self.__port, self.__service)
								try:
									b = open(self.__outputLocation, "r")
									b.close()
								except:
									f = open(self.__outputLocation, "a")
									writeString = "Hostname, IP Address, Protocol, Port, Service" + "\n"
									f.write(writeString)
									f.close()
								self.outputPortScanToCSVFile()
						if self.__verbose == True:
							print("Done outputting port")

		except:
			print("Failed to process port scans")
			sys.exit(1)

		try:
			#Ping Sweeps
			if self.__inputType == 'ping':
				if self.__verbose == True:
					print("Attempting to parse ping sweep xml input attributes...")
				for host in root.findall('host'):
					for ipaddress in host.iter('address'):
						ipSTR = str(ipaddress.attrib).split("'")

						#Convert Ping Sweeps
						if self.__inputType == 'ping':
							self.__ip = ipSTR[3]
							self.outputPingSweepToSubnetFile()
		except:
			print("Failed to process ping sweeps")
			sys.exit(1)

		try:
			#Outbound Port Scans
			if self.__inputType == 'outboundPort':
				if self.__verbose == True:
					print("Attempting to parse outbound port scan xml input attributes...")
				for host in root.findall('host'):
					for ipaddress in host.iter('address'):
						for hostname in host.iter('hostname'):
							for port in host.iter('port'):
								for service in host.iter('service'):
									ipSTR = str(ipaddress.attrib).split("'")
									hostnameSTR = str(hostname.attrib).split("'")
									portSTR = str(port.attrib).split("'")
									serviceSTR = str(service.attrib).split("'")
								
									#Convert Outbound Port Scans
									self.__hostname = hostnameSTR[3]
									self.__ip = ipSTR[3]
									self.__protocol = portSTR[3]
									self.__port = portSTR[7]
									self.__service = serviceSTR[3]
									try:
										b = open(self.__outputLocation+'.csv', "r")
										b.close()
									except:
										f = open(self.__outputLocation+'.csv', "a")
										writeString = "Hostname, IP Address, Protocol, Port, Service" + "\n"
										f.write(writeString)
										f.close()
									self.outputOutboundPortScanFile()
		except:
			print("Failed to process outbound port scans")
			sys.exit(1)


			#SMB Version
			#SMB Signing
			#Nessus

# Process command-line arguments.
if __name__ == '__main__':
	# Explicitly changing the stdout encoding format
	if sys.stdout.encoding is None:
		# Output is redirected to a file
		sys.stdout = codecs.getwriter('utf8')(sys.stdout)
	argParser = argparse.ArgumentParser(add_help = True, description = "Performs conversion of a valid NMAP .xml output file "
														"into into pentesting friendly output files formatted "
														"depending on the given options.")
	argParser.add_argument('-inputFile', action='store', help='input nmap file in xml format')
	argParser.add_argument('-inputType', choices=['ping', 'port', 'outboundPort', 'smbVersion', 'smbSigning', 'nessus'], default='port', help='inputed nmap file type')
	argParser.add_argument('-outputDirectory', action='store', help='output directory')
	argParser.add_argument('-outputFile', action='store', help='output file')
	argParser.add_argument('-outputType', choices=['txt', 'csv'], default='txt', help='outputed file type; csv currently not implemented')
	argParser.add_argument('-v', action=argparse.BooleanOptionalAction, help='enable verbose output for debugging')

	outputLocation = ''

	#Print out announcement
	print("MPSGDreamParser.py - Version 4.1 - Updated 3/21/24")

	#Error check empty expected items
	if len(sys.argv)==1:
		argParser.print_help()
		sys.exit(1)
	options = argParser.parse_args()
	if options.inputFile is None:
		print("An input file must be specified. This file should be an XML file.")
		sys.exit(1)
	if options.inputType is None:
		print("Please specify an input type with -inputType")
		sys.exit(1)
	if options.outputFile is None and not(options.inputType == 'port' and options.outputType == 'txt'):
		print("Please specify an output file name with -outputFile")
		sys.exit(1)
	if options.outputDirectory is None:
		options.outputDirectory ="./"
	if options.outputType is None:
		print("Please specify an output type with -outputType")
		sys.exit(1)
	if options.v == True:
		print('inputFile=',options.inputFile)
		print('inputType=',options.inputType)
		print('outputFile=',options.outputFile)
		print('outputDirectory=',options.outputDirectory)
		print('outputType=',options.outputType)
		print('verbose=',options.v)
		
	#Append and handle file extensions and directory traversal
	try:
		if not(os.path.isdir(options.outputDirectory)):
			print("Please provide a valid directory path, or check permissions on the folder. The provided directory was: ",options.outputDirectory)
			sys.exit(1)
	except:
		sys.exit(1)
	if not(str(options.outputDirectory).endswith("/")):
		options.outputDirectory = options.outputDirectory + "/"
	if options.outputType == 'txt' and not(str(options.outputFile).endswith(".txt")) and not(options.inputType == 'outboundPort'):
		options.outputFile = str(str(options.outputFile) + ".txt")
	if options.outputType == 'csv' and not(str(options.outputFile).endswith(".csv")) and not(options.inputType == 'outboundPort'):
		options.outputFile = str(str(options.outputFile) + ".csv")
	if str(options.outputFile).endswith(".txt"):
		options.outputType == 'txt'
	else:
		if str(options.outputFile).endswith(".csv"):
			options.outputType + ".csv"
		else:
			if not(options.inputType == 'outboundPort'):
				print("Invalid file extension. Please use .txt or .csv for output types.")
				sys.exit(1)

	#Create outputLocation
	if str(options.outputDirectory).endswith("/"):
		if str(options.outputFile).endswith(".txt") or str(options.outputFile).endswith(".csv"):
			if options.inputType == 'port' or options.inputType == 'nessus':
				outputLocation = str(options.outputDirectory)
				if str(options.outputFile).endswith(".csv"):
					outputLocation = str(str(outputLocation) + str(options.outputFile))
			else:
				outputLocation = str(str(options.outputDirectory) + str(options.outputFile))
		else:
			if options.inputType == 'outboundPort':
				outputLocation = str(str(options.outputDirectory) + str(options.outputFile))

	#Restrict usage of invalid option matchups
	if options.inputType == 'ping' and options.outputType == 'csv':
		print("Ping Sweep parsing does not support an output of .csv. Please use .txt")
		sys.exit(1)

	#Restrict Usage of unimplemented options
	if options.inputType == 'smbVersion' or options.inputType == 'smbSigning' or options.inputType == 'nessus':
		print("The specified input type has not yet been implemented. Currently implemented: port, ping, outbound")
		sys.exit(1)

	#Convert
	converter = convert(options.inputFile,options.inputType,outputLocation,options.outputType,options.v)
	try:
		if options.v == True:
			print("Attempting to convert file...")
		converter.convert()
	except:
		print("Conversion of nmap failed. This is due to a series of deeper failures. Maybe brush some salt into it?")
		sys.exit(1)