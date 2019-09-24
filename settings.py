#!/usr/bin/env python
# This file is part of Responder
# Original work by Laurent Gaffie - Trustwave Holdings
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import utils
import ConfigParser
import threading

from file_poller import FilePoller
from utils import *

import iptc

__version__ = 'Responder 2.3'

class Settings:

	def __init__(self):
		self.ResponderPATH = os.path.dirname(__file__)
		self.Bind_To = '0.0.0.0'

	def __str__(self):
		ret = 'Settings class:\n'
		for attr in dir(self):
			value = str(getattr(self, attr)).strip()
			ret += "    Settings.%s = %s\n" % (attr, value)
		return ret

	def toBool(self, str):
		return str.upper() == 'ON'

	def ExpandIPRanges(self):
		def expand_ranges(lst):
			ret = []
			for l in lst:
				tab = l.split('.')
				x = {}
				i = 0
				for byte in tab:
					if '-' not in byte:
						x[i] = x[i+1] = int(byte)
					else:
						b = byte.split('-')
						x[i] = int(b[0])
						x[i+1] = int(b[1])
					i += 2
				for a in range(x[0], x[1]+1):
					for b in range(x[2], x[3]+1):
						for c in range(x[4], x[5]+1):
							for d in range(x[6], x[7]+1):
								ret.append('%d.%d.%d.%d' % (a, b, c, d))
			return ret

		self.RespondTo = expand_ranges(self.RespondTo)
		self.DontRespondTo = expand_ranges(self.DontRespondTo)

	def populate(self, options):

		if options.Interface is None and utils.IsOsX() is False:
			print utils.color("Error: -I <if> mandatory option is missing", 1)
			sys.exit(-1)

		# Config parsing
		config = ConfigParser.ConfigParser()
		config.read(os.path.join(self.ResponderPATH, 'Responder.conf'))

		# Servers
		self.HTTP_On_Off     = self.toBool(config.get('Responder Core', 'HTTP'))
		self.SSL_On_Off      = self.toBool(config.get('Responder Core', 'HTTPS'))
		self.SMB_On_Off      = self.toBool(config.get('Responder Core', 'SMB'))
		self.SQL_On_Off      = self.toBool(config.get('Responder Core', 'SQL'))
		self.FTP_On_Off      = self.toBool(config.get('Responder Core', 'FTP'))
		self.POP_On_Off      = self.toBool(config.get('Responder Core', 'POP'))
		self.IMAP_On_Off     = self.toBool(config.get('Responder Core', 'IMAP'))
		self.SMTP_On_Off     = self.toBool(config.get('Responder Core', 'SMTP'))
		self.LDAP_On_Off     = self.toBool(config.get('Responder Core', 'LDAP'))
		self.DNS_On_Off      = self.toBool(config.get('Responder Core', 'DNS'))
		self.Krb_On_Off      = self.toBool(config.get('Responder Core', 'Kerberos'))

		# Db File
		self.DatabaseFile    = os.path.join(self.ResponderPATH, config.get('Responder Core', 'Database'))

		# Log Files
		self.LogDir = os.path.join(self.ResponderPATH, 'logs')

		if not os.path.exists(self.LogDir):
			os.mkdir(self.LogDir)

		self.SessionLogFile      = os.path.join(self.LogDir, config.get('Responder Core', 'SessionLog'))
		self.PoisonersLogFile    = os.path.join(self.LogDir, config.get('Responder Core', 'PoisonersLog'))
		self.AnalyzeLogFile      = os.path.join(self.LogDir, config.get('Responder Core', 'AnalyzeLog'))

		self.FTPLog          = os.path.join(self.LogDir, 'FTP-Clear-Text-Password-%s.txt')
		self.IMAPLog         = os.path.join(self.LogDir, 'IMAP-Clear-Text-Password-%s.txt')
		self.POP3Log         = os.path.join(self.LogDir, 'POP3-Clear-Text-Password-%s.txt')
		self.HTTPBasicLog    = os.path.join(self.LogDir, 'HTTP-Clear-Text-Password-%s.txt')
		self.LDAPClearLog    = os.path.join(self.LogDir, 'LDAP-Clear-Text-Password-%s.txt')
		self.SMBClearLog     = os.path.join(self.LogDir, 'SMB-Clear-Text-Password-%s.txt')
		self.SMTPClearLog    = os.path.join(self.LogDir, 'SMTP-Clear-Text-Password-%s.txt')
		self.MSSQLClearLog   = os.path.join(self.LogDir, 'MSSQL-Clear-Text-Password-%s.txt')

		self.LDAPNTLMv1Log   = os.path.join(self.LogDir, 'LDAP-NTLMv1-Client-%s.txt')
		self.HTTPNTLMv1Log   = os.path.join(self.LogDir, 'HTTP-NTLMv1-Client-%s.txt')
		self.HTTPNTLMv2Log   = os.path.join(self.LogDir, 'HTTP-NTLMv2-Client-%s.txt')
		self.KerberosLog     = os.path.join(self.LogDir, 'MSKerberos-Client-%s.txt')
		self.MSSQLNTLMv1Log  = os.path.join(self.LogDir, 'MSSQL-NTLMv1-Client-%s.txt')
		self.MSSQLNTLMv2Log  = os.path.join(self.LogDir, 'MSSQL-NTLMv2-Client-%s.txt')
		self.SMBNTLMv1Log    = os.path.join(self.LogDir, 'SMB-NTLMv1-Client-%s.txt')
		self.SMBNTLMv2Log    = os.path.join(self.LogDir, 'SMB-NTLMv2-Client-%s.txt')
		self.SMBNTLMSSPv1Log = os.path.join(self.LogDir, 'SMB-NTLMSSPv1-Client-%s.txt')
		self.SMBNTLMSSPv2Log = os.path.join(self.LogDir, 'SMB-NTLMSSPv2-Client-%s.txt')

		# HTTP Options
		self.Serve_Exe	      = self.toBool(config.get('HTTP Server', 'Serve-Exe'))
		self.Serve_Always     = self.toBool(config.get('HTTP Server', 'Serve-Always'))
		self.Serve_Html       = self.toBool(config.get('HTTP Server', 'Serve-Html'))
		self.Html_Filename    = config.get('HTTP Server', 'HtmlFilename')
		self.Exe_Filename     = config.get('HTTP Server', 'ExeFilename')
		self.Exe_DlName       = config.get('HTTP Server', 'ExeDownloadName')
		self.WPAD_Script      = config.get('HTTP Server', 'WPADScript')
		self.HtmlToInject     = config.get('HTTP Server', 'HtmlToInject')

		# Throttle Options
		self.ThrottleAuditor = {}
		self.ThrottleThreshold = config.get('Throttle', 'Threshold')
		self.ThrottleTimeThreshold = float(config.get('Throttle', 'TimeBan'))
		self.ThrottleVerbose = self.toBool(config.get('Throttle', 'Verbose'))
		self.ThrottleIPTables = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
		self.ThrottleLock = threading.Lock()
		self.ThrottleAuditTimeFrame = float(config.get('Throttle', 'AuditTimeFrame'))

		# MAC Filtering
		self.ArpTable = {}
		self.VendorTable = {}
		self.ArtTableFilteringVerbose = self.toBool(config.get('MACFiltering', 'Verbose'))
		self.ArpTableRefreshRate = config.get('MACFiltering', 'RefreshRate')
		self.DontRespondToVendor = filter(None, [x.lower().strip() for x in config.get('MACFiltering', 'DontRespondTo').strip().split(',')])


		if not os.path.exists(self.Html_Filename):
			print utils.color("/!\ Warning: %s: file not found" % self.Html_Filename, 3, 1)

		if not os.path.exists(self.Exe_Filename):
			print utils.color("/!\ Warning: %s: file not found" % self.Exe_Filename, 3, 1)

		# SSL Options
		self.SSLKey  = config.get('HTTPS Server', 'SSLKey')
		self.SSLCert = config.get('HTTPS Server', 'SSLCert')

		# Auto Ignore List
		self.AutoIgnore                 = self.toBool(config.get('Responder Core', 'AutoIgnoreAfterSuccess'))
		self.CaptureMultipleCredentials = self.toBool(config.get('Responder Core', 'CaptureMultipleCredentials'))
		self.AutoIgnoreList             = []

		# CLI options
		self.LM_On_Off       = options.LM_On_Off
		self.WPAD_On_Off     = options.WPAD_On_Off
		self.Wredirect       = options.Wredirect
		self.NBTNSDomain     = options.NBTNSDomain
		self.Basic           = options.Basic
		self.Finger_On_Off   = options.Finger
		self.Interface       = options.Interface
		self.OURIP           = options.OURIP
		self.Force_WPAD_Auth = options.Force_WPAD_Auth
		self.Upstream_Proxy  = options.Upstream_Proxy
		self.AnalyzeMode     = options.Analyze
		self.Verbose         = options.Verbose
		self.CommandLine     = str(sys.argv)

		if self.HtmlToInject is None:
			self.HtmlToInject = ''

		self.Bind_To = utils.FindLocalIP(self.Interface, self.OURIP)

		self.IP_aton         = socket.inet_aton(self.Bind_To)
		self.Os_version      = sys.platform

		# Set up Challenge
		self.NumChal = config.get('Responder Core', 'Challenge')

		if len(self.NumChal) is not 16:
			print utils.color("[!] The challenge must be exactly 16 chars long.\nExample: 1122334455667788", 1)
			sys.exit(-1)

		self.Challenge = ""
		for i in range(0, len(self.NumChal),2):
			self.Challenge += self.NumChal[i:i+2].decode("hex")

		# Set up logging
		logging.basicConfig(filename=self.SessionLogFile, level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
		logging.warning('Responder Started: %s' % self.CommandLine)
		logging.warning('Responder Config: %s' % str(self))

		Formatter = logging.Formatter('%(asctime)s - %(message)s')
		PLog_Handler = logging.FileHandler(self.PoisonersLogFile, 'w')
		ALog_Handler = logging.FileHandler(self.AnalyzeLogFile, 'a')
		PLog_Handler.setLevel(logging.INFO)
		ALog_Handler.setLevel(logging.INFO)
		PLog_Handler.setFormatter(Formatter)
		ALog_Handler.setFormatter(Formatter)

		self.PoisonersLogger = logging.getLogger('Poisoners Log')
		self.PoisonersLogger.addHandler(PLog_Handler)

		self.AnalyzeLogger = logging.getLogger('Analyze Log')
		self.AnalyzeLogger.addHandler(ALog_Handler)

		# Set up response settings
		self.filesToCallbacks = {}
		if options.Respond_To_File:
			logging.info("RespondTo will be filled from file '%s.' Responder.conf setting will be ignored." % options.Respond_To_File)
			print ("%s RespondTo will be filled from file '%s.' Responder.conf setting will be ignored." % (utils.color('[+]', 2, 1), options.Respond_To_File))
			self.filesToCallbacks[options.Respond_To_File] = self.update_respond_to
		else:
			self.RespondTo = filter(None, [x.upper().strip() for x in config.get('Responder Core', 'RespondTo').strip().split(',')])
		if options.Respond_To_Name_File:
			logging.info("RespondToName will be filled from file '%s.' Responder.conf setting will be ignored." % options.Respond_To_File)
			print ("%s RespondToName will be filled from file '%s.' Responder.conf setting will be ignored." % (utils.color('[+]', 2, 1), options.Respond_To_File))
			self.filesToCallbacks[options.Respond_To_Name_File] = self.update_respond_to_name
		else:
			self.RespondToName = filter(None, [x.upper().strip() for x in config.get('Responder Core', 'RespondToName').strip().split(',')])
		if options.Dont_Respond_To_File:
			logging.info("DontRespondTo will be filled from file '%s.' Responder.conf setting will be ignored." % options.Respond_To_File)
			print ("%s DontRespondTo will be filled from file '%s.' Responder.conf setting will be ignored." % (utils.color('[+]', 2, 1), options.Respond_To_File))
			self.filesToCallbacks[options.Dont_Respond_To_File] = self.update_dont_respond_to
		else:
			self.DontRespondTo = filter(None, [x.upper().strip() for x in config.get('Responder Core', 'DontRespondTo').strip().split(',')])
		if options.Dont_Respond_To_Name_File:
			logging.info("DontRespondToName will be filled from file '%s.' Responder.conf setting will be ignored." % options.Respond_To_File)
			print ("%s DontRespondToName will be filled from file '%s.' Responder.conf setting will be ignored." % (utils.color('[+]', 2, 1), options.Respond_To_File))
			self.filesToCallbacks[options.Dont_Respond_To_Name_File] = self.update_dont_respond_to_name
		else:
			self.DontRespondToName = filter(None, [x.upper().strip() for x in config.get('Responder Core', 'DontRespondToName').strip().split(',')])

		if self.filesToCallbacks:
			file_poller = FilePoller(self.filesToCallbacks)
			file_poller.start()
			logging.info("File pollers started for files: %s" % self.filesToCallbacks.keys())
			print ("%s File pollers started for files: %s" % (utils.color('[+]', 2, 1), self.filesToCallbacks.keys()))


	@staticmethod
	def read_file_lines(filename):
		if filename and os.path.exists(filename):
			with open(filename, 'r') as f:
				return f.read().splitlines()
		else:
			logging.error("File %s doesn't exist")
			return []

	def update_respond_to(self, filename):
		self.RespondTo = set(Settings.read_file_lines(filename)) or []
		self.ExpandIPRanges()
		logging.info("RespondTo updated: %s" % self.RespondTo)
		print ("%s RespondTo updated: %s" % (utils.color('[+]', 2, 1), self.RespondTo))

	def update_respond_to_name(self, filename):
		self.RespondToName = set(Settings.read_file_lines(filename)) or []
		logging.info("RespondToName updated: %s" % self.RespondToName)
		print ("%s RespondToName updated: %s" % (utils.color('[+]', 2, 1), self.RespondToName))

	def update_dont_respond_to(self, filename):
		self.DontRespondTo = set(Settings.read_file_lines(filename)) or []
		self.ExpandIPRanges()
		logging.info("DontRespondTo updated: %s" % self.DontRespondTo)
		print ("%s DontRespondTo updated: %s" % (utils.color('[+]', 2, 1), self.DontRespondTo))

	def update_dont_respond_to_name(self, filename):
		self.DontRespondToName = set(Settings.read_file_lines(filename)) or []
		logging.info("DontRespondToName updated: %s" % self.DontRespondToName)
		print ("%s DontRespondToName updated: %s" % (utils.color('[+]', 2, 1), self.DontRespondToName))



def init():
	global Config
	Config = Settings()
