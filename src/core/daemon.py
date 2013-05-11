#!/usr/bin/env python
#
#  InCC - Invisible Covert Channel engine.
#                                                              
# Copyright (C) 2013  Luis Campo Giralte 
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this library; if not, write to the
# Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
# Boston, MA  02110-1301, USA.
#
# Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013 
#
"""This script manage the main functions of the incc system """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import sys
import incc 
from optparse import OptionParser

def parseOptions():
	"""Parse the user options"""

	usage = "Usage: %prog [options]"
	
	p = OptionParser(usage)

	p.add_option("-i", "--interface", dest="interface", default=None,
		help="Sets the interface for listen")
	p.add_option("-S", "--statistics", dest="statistics", action='store_true', 
		default=False, help="Shows the statistics")
	p.add_option("-d", "--destination", dest="destination", default=None,
		help="Sets the destination IP network/address")
	p.add_option("-s", "--source", dest="source", default=None,
		help="Sets the source IP network/address")
	p.add_option("-t", "--ttl", dest="timetolive", default=None,
		help="Sets the TTL for the generated IP packets(debug)")
	p.add_option("-k", "--key", dest="rc4key", default=None,
		help="Sets the encryption key for the generated IP packets")
	p.add_option("-x", "--payload", dest="show_payload", action='store_true', 
		default=False, help="Shows the generated payloads")

	return p

if __name__ == '__main__':

	parser = parseOptions()
    	(options, args) = parser.parse_args()
	if(options.interface == None):
      		parser.error("Argument is required")
      		sys.exit(1)  

	incc.INCC_Init()

	if(options.destination != None):
		incc.INCC_SetDestinationIP(options.destination)

	if(options.source != None):
		incc.INCC_SetSourceIP(options.source)

	if(options.timetolive != None):
		incc.INCC_SetPacketTTL(int(options.timetolive))

	if(options.show_payload != None):
		incc.INCC_ShowGeneratedPayload(options.show_payload)

	# TODO(luis): the First key interchange could be done by using RSA and with
	# standar sockets and once the interchage have done close the open
	# socket and use random key rc4 for the main encryption.
	if(options.rc4key != None):
		incc.INCC_SetEncryptionKey(options.rc4key)

	incc.INCC_SetSource(options.interface)

	# INCC_SetExitOnPcap(exit_on_pcap);

	# netbios specification:
	# first two bytes from transaction id
	# and the rest the signature candidate
	# Example of packet chaining 
	incc.INCC_AddSignature(1, "netbios", 
		"^.{2}\\x01\\x10\\x00\\x01.*\\x00\\x20\\x00\\x01", "myhead",6, "mytail",6)
	incc.INCC_AddSignature(2, "mypacket", "^myhead.*mytail", "myhead",6, "mytail",6)

	# A simple distributed tables of bittorrent signature.
	incc.INCC_AddSignature(3, "torrent", "d1:ad2:id20:","d1:ad2:id20:",12, None,0)

	# A detection of bittorrent and generate battlefield traffic
	incc.INCC_AddSignature(3, "torrent", "d1:ad2:id20:","\x11\x20\x00\x01\x00\x00\x50\xb9\x10\x11",10, None,0)

	incc.INCC_Start()

	try:
		incc.INCC_Run()
	except (KeyboardInterrupt, SystemExit):
		incc.INCC_Stop()
	
	if(options.statistics):
		incc.INCC_Stats()	
	incc.INCC_StopAndExit()

	sys.exit(0)
