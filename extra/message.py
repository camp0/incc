__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
#
# Example for manage methods and properties over dbus.
#
import fileinput
import sys
import dbus
	
if __name__ == '__main__':
	
	bus = dbus.SessionBus()
	try:
		proxy = bus.get_object('incc.engine', '/incc/engine')
	except:	
		print "No InCC engine available on the bus"
		sys.exit(-1)

	iface = dbus.Interface(proxy,dbus_interface='incc.engine')

	while 1:
    		try:
			print "Enter message:"
        		line = sys.stdin.readline()
    		except KeyboardInterrupt:
        		break

    		if not line:
        		break

		print "Sending to InCC"
		iface.SendMessage(line.rstrip())

	sys.exit(0)	
