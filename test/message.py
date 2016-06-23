import dbus
import sys

if __name__ == '__main__':

    bus = dbus.SessionBus()
    try:
        proxy = bus.get_object('incc.engine0', '/incc/engine0')
    except:
        print "No InCC engine available on the bus"
        sys.exit(-1)

    iface = dbus.Interface(proxy,dbus_interface='incc.engine')
    iface.SendMessage("hi jajajaj")
    sys.exit(0)
