__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import time
import random
import ctypes
import sys
sys.path.append("../src/core/")
import incc_test as p
import atexit
import signal

def signal_usr1(signum, frame):
    """ Callback invoked when a signal is received """
    sys.stdout.flush()
    p.INCC_Stats()
    sys.exit(0)

if __name__ == '__main__':

    """ This is for testing purposes 
        
        sys.argv[1] equals source ip
        sys.argv[2] equals destination ip
        sys.argv[3] pcapfile
        sys.argv[4] network device optional

    """
    print ("Running dummy instance on:",sys.argv[1])

    srcip = sys.argv[1]
    srcmask = sys.argv[2]
    dstip = sys.argv[3]
    dstmask = sys.argv[4]
    pcapfile = sys.argv[5]
    have_network_device = False
    network_device = None
    if (len(sys.argv) > 6):
        have_network_device = True
        network_device = sys.argv[6]

    p.INCC_Init()
    p.INCC_SetPacketTTL(16)
    p.INCC_SetEncryptionKey("this is a key")
    p.INCC_SetSource(pcapfile)
    p.INCC_SetExitOnPcap(have_network_device)

    signal.signal(signal.SIGUSR1, signal_usr1)

    p.INCC_SetSourceIP(srcip)
    p.INCC_SetSourceMask(srcmask)
    p.INCC_SetDestinationIP(dstip)
    p.INCC_SetDestinationMask(dstmask)
    p.INCC_AddSignature(1, "Gnutella", "^GND.*$","GND",3, None,0)
    p.INCC_Start()
    try:
        p.INCC_Run()
    except (KeyboardInterrupt, SystemExit):
        p.INCC_Stop()
        sys.exit(0)

    if (have_network_device):
        p.INCC_SetSource(network_device)
        try:
            p.INCC_Start()
            p.INCC_Run()
        except (KeyboardInterrupt, SystemExit):
            p.INCC_Stop()
      
    print("out out") 
    sys.exit(0)
