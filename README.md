InCC (Invisible Covert Channel)
=======

InCC is a light-weight covert channel, which is designed to produce
a undetectable communication channel between systems. This channel, fully transparent to any network anal-
ysis, is able to send messages on the same production network without compromising its existence. By using
techniques like encryption, address spoofing, signatures and traffic analysis, the channel is able to hide the
flows on the network without compromising the source and destination.

This hybrid daemon is capable of hiding information by learning from the 
network and, in a second stage, of sending similar traffic in order to 
hide the messages as a cover channel does.


Using InCC
--------

The main script file is daemon.py, you can rewrite in order to connect with i
other subsystem as well as many others. 

First open the daemon.py and add the following lines in order to use 
bit-torrent has cover channel.

        incc.INCC_SetSource(options.interface)

        # distributed table bit-torrent signature.
        incc.INCC_AddSignature(1,"bittorrent","d1:ad2:id20:","d1:ad2:id20:",None)

        incc.INCC_Start();

        try:
                incc.INCC_Run();
        except:
                incc.INCC_Stop();

and execute the daemon with the -t flag, so the identification of the packet will be easy(just for debuging purposes).

	luis@dell:~/c/incc/src/core$ sudo python daemon.py -i eth1 -t 1
	[stdout] INFO     incc.engine - Allocating 262144 flows on pool, current flows on pool 0
	[stdout] INFO     incc.engine - adding signature 'torrent' to the engine
	[stdout] INFO     incc.engine - Add signature id(1) to the detection 
	[stdout] INFO     incc.engine - Trying to start the engine, status=stop
	[stdout] INFO     incc.engine - Starting engine
	InCC Engine running on Linux machine i686
        	version #22-Ubuntu SMP Wed Nov 2 15:17:35 UTC 2011

on other terminal execute the script message.py

	luis@dell:~/c/incc/extra$ sudo python message.py 
	Enter message:
	hello world
	Sending to InCC

So if the daemon dont detect any traffic the output will be as following

	[stdout] INFO     incc.bus - Executing method 'SendMessage' from interface 'incc.engine'
	[stdout] INFO     incc.engine - No traffic avaiable to detect

in any other case.....

	[stdout] INFO     incc.engine - Detecting 'torrent' on flow [192.168.1.1:51413:17:79.116.204.198:61252] flow(0xa6ae3b0)
	[stdout] INFO     incc.engine - Detecting 'torrent' on flow [192.168.1.1:51413:17:95.32.45.218:21618] flow(0xa6ae000)
	[stdout] INFO     incc.engine - Detecting 'torrent' on flow [192.168.1.1:51413:17:84.76.54.24:51413] flow(0xa6ae120)
	[stdout] INFO     incc.engine - Detecting 'torrent' on flow [192.168.1.1:51413:17:88.135.2.4:35691] flow(0xa6adaf0)
	[stdout] INFO     incc.engine - Detecting 'torrent' on flow [192.168.1.1:51413:17:91.83.174.189:38669] flow(0xa6adac0)
	[stdout] INFO     incc.engine - Detecting 'torrent' on flow [192.168.1.1:51413:17:99.42.213.114:18363] flow(0xa6ada90)
	[stdout] INFO     incc.engine - Detecting 'torrent' on flow [192.168.1.1:51413:17:46.105.127.159:6881] flow(0xa6ad940)
	[stdout] INFO     incc.bus - Executing method 'SendMessage' from interface 'incc.engine'
	[stdout] INFO     incc.engine - Sending Message over 'torrent' using [192.168.1.1:51413:17:46.105.127.159:6881] 55 bytes
	[stdout] INFO     incc.engine - Detecting 'torrent' on flow [192.168.1.1:51414:17:46.105.127.159:6881] flow(0xa6ad2d0)
	[stdout] INFO     incc.engine - Message received and decrypted flow(0xa6ad2d0)msg(hello world)

Contributing to InCC
-------------------------

InCC is under the terms of GPLv2 and is under develop.

Check out the InCC source with 

    $ git clone git://github.com/camp0/incc.git
    $ cd incc 
    $ ./autogen.sh 
    $ ./configure
    $ make && make install

 
