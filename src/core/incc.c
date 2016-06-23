/* 
 * InCC - Invisible Covert Channel engine.
 *                                                              
 * Copyright (C) 2013  Luis Campo Giralte 
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013 
 *
 */
#include "incc.h"
#include "inccdbus.h"
#include "callbacks.h"
#include "genericflow.h"
#include "connection.h"

#define INCCLOG_CATEGORY_NAME INCC_INTERFACE
#include "log.h"

#define DEBUG 1

static ST_InCCEngine *_inccEngine = NULL;

static int timeout_checker = 180;

/**
 * INCC_Init - Initialize the main structures of the incc
 */
void INCC_Init() {
	register int i,j;
	ST_Callback *current = NULL;
	ST_Interface *interface = NULL;
	GString *interface_name = NULL;

	_inccEngine = (ST_InCCEngine*)g_new0(ST_InCCEngine,1);

	POLG_Init();
	ICDS_Init();
	_inccEngine->incc_status = INCC_STATE_STOP;
	_inccEngine->is_pcap_file = FALSE;
	_inccEngine->when_pcap_done_exit = FALSE;
	_inccEngine->pcapfd = 0;
	_inccEngine->pcap = NULL;
	_inccEngine->ttl = 64;
	_inccEngine->src_port = 0;
	_inccEngine->src_address = -1;
	_inccEngine->src_mask_address = 0xFFFFFFFF;
	_inccEngine->dst_port = 0;
	_inccEngine->dst_address = -1;
	_inccEngine->dst_mask_address = 0xFFFFFFFF; 
        _inccEngine->send_messages = 0;
        _inccEngine->try_send_messages = 0;
        _inccEngine->receive_messages = 0;
        _inccEngine->decrypt_messages = 0;
	_inccEngine->sockrawfd = -1; 
	_inccEngine->show_generated_payloads = FALSE;
	_inccEngine->source = g_string_new("");
	_inccEngine->interface_bus_name = NULL; 
	interface_name = g_string_new("");

	for (register int i = 0; i < 5 ; i++) {
		g_string_printf(interface_name,"%s%i",INCC_INTERFACE,i);

		_inccEngine->bus = ICDS_Connect(interface_name->str,(void*)_inccEngine);
		if (_inccEngine->bus != NULL) {
			_inccEngine->interface_bus_name = interface_name;
			break;
		}
	}

	/* Only load the callbacks if dbus is running */ 
	if(_inccEngine->bus != NULL) {
		i = 0;
		interface = &ST_PublicInterfaces[0];
		while(interface->name != NULL) {
			/* Loads the methods first */
			current = (ST_Callback*)&(interface->methods[0]);
			j = 0;
			while((current != NULL)&&(current->name != NULL)) {
				ICDS_AddPublicMethod(interface,current);
				j++;
				current = (ST_Callback*)&(interface->methods[j]);
			}
			j = 0;
			current = (ST_Callback*)&(interface->signals[0]);
			while((current != NULL)&&(current->name != NULL)) {
				ICDS_AddPublicMethod(interface,current);
				j++;
				current = (ST_Callback*)&(interface->signals[j]);
			} 
			j = 0;
			current = (ST_Callback*)&(interface->properties[0]);
			while((current!=NULL)&&(current->name != NULL)){
				ICDS_AddPublicProperty(interface,current);
				j++;
				current = (ST_Callback*)&(interface->properties[j]);
			}
			i++;
			interface = &ST_PublicInterfaces[i];
		}		
	}
	
	PKCX_Init();
	SYIN_Init();

	_inccEngine->protocol = PROT_Init();
	_inccEngine->conn = COMN_Init();
	_inccEngine->flowpool = FLPO_Init();
	_inccEngine->detect = DTTN_Init(); 
	COMN_SetFlowPool(_inccEngine->conn,_inccEngine->flowpool);

#ifdef HAVE_LIBLOG4C
	LOG(INCCLOG_PRIORITY_DEBUG,"Initialized engine....");
	if (_inccEngine->interface_bus_name == NULL) {
		LOG(INCCLOG_PRIORITY_DEBUG,"Not connected to DBus");
	} else {
		LOG(INCCLOG_PRIORITY_DEBUG,"Connected as %s on DBus", _inccEngine->interface_bus_name->str);
	}
	LOG(INCCLOG_PRIORITY_DEBUG,"connection manager (0x%x)",_inccEngine->conn);
	LOG(INCCLOG_PRIORITY_DEBUG,"flowpool (0x%x)",_inccEngine->flowpool);
#else
#ifdef DEBUG
	fprintf(stdout,"Initialized engine....\n");
	fprintf(stdout,"connection manager (0x%x)\n",_inccEngine->conn);
	fprintf(stdout,"flowpool (0x%x)\n",_inccEngine->flowpool);
#endif
#endif
	return;
}

/**
 * INCC_SetSource - Sets the source of the network packets
 *
 * @param source a pcap file or a ethernet device
 */
void INCC_SetSource(char *source){
	g_string_printf(_inccEngine->source,"%s",source);
}


/**
 * INCC_ShowGeneratedPayload - Show the generated packets, usefull for debuging. 
 *
 * @param value true or false 
 */
void INCC_ShowGeneratedPayload(int value){

	_inccEngine->show_generated_payloads = value;
	return;
}

/**
 * INCC_Start - Starts the engine 
 */

void INCC_Start() {

	LOG(INCCLOG_PRIORITY_INFO,
		"Trying to start the engine, status=%s",incc_states_str[_inccEngine->incc_status]);	
	if(_inccEngine->incc_status == INCC_STATE_STOP) {
		char errbuf[PCAP_ERRBUF_SIZE];

		_inccEngine->is_pcap_file = FALSE;
		_inccEngine->pcap = pcap_open_live(_inccEngine->source->str, PCAP_ERRBUF_SIZE, 1, -1, errbuf);
		if(_inccEngine->pcap == NULL) {
			_inccEngine->pcap = pcap_open_offline(_inccEngine->source->str,errbuf);
			if(_inccEngine->pcap == NULL) {
				fprintf(stderr, "Could not open device/file \"%s\": %s\n", _inccEngine->source->str, errbuf);
				return;
			}
			_inccEngine->is_pcap_file = TRUE;
		}

		if(pcap_setnonblock(_inccEngine->pcap, 1, errbuf) == 1){
			fprintf(stderr, "Could not set device \"%s\" to non-blocking: %s\n", _inccEngine->source->str,errbuf);
			pcap_close(_inccEngine->pcap);
                	_inccEngine->pcap = NULL;
                	return;
        	}

		/* if is a pcap file we will inject the packet on lo just for testing purposes */
		if (_inccEngine->is_pcap_file == TRUE) {
			_inccEngine->sockrawfd = PCKT_InitToDevice("lo");
		} else {
			_inccEngine->sockrawfd = PCKT_InitToDevice(_inccEngine->source->str);
		}
		_inccEngine->pcapfd = pcap_get_selectable_fd(_inccEngine->pcap);
		_inccEngine->incc_status = INCC_STATE_RUNNING;
                LOG(INCCLOG_PRIORITY_INFO,"Starting engine",NULL);
	}
}

/**
 * INCC_Stop - Stops the engine
 */
void INCC_Stop() {
	
	LOG(INCCLOG_PRIORITY_INFO,
		"Trying to stop the engine, status=%s",incc_states_str[_inccEngine->incc_status]);	
	if(_inccEngine->incc_status == INCC_STATE_RUNNING) {
		// printf("pcap = 0x%x\n",_inccEngine->pcap);
		//if(_inccEngine->pcap != NULL);
		pcap_close(_inccEngine->pcap);
		close(_inccEngine->sockrawfd);
		_inccEngine->pcap = NULL;
		_inccEngine->pcapfd = -1;
		_inccEngine->incc_status = INCC_STATE_STOP;
                LOG(INCCLOG_PRIORITY_INFO,"Stoping engine",NULL);
	}
}

/**
 * INCC_StopAndExit - Stops and exit the incc
 */
void INCC_StopAndExit() {
	INCC_Stop();
	INCC_Destroy();
	exit(0);
}

/**
 * INCC_Destroy - Destroy the ST_InCCEngine type
 */
void INCC_Destroy() {
	ICDS_Destroy();
	// TODO: the flows stored on the connection manager
	// should be returned to the pools.
	// COMN_ReleaseFlows(_inccEngine->conn);
	COMN_ReleaseFlows(_inccEngine->conn);

	close(_inccEngine->sockrawfd);
	g_string_free(_inccEngine->source,TRUE);
	g_string_free(_inccEngine->interface_bus_name,TRUE);
	FLPO_Destroy(_inccEngine->flowpool);
	COMN_Destroy(_inccEngine->conn);
	DTTN_Destroy(_inccEngine->detect);
	PROT_Destroy(_inccEngine->protocol);
	PKCX_Destroy();
	POLG_Destroy();
	g_free(_inccEngine);
	_inccEngine = NULL;
	return;
}

/**
 * INCC_Stats - Show statistics related to the ST_InCCEngine 
 */

void INCC_Stats() {
        PKDE_PrintfStats();
        FLPO_Stats(_inccEngine->flowpool);
        COMN_Stats(_inccEngine->conn);
	DTTN_Stats(_inccEngine->detect);
	fprintf(stdout,"Messages\n");
	fprintf(stdout,"\tTry send: %d\n",_inccEngine->try_send_messages);
	fprintf(stdout,"\tSend: %d\n",_inccEngine->send_messages);
	fprintf(stdout,"\tDecrypted: %d\n",_inccEngine->decrypt_messages);
	fprintf(stdout,"\tReceived: %d\n",_inccEngine->receive_messages);
	return;
}

void INCC_SetExitOnPcap(int value){
	_inccEngine->when_pcap_done_exit = value;
}


/**
 * INCC_ProcessIncomingFlow - Process the input, forward messages to other process from the network
 *
 * @param sig The signature detected on the flow
 * @para 
 */

void INCC_ProcessIncomingFlow(ST_Signature *sig,ST_GenericFlow *f,unsigned char *payload,int len) {
	uint32_t ipsrc = PKCX_GetIPSrcAddr();
	uint32_t masksrc = _inccEngine->src_mask_address;
	uint32_t maskdst = _inccEngine->dst_mask_address;
	uint32_t ipdst = PKCX_GetIPDstAddr();

	uint32_t net_lower_src = (ipsrc & masksrc);
    	uint32_t net_upper_src = (net_lower_src | (~masksrc));
	uint32_t net_lower_dst = (ipdst & maskdst);
    	uint32_t net_upper_dst = (net_lower_dst | (~maskdst));

	if ((ipsrc >= net_lower_src && ipsrc <= net_upper_src)&&(ipdst >= net_lower_dst && ipdst<= net_upper_dst)) {
		// The flow in on the network configured
		uint16_t srcport = PKCX_GetUDPSrcPort();	
		uint16_t dstport = PKCX_GetUDPDstPort();	
		
		// the flow haves the same ports configured or the user
		// dont set the ports for other ports
		if(((srcport==_inccEngine->src_port)&&(dstport==_inccEngine->dst_port))||
			((_inccEngine->src_port == 0)&&(_inccEngine->dst_port == 0))){
			ST_Payload pkt;
			ST_Payload *pkt_recover;

			_inccEngine->decrypt_messages ++;
			pkt.payload = payload;
			pkt.len = len;

#ifdef HAVE_LIBLOG4C
			LOG(INCCLOG_PRIORITY_DEBUG,
				"Candidate packet from [%s:%d:%d:%s:%d] flow(0x%x) length(%d)",
				PKCX_GetSrcAddrDotNotation(),
				PKCX_GetSrcPort(),
				17,
				PKCX_GetDstAddrDotNotation(),
				PKCX_GetDstPort(),
                       		f,len);
#else
			fprintf(stdout,"Candidate packet from [%s:%d:%d:%s:%d] flow(0x%x) length(%d)\n",
                                PKCX_GetSrcAddrDotNotation(),
                                PKCX_GetSrcPort(),
                                17,
                                PKCX_GetDstAddrDotNotation(),
                                PKCX_GetDstPort(),
                                f,len);
#endif
	
			pkt_recover = PROT_RecoverPayload(_inccEngine->protocol,&pkt,sig);
			if(pkt_recover) {
				_inccEngine->receive_messages ++;
#ifdef HAVE_LIBLOG4C
				LOG(INCCLOG_PRIORITY_INFO,
					"Message recevied on flow [%s:%d:%d:%s:%d] flow(0x%x) Message(%s)",
					PKCX_GetSrcAddrDotNotation(),
					PKCX_GetSrcPort(),
					17,
					PKCX_GetDstAddrDotNotation(),
					PKCX_GetDstPort(),
					f,
					pkt_recover->payload);
#else
				fprintf(stdout,"Message recevied on flow [%s:%d:%d:%s:%d] flow(0x%x) Message(%s)\n",
					PKCX_GetSrcAddrDotNotation(),
					PKCX_GetSrcPort(),
					17,
					PKCX_GetDstAddrDotNotation(),
					PKCX_GetDstPort(),
					f,
					pkt_recover->payload);
#endif
			}			
		}
	} else {
		printf("Candidate packet from [%s:%d:%d:%s:%d] do not matchs with addresses\n",
				PKCX_GetSrcAddrDotNotation(),
				PKCX_GetSrcPort(),
				17,
				PKCX_GetDstAddrDotNotation(),
				PKCX_GetDstPort(),
                       		f,len);
	}
	return;
}


/**
 * INCC_Run - Main loop, for manage the packets and the dbus-messages. 
 *
 */
void INCC_Run() {
	ST_GenericFlow *flow;
	ST_Signature *signature;
	register int i;
	int nfds,usepcap,ret,update_timers;
        DBusWatch *local_watches[MAX_WATCHES];
	struct timeval currenttime;
	struct timeval lasttimeouttime;
	struct pcap_pkthdr *header;
	unsigned char *pkt_data;
	struct pollfd local_fds[MAX_WATCHES];
        struct in_addr a;
        char ip_src_str[INET_ADDRSTRLEN];
        char ip_src_mask_str[INET_ADDRSTRLEN];
        char ip_dst_str[INET_ADDRSTRLEN];
        char ip_dst_mask_str[INET_ADDRSTRLEN];

	// Verfiy the IP addresses of the engine
        a.s_addr = _inccEngine->src_address;
        if (inet_ntop(AF_INET, &a, ip_src_str, INET_ADDRSTRLEN) == NULL) {
		fprintf(stderr,"Invalid ipsrc parameter\n");
		exit(-1);
	}
        a.s_addr = _inccEngine->src_mask_address;
        if (inet_ntop(AF_INET, &a, ip_src_mask_str, INET_ADDRSTRLEN) == NULL) {
		fprintf(stderr,"Invalid ipsrc mask parameter\n");
		exit(-1);
	}
        a.s_addr = _inccEngine->dst_address;
        if (inet_ntop(AF_INET, &a, ip_dst_str, INET_ADDRSTRLEN) == NULL) {
		fprintf(stderr,"Invalid ipdst parameter\n");
		exit(-1);
	}
        a.s_addr = _inccEngine->dst_mask_address;
        if (inet_ntop(AF_INET, &a, ip_dst_mask_str, INET_ADDRSTRLEN) == NULL) {
		fprintf(stderr,"Invalid ipsdst mask parameter\n");
		exit(-1);
	}

        fprintf(stdout,"%s running on  %s machine %s\n",INCC_ENGINE_NAME,
		SYIN_GetOSName(),SYIN_GetMachineName());
        fprintf(stdout,"\tversion %s\n",SYIN_GetVersionName());
        fprintf(stdout,"\tipsrc %s netmask %s\n",ip_src_str,ip_src_mask_str);
        fprintf(stdout,"\tipdst %s netmask %s\n",ip_dst_str,ip_dst_mask_str);

        gettimeofday(&lasttimeouttime,NULL);
	update_timers = 1;
	while (TRUE) {
                nfds = 0;
                usepcap = 0;
                gettimeofday(&currenttime,NULL);

                for (i = 0; i < ICDS_GetTotalActiveDescriptors(); i++) {
                        if (ICDS_GetDescriptorByIndex(i) == 0 ||
                            !dbus_watch_get_enabled(ICDS_GetWatchByIndex(i))) {
                                continue;
                        }

                        local_fds[nfds].fd = ICDS_GetDescriptorByIndex(i); 
                        local_fds[nfds].events = ICDS_GetEventsByIndex(i);
                        local_fds[nfds].revents = 0;
                        local_watches[nfds] = ICDS_GetWatchByIndex(i);
                        nfds++;
                }

                if(_inccEngine->incc_status == INCC_STATE_RUNNING) {
                        local_fds[nfds].fd = _inccEngine->pcapfd;
                        local_fds[nfds].events = POLLIN|POLLPRI|POLLHUP;
                        local_fds[nfds].revents = 0;
                        usepcap = 1;
                }

                ret = poll(local_fds,nfds+usepcap,-1);
                if (ret <0){
                        //perror("poll");
                        break;
                }

                if((local_fds[nfds].revents & POLLIN)&&(_inccEngine->incc_status == INCC_STATE_RUNNING)){
                        ret = pcap_next_ex(_inccEngine->pcap,(struct pcap_pkthdr*)&header,(unsigned char*)&pkt_data);
			if(ret < 0) {
                                INCC_Stop();
                                usepcap = 0;
                                if(_inccEngine->is_pcap_file == TRUE){
					fprintf(stdout,"Source analyze done.\n");
					if(_inccEngine->when_pcap_done_exit == TRUE)
                                        	break;
                                }
			}else{
				if(PKDE_Decode(header,pkt_data) == TRUE){
					int segment_size;
					int protocol = PKCX_GetIPProtocol();
			
					if(protocol != IPPROTO_UDP)
						continue;
					uint32_t seq = PKCX_GetSequenceNumber();
					unsigned long hash;
						/* Find a ST_GenericFlow object in order to evaluate it */
					flow = COMN_FindConnection(_inccEngine->conn,
						PKCX_GetIPSrcAddr(),
						PKCX_GetSrcPort(),
						protocol,
						PKCX_GetIPDstAddr(),
						PKCX_GetDstPort(),
						&hash);	
							
					if (flow == NULL) {
						flow = FLPO_GetFlow(_inccEngine->flowpool);
						if (flow != NULL) {
							GEFW_SetFlowId(flow,
								PKCX_GetIPSrcAddr(),
								PKCX_GetSrcPort(),
								protocol,
								PKCX_GetIPDstAddr(),
								PKCX_GetDstPort());	
									
							COMN_InsertConnection(_inccEngine->conn,flow,&hash);
#ifdef DEBUG
							LOG(INCCLOG_PRIORITY_DEBUG,
								"New connection on Pool [%s:%d:%d:%s:%d] flow(0x%x)",
								PKCX_GetSrcAddrDotNotation(),
								PKCX_GetSrcPort(),
								protocol, 
								PKCX_GetDstAddrDotNotation(),
								PKCX_GetDstPort(),
								flow);
#endif 
							/* Check if the flow allready have a ST_MemorySegment attached */
							GEFW_SetArriveTime(flow,&currenttime);	
						}else{
							//WARNING("No flow pool allocated\n");
							continue;
						}
					}
					// check test/pcapfiles directory
					segment_size = PKCX_GetPayloadLength();
					flow->total_packets++;
					flow->total_bytes += segment_size;

					if(flow->detected == 0){ // The flow is not detected
						if(segment_size > 0 ){ // the packet have payload
							signature = DTTN_MatchsSignatures(_inccEngine->detect,
								flow,
								PKCX_GetPayload(),
								segment_size);
							if(signature) {
                                                        	LOG(INCCLOG_PRIORITY_INFO,
									"Detecting '%s' on flow [%s:%d:%d:%s:%d] flow(0x%x)",
									signature->name,
									PKCX_GetSrcAddrDotNotation(),
									PKCX_GetSrcPort(),
									protocol,
									PKCX_GetDstAddrDotNotation(),
									PKCX_GetDstPort(),
                                                                	flow);

								INCC_ProcessIncomingFlow(signature,flow,
									PKCX_GetPayload(),segment_size);	
							}
						}
					}
					GEFW_UpdateTime(flow,&currenttime);
				} // end of decode;
			}
                }
		/* updates the flow time every 180 seconds aproximately
		 * in order to avoid sorting without non-sense the flow list timer
		 * Notice that if not dbus messages available on the buss the 
		 * timers never execute.
		 */
		if(lasttimeouttime.tv_sec + timeout_checker < currenttime.tv_sec) {
			if(update_timers) {
				COMN_UpdateTimers(_inccEngine->conn,&currenttime);
				update_timers = 0;
				lasttimeouttime.tv_sec = currenttime.tv_sec;
				lasttimeouttime.tv_usec = currenttime.tv_usec;
			}
		}else 
			update_timers = 1;
               	for (i = 0; i < nfds; i++) {
                        if (local_fds[i].revents) {
                                ICDS_Handler(_inccEngine->bus,local_fds[i].revents, local_watches[i]);
                        }
                }
        }
        return;
}

/**
 * INCC_SetEncryptionKey - Sets the initial rc4 encryption key. 
 *
 * @param key the rc4 key
 *
 */
void INCC_SetEncryptionKey(char *key) {

        LOG(INCCLOG_PRIORITY_INFO,
                "setting encryption key '%s'",key);
	_inccEngine->protocol->rc4_encryption_key = key;
	return;
}

/**
 * INCC_AddSignature - Adds a signature to the sistem. 
 *
 * @param identifier a number that identify the signature.
 * @param name the name of the signature.
 * @param expresion a regular expresssion.
 * @param head the head of the regular expression.
 * @param tail the tail of the regular expresssion. 
 *
 */
void INCC_AddSignature(int identifier,char *name,char *expression,char *head,int hsize, char *tail,int tsize){
	ST_Signature *sig = SGNT_Init();

        LOG(INCCLOG_PRIORITY_INFO,
                "adding signature '%s' to the engine",name);

	SGNT_SetValues(sig,identifier,name,expression,head,hsize,tail,tsize);

	DTTN_AddSignature(_inccEngine->detect,sig);	

	return;
}

/**
 * INCC_SetSourcePort - Sets the source port for the generated packets. 
 *
 * @param srcport . 
 *
 */
void INCC_SetSourcePort(int srcport){
	_inccEngine->src_port = srcport;
	return;
}

/**
 * INCC_SetDestinationPort - Sets the destination port for the generated packets. 
 *
 * @param dstport . 
 *
 */
void INCC_SetDestinationPort(int dstport){
	_inccEngine->dst_port = dstport;
	return;
}


void INCC_SetSourceIP(char *ipsrc){

	_inccEngine->src_address = inet_addr(ipsrc);
	return;
}

void INCC_SetSourceMask(char *masksrc){

	_inccEngine->src_mask_address = inet_addr(masksrc);
	return;
}

void INCC_SetDestinationMask(char *maskdst){

	_inccEngine->dst_mask_address = inet_addr(maskdst); 
	return;
}

void INCC_SetDestinationIP(char *ipdst){

        _inccEngine->dst_address = inet_addr(ipdst);
	return;
}

/**
 * INCC_SendMessage - Receive a message from the dbus and send over the network. 
 *
 * @param message message to report to the network
 *
 */
void INCC_SendMessage(char *message){
	ST_Available *av = NULL;
	int ret;
	uint32_t ipsrc;
	uint32_t ipdst;
	uint16_t portsrc;
	uint16_t portdst;
	struct in_addr a,b;
        char ipsrc_str[INET_ADDRSTRLEN];
        char ipdst_str[INET_ADDRSTRLEN];

	_inccEngine->try_send_messages ++;

	av = DTTN_GetAvailable(_inccEngine->detect);
	if(av) {
		ST_Payload *payload;

		if(_inccEngine->src_address == -1) { // use the source IP of the flow
			ipsrc = av->sig->ipsrc;
		}else{
			if(_inccEngine->src_mask_address == 0){ // There is a source IP address that can be used
				ipsrc = _inccEngine->src_address;
			}else{
				// TODO: if the user configures a network 195.11.100.0/24
				// a good techique will be generate a random source ip from the
				// corresponding network.
				// this works also for the destination address. 
				ipsrc = av->sig->ipsrc; // use the ip source of the detected flow
			}
		}
		if(_inccEngine->dst_address == -1) { // use the destination IP of the flow
			ipdst = av->sig->ipdst;
		}else{
			if(_inccEngine->dst_mask_address == 0){ // There is a source IP address that can be used
				ipdst = _inccEngine->dst_address;
			}else{
				ipdst = av->sig->ipdst; // use the ip dest of the detected flow
			}
                }
		ipdst = av->sig->ipdst;
		portsrc = av->sig->portsrc;		
		portdst = av->sig->portdst;		
		a.s_addr = ntohl(ipsrc);
		b.s_addr = ntohl(ipdst);

        	inet_ntop(AF_INET, &a, ipsrc_str, INET_ADDRSTRLEN);
        	inet_ntop(AF_INET, &b, ipdst_str, INET_ADDRSTRLEN);

		payload = PROT_GeneratePayload(_inccEngine->protocol,av->sig,message,strlen(message));
		ret = PCKT_Send(_inccEngine->sockrawfd,
			ipsrc,
			ipdst,
			_inccEngine->ttl,
			// TODO: If the source of the traffic is on the same machine as incc
			// the ports can not be the same. In any other case could.
			portsrc +1,
			portdst,
			payload->payload,
			payload->len);
        	LOG(INCCLOG_PRIORITY_INFO,
                	"Reporting incident over '%s' using [%s:%d:17:%s:%d] %d bytes",av->sig->name,
			ipsrc_str,portsrc,ipdst_str,portdst,ret);
		if(_inccEngine->show_generated_payloads == TRUE){
			PYLD_Printf(payload);
		}
		_inccEngine->send_messages ++;
		PYLD_Destroy(payload);
	}else{
        	LOG(INCCLOG_PRIORITY_INFO,
                	"No traffic avaiable to detect");
	}
	return;
}


void INCC_SetPacketTTL(int ttl){
	_inccEngine->ttl = ttl;
	return;
}
