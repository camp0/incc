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

#ifndef _PACKETCONTEXT_H_
#define _PACKETCONTEXT_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#ifdef HAVE_IPV6
#include <netinet/ip6.h>
#endif

#define ETH_P_8021Q 0x8100
#define ETH_P_IP 0x0800

struct ST_PacketContext {
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;
	unsigned char *payload;
	int len;
	struct timeval *now;
};

typedef struct ST_PacketContext ST_PacketContext;

ST_PacketContext _pktctx;
	
static void PKCX_Init(void) { _pktctx.ip= NULL;_pktctx.tcp = NULL;_pktctx.udp = NULL;_pktctx.payload = NULL;_pktctx.len=0;};
static void PKCX_Destroy(void) { return;};
static void PKCX_SetTCPHeader(unsigned char *packet) { _pktctx.tcp = (struct tcphdr*)packet; };
static void PKCX_SetUDPHeader(unsigned char *packet) { _pktctx.udp = (struct udphdr*)packet; };
static void PKCX_SetL7Payload(unsigned char *packet,int length) {_pktctx.payload = packet;_pktctx.len = length;};

static void PKCX_SetIPHeader(unsigned char* packet) { _pktctx.ip = (struct iphdr*)packet;} ;

/* IP Fields */
static void PKCX_SetIPSrcAddr(u_int32_t saddr) { _pktctx.ip->saddr = saddr; };
static void PKCX_SetIPDstAddr(u_int32_t daddr) { _pktctx.ip->daddr = daddr; };
static u_int32_t PKCX_GetIPSrcAddr(void) { return ntohl(_pktctx.ip->saddr); };
static u_int32_t PKCX_GetIPDstAddr(void) { return ntohl(_pktctx.ip->daddr); };
static u_int8_t PKCX_GetTTL(void) { return _pktctx.ip->ttl; }
static u_int32_t PKCX_GetIPPacketLength(void) { return ntohs(_pktctx.ip->tot_len); }
static u_int16_t PKCX_GetIPHeaderLength(void) { return _pktctx.ip->ihl * 4; }
static int PKCX_IsIPver4(void) { return _pktctx.ip->version == 4; }
static int PKCX_GetIPProtocol(void) { return _pktctx.ip->protocol; }
/* TCP Fields */
static struct tcphdr *PKCX_GetTCPHeader(void) { return _pktctx.tcp;}
static unsigned int PKCX_GetTCPPayloadLength(void) { return ntohs(_pktctx.ip->tot_len) - _pktctx.ip->ihl * 4 - _pktctx.tcp->doff * 4; }
static int PKCX_GetPayloadLength(void) { return _pktctx.len; }
static unsigned int PKCX_GetTCPHeaderLength(void) { return _pktctx.tcp->doff * 4; }
static u_int16_t PKCX_GetTCPSrcPort(void) { return ntohs(_pktctx.tcp->source); }
static u_int16_t PKCX_GetTCPDstPort(void) { return ntohs(_pktctx.tcp->dest); }
static int PKCX_IsTCPSyn(void) { return _pktctx.tcp->syn;}
static int PKCX_IsTCPAck(void) { return _pktctx.tcp->ack;}
static int PKCX_IsTCPRst(void) { return _pktctx.tcp->rst;}
static int PKCX_IsTCPFin(void) { return _pktctx.tcp->fin;}
static int PKCX_IsTCPPush(void) { return _pktctx.tcp->psh;}
static unsigned char *PKCX_GetPayload(void) { return _pktctx.payload;}

static char* PKCX_GetSrcAddrDotNotation(void) { 
	struct in_addr a; 
        static char ip[INET_ADDRSTRLEN];
	a.s_addr=_pktctx.ip->saddr; 
        inet_ntop(AF_INET, &a, ip, INET_ADDRSTRLEN);
        return (char*)&ip;
}

static char* PKCX_GetDstAddrDotNotation(void) { 
	struct in_addr a;
        static char ip[INET_ADDRSTRLEN];
        a.s_addr=_pktctx.ip->daddr;
        inet_ntop(AF_INET, &a, ip, INET_ADDRSTRLEN);
        return (char*)&ip;
}
static u_int32_t PKCX_GetTCPSequenceNumber(void) { return ntohl(_pktctx.tcp->seq); }

/* UDP Fields */
static u_int16_t PKCX_GetUDPSrcPort(void) { return ntohs(_pktctx.udp->source);}
static u_int16_t PKCX_GetUDPDstPort(void) { return ntohs(_pktctx.udp->dest);}
static unsigned int PKCX_GetUDPPayloadLength(void) { return ntohs(_pktctx.udp->len) - sizeof(struct udphdr); }
static unsigned int PKCX_GetUDPHeaderLength(void) { return sizeof(struct udphdr); }

/* Generic fields */
static u_int16_t PKCX_GetDstPort(void) { 
	if(_pktctx.ip->protocol == IPPROTO_TCP)
		return ntohs(_pktctx.tcp->dest);
	else
		if(_pktctx.ip->protocol == IPPROTO_UDP)
			return ntohs(_pktctx.udp->dest);	
	return 0;
}

static u_int16_t PKCX_GetSrcPort(void) {
        if(_pktctx.ip->protocol == IPPROTO_TCP)
                return ntohs(_pktctx.tcp->source);
        else
                if(_pktctx.ip->protocol == IPPROTO_UDP)
                        return ntohs(_pktctx.udp->source);
        return 0;
}

static u_int32_t PKCX_GetSequenceNumber(void) { 
	if(_pktctx.ip->protocol == IPPROTO_TCP)
		return ntohl(_pktctx.tcp->seq); 
	return 0;
}

#endif
