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

#include "packetdecoder.h"
#include "packetcontext.h"

#define TRUE 1
#define FALSE 0

static ST_PacketDecoder _pktdec;

static unsigned int ether_size = sizeof(struct ethhdr);

void PKDE_Init() {
    _pktdec._totalEthernetPackets = 0;
    _pktdec._totalEthernetVlanPackets = 0;
    _pktdec._totalIpPackets = 0;
    _pktdec._totalIpv6Packets = 0;
    _pktdec._totalTcpPackets = 0;
    _pktdec._totalUdpPackets = 0;
    _pktdec._totalUnknownPackets = 0;
    _pktdec._totalL7Packets = 0;
    return;
}

void PKDE_Destroy(){
    return;
}

void PKDE_PrintfStats() {
    fprintf(stdout,"Packet decoder statistics\n");
    fprintf(stdout,"\ttotal Ethernet packets %ld\n",_pktdec._totalEthernetPackets);
    fprintf(stdout,"\ttotal Vlan packets %ld\n",_pktdec._totalEthernetVlanPackets);
    fprintf(stdout,"\ttotal IP packets %ld\n",_pktdec._totalIpPackets);
    fprintf(stdout,"\ttotal IPv6 packets %ld\n",_pktdec._totalIpv6Packets);
    fprintf(stdout,"\ttotal TCP packets %ld\n",_pktdec._totalTcpPackets);
    fprintf(stdout,"\ttotal UDP packets %ld\n",_pktdec._totalUdpPackets);
    fprintf(stdout,"\ttotal L7 packets %ld\n",_pktdec._totalL7Packets);
    fprintf(stdout,"\ttotal Unknown packets %ld\n",_pktdec._totalUnknownPackets);
    return;
}


int PKDE_Decode(struct pcap_pkthdr *hdr, unsigned char *packet) {
    unsigned int offset = ether_size;
    unsigned int l7size = 0;
    int have_l7 = FALSE;
    unsigned short next_proto = ETH_P_IP;

    _pktdec._totalEthernetPackets++;
    do {
        switch(next_proto){
            case IPPROTO_IP:
            case ETH_P_IP:
                _pktdec._totalIpPackets++;
                PKCX_SetIPHeader((packet+offset));
                offset += PKCX_GetIPHeaderLength();
                next_proto = PKCX_GetIPProtocol();
                if(PKCX_IsIPver4() == FALSE)
                        next_proto = IPPROTO_IPV6;
                break;
            case ETH_P_8021Q:
                _pktdec._totalEthernetVlanPackets++;
                offset += 4;
                next_proto = ETH_P_IP;
                break;
            case IPPROTO_TCP:
                _pktdec._totalTcpPackets++;
                have_l7 = TRUE;
                PKCX_SetTCPHeader((packet+offset));
                offset += PKCX_GetTCPHeaderLength();
                l7size = PKCX_GetTCPPayloadLength();
                next_proto = 0;
                break;
            case IPPROTO_UDP:
                _pktdec._totalUdpPackets++;
                have_l7 = TRUE;
                PKCX_SetUDPHeader((packet+offset));
                offset += PKCX_GetUDPHeaderLength();
                l7size = PKCX_GetUDPPayloadLength();
                next_proto = 0;
                break;
            case IPPROTO_ICMP:
            case IPPROTO_IPV6:
#ifdef HAVE_IPV6
                PKCX_SetIPv6Header((packet+offset));
                offset += PKCX_GetIPv6HeaderLength();
                next_proto = PKCX_GetIPv6Protocol();
#endif
                _pktdec._totalIpv6Packets++;

                return FALSE;
            default:
                _pktdec._totalUnknownPackets++;
                return FALSE;
        }
    }while(have_l7==FALSE);
    PKCX_SetL7Payload((packet+offset),l7size);
    _pktdec._totalL7Packets++;
/*  DEBUG0("Decoding IPPacket: [%s:%d:%d:%s:%d] length %d l7flag %d\n",
    PKCX_GetSrcAddrDotNotation(),
    PKCX_GetSrcPort(),
    PKCX_GetIPProtocol(),
    PKCX_GetDstAddrDotNotation(),
    PKCX_GetDstPort(),l7size,have_l7);
*/
    return TRUE;
}

