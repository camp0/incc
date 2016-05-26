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

#include "packet.h"

int PCKT_Init(){
    int sock;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    return sock;
}

int PCKT_InitToDevice(char *dev){
    int sock;

    sock = PCKT_Init();

    int one = 1;
    const int *val = &one;
    setsockopt (sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one));
    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev));

    return sock; 
}

unsigned short in_cksum(unsigned short *addr,int len)
{
    register int nleft = len;
    register u_short *w = addr;
    register int sum = 0;
    u_short answer = 0;

    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return(answer);
}


int PCKT_Send(int sockfd,uint32_t saddr,uint32_t daddr,int ttl,uint16_t sport, uint16_t dport,unsigned char *payload,int len){
    int ret;
    struct iphdr  ip;
    struct udphdr udp;
    static char packet[1500];
    struct sockaddr_in sin;

    sin.sin_family     = AF_INET;
    sin.sin_addr.s_addr= htonl(daddr);
    sin.sin_port       = dport;

    ip.ihl      = 5;
    ip.version  = 4;
    ip.tos      = 0;
    ip.tot_len  = htons(28 + len);
    ip.id       = htons(31337 + (rand()%100));
    ip.frag_off = 0;
    ip.ttl      = ttl;
    ip.protocol = IPPROTO_UDP;
    ip.check    = 0;
    ip.saddr    = htonl(saddr);
    ip.daddr    = htonl(daddr);
    ip.check    = in_cksum((char *)&ip, sizeof(ip));

    udp.source = htons(sport);
    udp.dest   = htons(dport);
    udp.len    = htons(8 + len);
    udp.check  = (short) 0;

    memcpy(packet, (char *)&ip, sizeof(ip));
    memcpy(packet+sizeof(ip), (char *)&udp, sizeof(udp));
    memcpy(packet+sizeof(ip)+sizeof(udp), (char *)payload, len);

    ret = sendto(sockfd, packet, sizeof(ip)+sizeof(udp)+len, 0,
            (struct sockaddr *)&sin, sizeof(struct sockaddr_in));
    return ret;
}
