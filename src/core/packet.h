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

#ifndef _PACKET_H_
#define _PACKET_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>


int PCKT_Init(void);
int PCKT_InitToDevice(char *dev);
int PCKT_Send(int sockfd,uint32_t saddr,uint32_t daddr,int ttl,uint16_t sport, uint16_t dport,unsigned char *payload,int len);


#endif
