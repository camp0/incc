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

#ifndef _GENERICFLOW_H_
#define _GENERICFLOW_H_

#include <sys/types.h>

struct ST_GenericFlow {
	u_int32_t saddr;
	u_int32_t daddr;
	u_int16_t sport;
	u_int16_t dport;
	u_int16_t protocol;

	short detected;

	int32_t total_bytes;
        int32_t total_packets;

	struct timeval arrive_time;
	struct timeval current_time;
	void (*release)(struct ST_GenericFlow *f,void *data);
} __attribute__((packed));

typedef struct ST_GenericFlow ST_GenericFlow;

static void GEFW_SetFlowId(ST_GenericFlow *f,u_int32_t saddr,u_int16_t sport,u_int16_t protocol,u_int32_t daddr,u_int16_t dport){
	f->saddr = saddr;
	f->sport = sport;
	f->daddr = daddr;
	f->dport = dport;
	f->protocol = protocol;
	f->detected = 0;
	f->release = NULL;
	return;
}
static void GEFW_Reset(ST_GenericFlow *f) { 
	f->total_bytes = 0;f->total_packets= 0;
	f->arrive_time.tv_sec = 0;f->arrive_time.tv_usec = 0;
	f->current_time.tv_sec = 0;f->current_time.tv_usec = 0;
	f->detected = 0;
	f->release = NULL;
	return;
};

static void GEFW_SetArriveTime(ST_GenericFlow *f,struct timeval *t) { 
	f->arrive_time.tv_sec = t->tv_sec;f->arrive_time.tv_usec = t->tv_usec;
	f->current_time.tv_sec = t->tv_sec;f->current_time.tv_usec = t->tv_usec; 
};

static void GEFW_UpdateTime(ST_GenericFlow *f,struct timeval *t) {
	f->current_time.tv_sec = t->tv_sec;f->current_time.tv_usec = t->tv_usec; 
}

static void GEFW_Destroy(ST_GenericFlow *f){
	if(f){
		g_free(f);
		f = NULL;
	}
}
#endif
