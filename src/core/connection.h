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

#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <log4c.h>
#include "flowpool.h"
#include "interfaces.h"
#include <netinet/in.h>

struct ST_Connection {
	GHashTable *table;
	GList *timers;
	int inactivitytime;
	int32_t expiretimers;
	int32_t inserts;
	int32_t releases;
	int32_t current_connections;
	ST_FlowPool *flowpool;
};

typedef struct ST_Connection ST_Connection;

ST_Connection *COMN_Init(void);
void COMN_Destroy(ST_Connection *conn); 

ST_GenericFlow *COMN_FindConnection(ST_Connection *conn,u_int32_t saddr,u_int16_t sport,u_int16_t protocol,u_int32_t daddr,u_int16_t dport,unsigned long *hash);
void COMN_InsertConnection(ST_Connection *conn,ST_GenericFlow *flow,unsigned long *hash);
void COMN_UpdateTimers(ST_Connection *conn,struct timeval *currenttime);
void COMN_SetFlowPool(ST_Connection *conn,ST_FlowPool *flowpool);
void COMN_ReleaseFlows(ST_Connection *conn);
void COMN_Stats(ST_Connection *conn);

#endif

