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

#ifndef _INCC_H_
#define _INCC_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <dbus/dbus.h>
#include <stdio.h>
#include <glib.h>
#include <log4c.h>
#include <sys/time.h>
#include "detection.h"
#include "packetcontext.h"
#include "packetdecoder.h"
#include "protocol.h"
#include "connection.h"
#include "payload.h"
#include "flowpool.h"
#include "system.h"
#include "privatecallbacks.h"
#include "banner.h"

enum {
        INCC_STATE_STOP = 0,
        INCC_STATE_RUNNING
} incc_states;

static const char *incc_states_str [] = { "stop","running"};

#define INCC_ENGINE_NAME "InCC engine"

struct ST_InCCEngine {
	int incc_status;
	int pcapfd;
	int is_pcap_file;
	int when_pcap_done_exit;
	int sockrawfd; // socket for outbound messages;
	short show_generated_payloads;
	char *output_file_name;
	FILE *output_file;

	// Info related to the spoofed flow
	uint32_t src_address;
	uint32_t dst_address;
	uint32_t src_mask_address;
	uint32_t dst_mask_address;
	int16_t src_port;
	int16_t dst_port;
	int ttl;

	DBusConnection *bus;
	ST_Connection *conn;
	ST_FlowPool *flowpool;
	ST_Detection *detect;
	ST_Protocol *protocol;
	GString *source;
	pcap_t *pcap;
	// Statistics
	int32_t send_messages;
	int32_t receive_messages;
	int32_t decrypt_messages;
};

typedef struct ST_InCCEngine ST_InCCEngine;

void INCC_Init(void);
void INCC_Destroy(void);

void INCC_AddSignature(int identifier,char *name, char *expression,char *head,int hsize, char *tail,int tsize);
void INCC_SetSource(char *source);
void INCC_SetExitOnPcap(int value);
void INCC_SetOutputFileName(char *file_name);

void INCC_ShowGeneratedPayload(int value);
void INCC_SetPacketTTL(int ttl);
void INCC_SetSourceIP(char *ipsrc);
void INCC_SetSourcePort(int srcport);
void INCC_SetDestinationIP(char *ipdst);
void INCC_SetDestinationPort(int dstport);
void INCC_SetEncryptionKey(char *key);

void INCC_SendMessage(char *message);

void INCC_Stats(void);
void INCC_Start(void);
void INCC_Stop(void);
void INCC_StopAndExit(void);
void INCC_Run(void);

#endif
