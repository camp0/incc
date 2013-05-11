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

#include "protocol.h"

#define INCCLOG_CATEGORY_NAME INCC_INTERFACE
#include "log.h"

/**
 * PROT_Init - Initialize the protocol 
 *
 * @return ST_Protocol
 */

ST_Protocol *PROT_Init() {
	ST_Protocol *p = NULL;

	p = (ST_Protocol*)g_new(ST_Protocol,1);
	p->rc4_encryption_key = "kaka";
	return p;
}

/**
 * PROT_Stats - Shows statistics of a ST_Protocol
 *
 */

void PROT_Stats(ST_Protocol *p){

	fprintf(stdout,"Protocol statistics\n");
	return;
}

/**
 * PROT_Destroy - free a ST_Protocol
 *
 * @param p the ST_Protocol to free
 */
void PROT_Destroy(ST_Protocol *p){
	g_free(p);
	p = NULL;
}

/**
 * PROT_GeneratePayload - Generates a ST_Payload given a ST_Protocol. 
 *
 * @param proto the ST_Protocol 
 * @param sig the ST_Signature 
 * @param buffer the buffer to send
 * @param len the length of the buffer
 *
 * @return ST_Payload
 */
ST_Payload *PROT_GeneratePayload(ST_Protocol *proto,ST_Signature *sig,char *buffer,int len){
	ST_Payload *payload = NULL;

	payload = PYLD_GeneratePayload(proto->rc4_encryption_key,
		sig->head,
		sig->headsize,
		sig->tail,
		sig->tailsize,
		buffer,len);

	return payload;
}

/**
 * PROT_Destroy - free a ST_Protocol
 *
 * @param proto the ST_Protocol 
 * @param sig the ST_Signature
 *
 * @return ST_Payload
 */
ST_Payload *PROT_RecoverPayload(ST_Protocol *proto,ST_Payload *p,ST_Signature *sig){
	ST_Payload *payload = NULL;

	payload = PYLD_RecoverPayload(proto->rc4_encryption_key,p,
		sig->head,
		sig->headsize,
		sig->tail,
		sig->tailsize);

	return payload;
}

