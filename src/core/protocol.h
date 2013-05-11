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

#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "signature.h"
#include <sys/types.h>
#include <glib.h>
#include "payload.h"

// Specifies the protocol behaviour
struct ST_Protocol {
	char *rc4_encryption_key; // The rc4 encryption key
};

typedef struct ST_Protocol ST_Protocol;

ST_Protocol *PROT_Init(void);
void PROT_Destroy(ST_Protocol *p);
void PROT_Stats(ST_Protocol *p);
ST_Payload *PROT_GeneratePayload(ST_Protocol *proto,ST_Signature *sig,char *buffer,int len);
ST_Payload *PROT_RecoverPayload(ST_Protocol *proto,ST_Payload *p,ST_Signature *sig);

#endif
