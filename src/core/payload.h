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

#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <openssl/rc4.h>

struct ST_Payload{
	unsigned char *payload;
	int len;
};

typedef struct ST_Payload ST_Payload;

ST_Payload *PYLD_GeneratePayload(char *rc4key,unsigned char *head, int headsize, unsigned char *tail, int tailsize,char *buffer,int len);
ST_Payload *PYLD_RecoverPayload(char *rc4key,ST_Payload *p,unsigned char *head, int headsize, unsigned char *tail,int tailsize);
void PYLD_Destroy(ST_Payload *p);
void PYLD_Printf(ST_Payload *p);

#endif
