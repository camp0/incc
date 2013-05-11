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

#ifndef _DETECTION_H_
#define _DETECTION_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <glib.h>
#include "signature.h"
#include "interfaces.h"
#include "genericflow.h"

struct ST_Available {
	ST_Signature *sig;

	struct timeval arrive_time;
	struct timeval current_time;
};

typedef struct ST_Available ST_Available;

struct ST_Detection {
	GSList *signatures;
	GHashTable *available;
	int32_t total_releases;
	int32_t total_acquires;
	int32_t total_errors;
};

typedef struct ST_Detection ST_Detection;

ST_Detection *DTTN_Init(void);
void DTTN_Destroy(ST_Detection *d);
void DTTN_AddSignature(ST_Detection *d,ST_Signature *s);
ST_Signature *DTTN_MatchsSignatures(ST_Detection *d,ST_GenericFlow *f,unsigned char *payload,int len);
void DTNN_Stats(ST_Detection *d);
ST_Available *DTTN_GetAvailable(ST_Detection *d);


#endif
