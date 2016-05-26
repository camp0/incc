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

#ifndef _SIGNATURE_H_
#define _SIGNATURE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <sys/types.h>
#include "interfaces.h"
#include <pcre.h>

#define MAX_EXPRESSION_NAME 32
#define MAX_EXPRESSION 32

struct ST_Signature {
    int identifier;
    char name[MAX_EXPRESSION_NAME];
    unsigned char expression[MAX_EXPRESSION];
    unsigned char head[MAX_EXPRESSION];
    unsigned char tail[MAX_EXPRESSION];
    int headsize;
    int tailsize;
    pcre *regex;
    pcre_extra *extra_regex;
    int32_t matchs;
    
    // last flow that matchs the signature
    u_int32_t ipsrc;
    u_int32_t ipdst;
    u_int16_t portsrc;
    u_int16_t portdst;
} __attribute__((packed));

typedef struct ST_Signature ST_Signature;

ST_Signature *SGNT_Init(void); 
void SGNT_Destroy(ST_Signature *sig);
void SGNT_SetValues(ST_Signature *sig,int identifier,char *name,char *expression,
    unsigned char *head,int headsize, unsigned char *tail,int tailsize);
int SGNT_Matchs(ST_Signature *s,unsigned char *payload,int len);

#endif
