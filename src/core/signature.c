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

#include "signature.h"
#include "packetcontext.h"

#define INCCLOG_CATEGORY_NAME INCC_INTERFACE
#include "log.h"

/**
 * SGNT_Init - Initialize a signature  
 *
 * @return ST_Signature
 */

ST_Signature *SGNT_Init() {
    ST_Signature *sig = NULL;

    sig = (ST_Signature*)g_new(ST_Signature,1);
    sig->identifier = 0;
    bzero(sig->name,MAX_EXPRESSION_NAME);
    bzero(sig->expression,MAX_EXPRESSION);
    bzero(sig->head,MAX_EXPRESSION);
    bzero(sig->tail,MAX_EXPRESSION);
    sig->regex = NULL;
    sig->extra_regex = NULL;
    sig->matchs = 0;
    sig->ipsrc = 0;
    sig->ipdst = 0;
    sig->portsrc = 0;
    sig->portdst = 0;
    sig->headsize = 0;
    sig->tailsize = 0;
    return sig;
}

/**
 * SGNT_Destroy - free a ST_Signature
 *
 * @param p the ST_Signature to free
 */

void SGNT_Destroy(ST_Signature *sig){
    pcre_free(sig->regex);
#if PCRE_MAYOR == 8 && PCRE_MINOR >= 20
    pcre_free_study(sig->extra_regex);
#else
    pcre_free(sig->extra_regex);
#endif
    g_free(sig);
    sig = NULL;
    return;
}

/**
 * SGNT_SetValues - Sets the values to the ST_Signature struct 
 *
 * @param sig the ST_Signature
 * @param identifier 
 * @param name
 * @param expression
 * @param head
 * @param headsize
 * @param tail
 * @param tailsize
 * 
 */

void SGNT_SetValues(ST_Signature *sig,int identifier,char *name,char *expression,
    unsigned char *head, int headsize, unsigned char *tail, int tailsize) {
    const char *errstr;
    int rsize;
    int erroffset;

    if(sig){
        sig->identifier = identifier;
        snprintf(sig->name,MAX_EXPRESSION_NAME,"%s",name);
        snprintf(sig->expression,MAX_EXPRESSION,"%s",expression);
        bzero(sig->head,MAX_EXPRESSION);
        if((head != NULL)||(headsize>0)){
            if(headsize>MAX_EXPRESSION)
                rsize = MAX_EXPRESSION;
            else
                rsize = headsize;
            memcpy(sig->head,head,rsize);
            sig->headsize = rsize;  
        }

        bzero(sig->tail,MAX_EXPRESSION);
        sig->tailsize = 0;
        if((tail != NULL)&&(tailsize>0)){
            if(tailsize > MAX_EXPRESSION)
                rsize = MAX_EXPRESSION;
            else
                rsize = tailsize;

            memcpy(sig->tail,tail,rsize);
            sig->tailsize = tailsize;
        }
        sig->regex = pcre_compile((char*)expression, 0, &errstr, &erroffset, 0);
        if(sig->regex == NULL) {
            LOG(INCCLOG_PRIORITY_WARN,
                "PCRE expression compilation fail '%s'",errstr);
            return;
        }
#ifdef PCRE_HAVE_JIT
        sig->extra_regex = pcre_study(sig->regex,PCRE_STUDY_JIT_COMPILE,&errstr);
        if(sig->extra_regex == NULL) {
            LOG(INCCLOG_PRIORITY_WARN,
                "PCRE study with JIT support failed '%s'",errstr);
        }
        int jit = 0;
        int ret;

        ret = pcre_fullinfo(sig->regex,sig->extra_regex, PCRE_INFO_JIT,&jit);
        if (ret != 0 || jit != 1) {
            LOG(INCCLOG_PRIORITY_WARN,
                "PCRE JIT compiler does not support the expresion '%s'",sig->expression);
        }
#else
        sig->extra_regex = pcre_study(sig->regex,0,&errstr);
        if(sig->extra_regex == NULL)
            LOG(INCCLOG_PRIORITY_WARN,
                "PCRE study failed '%s'",errstr);
#endif
    }
    return;
}

#define OVECCOUNT 32

/**
 * Prints a buffer, just for debugging pourposes. 
 *
 * @param payload pointer to the buffer 
 * @param size of the buffer 
 */
void printfhex(char *payload,int size) {
    char buffer[10];
    int i,fd;
    const u_char *ptr;
    int online = 0;

    ptr = payload;
    write(0,"\n",1);
    for ( i= 0;i<size;i++) {
        if ( online == 16 ) {
            write(0,"\n",1);
            online = 0;
        }
        online ++;
        sprintf(buffer,"%02x ",*ptr);
        write(0,buffer,strlen(buffer));
        ptr++;
    }
    write(0,"\n",1);
    return;
}

/**
 * SGNT_Matchs - Evaluate the given payload with the corresponding regex 
 *
 * @param s the ST_Signature
 * @param payload 
 * @param len 
 * 
 */

int SGNT_Matchs(ST_Signature *s,unsigned char *payload,int len) {
    int ret = 0;
    int ovector[OVECCOUNT];

    ret = pcre_exec(s->regex,s->extra_regex,(char*)payload,len,
        0 /* Start offset */,
        0 /* options */ ,
        ovector, OVECCOUNT);

    if (ret > 0) {
        s->matchs ++;
        s->ipsrc = PKCX_GetIPSrcAddr();
        s->ipdst = PKCX_GetIPDstAddr();
        s->portsrc = PKCX_GetUDPSrcPort();
        s->portdst = PKCX_GetUDPDstPort();
        return 1;
    }
    return 0;
}
