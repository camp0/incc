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

#include "payload.h"

#define MAX_CRYPT_BUFFER 1500

/*
 * The packet generated have the following fields:
 *
 * ---------------------------------
 * | head | rc4 encryption  | tail |
 * ---------------------------------
 *        /                 \
 *       /                   \
 *      /                     \
 * -----------------------------------
 * | magic_stamp | options | message |
 * -----------------------------------
 *
 */

// TODO: The keys should be changed by using RSA or other algo.
static char *magic_stamp = "kaka"; // A stamp on the payload so the packet its recovered
static int magic_stamp_len = 4;
/**
 * PYLD_GeneratePayload - Generates a ST_Payload give a head, tail and the buffer to send over the network 
 *
 * @param rc4key the encryption key
 * @param head the signature head
 * @param headsize the head signature size
 * @param tail the signature tail
 * @param tailsize the signature tail size
 * @param buffer the buffer to encrypt with RC4
 * @param len the length of the buffer
 *
 * @return ST_Payload
 */

ST_Payload *PYLD_GeneratePayload(char *rc4key,unsigned char *head,int headsize,unsigned char *tail,int tailsize,char *buffer,int len){
    RC4_KEY key;
    ST_Payload *p = g_new(ST_Payload,1);
    int length = 0;
    int crypt_len = 0;
    int offset = 0;
    char buffer_crypt[MAX_CRYPT_BUFFER];
    char buffer_plain[MAX_CRYPT_BUFFER];

    if((head != NULL)&&(headsize>0)) {
        length += headsize;
    }
    if((tail != NULL)&&(tailsize>0)){
        length += tailsize;
    }
    length += len + magic_stamp_len; // 4 bytes of magic stamp 

    p->len = 0;
    p->payload = malloc(length);
    memset(p->payload,0,length);
    bzero(buffer_crypt,MAX_CRYPT_BUFFER);   
    bzero(buffer_plain,MAX_CRYPT_BUFFER);
    
    memcpy(buffer_plain,magic_stamp,magic_stamp_len);
    memcpy(buffer_plain+magic_stamp_len,buffer,len);

    crypt_len = len + magic_stamp_len;
    RC4_set_key(&key,strlen(rc4key),rc4key);    
    RC4(&key,crypt_len,buffer_plain,buffer_crypt);

    if((head != NULL)&&(headsize>0)){
        memcpy(p->payload,head,headsize);
        offset += headsize;
    }
    memcpy((p->payload+offset),buffer_crypt,crypt_len);
    offset += crypt_len;
    if((tail != NULL)&&(tailsize>0)){
        memcpy((p->payload+offset),tail,tailsize);
    }
    p->len = length;
    return p;
}

/**
 * PYLD_RecoverPayload - Tries to recover a ST_Payload give a head, tail previously detected
 *  If the message is corrected and recovered by the RC4 key a new ST_Payload is returned, in
 *  any other case NULL is returned 
 *
 * @param rc4key the encryption key
 * @param p the ST_Payload with the original payload and its length
 * @param head the signature head
 * @param headsize the signature head size
 * @param tail the signature tail
 * @param tailsize the signature tail size
 *
 * @return ST_Payload
 */

ST_Payload *PYLD_RecoverPayload(char *rc4key,ST_Payload *p,unsigned char *head,int headsize, unsigned char *tail,int tailsize) {
    RC4_KEY key;
    ST_Payload *pnew = NULL;
    int offset = 0;
    int length = 0;
    char buffer_plain[MAX_CRYPT_BUFFER];

    if(head)
        offset = headsize;

    length = p->len - offset;
    if(tail)
        length = length - tailsize;

    if(length < 0){ // there is nothing to recover
        return NULL;
    }

    bzero(buffer_plain,MAX_CRYPT_BUFFER);
    RC4_set_key(&key,strlen(rc4key),rc4key);    
    RC4(&key,length,(p->payload+offset),buffer_plain);  

    //check the magic stamp
    if(memcmp(buffer_plain,magic_stamp,magic_stamp_len) == 0) {
        ST_Payload *pnew = g_new(ST_Payload,1);
        
        pnew->payload = NULL;
        pnew->len = 0;

        length = length - magic_stamp_len;  
        pnew->payload = malloc(length);
        pnew->len =  length;
        bzero(pnew->payload,length);
        memcpy(pnew->payload,(buffer_plain+magic_stamp_len),length);

        return pnew;
    }
    return NULL; 
}

/**
 * PYLD_Destroy - Frees a ST_Payload.
 *
 * @param p the ST_Payload to free. 
 *
 */

void PYLD_Destroy(ST_Payload *p){
    if(p){
        free(p->payload);
        g_free(p);
        p = NULL;
    }
    return;
}

void __PYLD_PrintfHexAscii(unsigned char *payload, int len, int offset){
    register int i;
    int gap;
    unsigned char *ch;

    printf("%05d   ", offset);
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        if (i == 7) printf(" ");
    }
    if (len <8 ) printf(" ");
    
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) printf("   ");
    }
    printf("   ");
    
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    printf("\n");
    return;
}

void PYLD_Printf(ST_Payload *p){
    int len_rem = p->len;
    int line_width = 16; 
    int line_len;
    int offset = 0; 
    unsigned char *ch = p->payload;

    if (p->len <= 0)
        return;

    if (p->len <= line_width) {
        __PYLD_PrintfHexAscii(ch, p->len, offset);
        return;
    }

    for(;;) {
        /* compute current line length */
        line_len = line_width % len_rem;

        __PYLD_PrintfHexAscii(ch, line_len, offset);
        len_rem = len_rem - line_len;
        ch = ch + line_len;
        offset = offset + line_width;
        if (len_rem <= line_width) {
            __PYLD_PrintfHexAscii(ch, len_rem, offset);
            break;
        }
    }
    return;
}
