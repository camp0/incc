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

#include "detection.h"

#define INCCLOG_CATEGORY_NAME INCC_INTERFACE
#include "log.h"

/**
 * DTTN_Init - Initialize the detection
 *
 * @return ST_Detection
 */

ST_Detection *DTTN_Init() {
	ST_Detection *d = NULL;

	d = (ST_Detection*)g_new(ST_Detection,1);
	d->signatures = NULL;	
	d->available = g_hash_table_new(g_str_hash,g_str_equal);
	return d;
}

/**
 * DTTN_Stats - Shows statistics of a ST_Detection
 *
 */

void DTTN_Stats(ST_Detection *d){
        GHashTableIter iter;
        gpointer k,v;

	GSList *current = d->signatures;
	fprintf(stdout,"Detection statistics\n");
	while(current!= NULL) {
		ST_Signature *s = (ST_Signature*)current->data;

		fprintf(stdout,"\tSignature id %d, name '%s', matchs %d\n",
			s->identifier,s->name,s->matchs);
		current = g_slist_next(current);
	}
        g_hash_table_iter_init (&iter, d->available);
        while (g_hash_table_iter_next (&iter, &k, &v)) {
                ST_Available *av = (ST_Available*)v;
		
		fprintf(stdout,"\tSession %s duration %d seconds\n",av->sig->name,av->current_time.tv_sec-av->arrive_time.tv_sec);
	}
	return;
}

/**
 * DTTN_GetAvailable - Gets the most available signature detected
 *
 * @param d
 *
 * @return ST_Available
 */

ST_Available *DTTN_GetAvailable(ST_Detection *d){
	GHashTableIter iter;
        gpointer k,v;
	ST_Available *best = NULL;

        g_hash_table_iter_init (&iter, d->available);
        while (g_hash_table_iter_next (&iter, &k, &v)) {
                ST_Available *av = (ST_Available*)v;
		if(best == NULL) 
			best = av;

		return best;	
        }
	return NULL;
}


/**
 * DTTN_Destroy - free a ST_Detection
 *
 * @param p the ST_Detection to free
 */
void DTTN_Destroy(ST_Detection *d){
	// TODO 

	g_slist_free(d->signatures);
	g_free(d);
	d = NULL;
}

void DTTN_AddSignature(ST_Detection *d,ST_Signature *s){

	if(s) {
		LOG(INCCLOG_PRIORITY_INFO,
			"Add signature id(%d) to the detection ",s->identifier);

		d->signatures = g_slist_prepend(d->signatures,s);
	}
        return ;
}

ST_Signature *DTTN_MatchsSignatures(ST_Detection *d,ST_GenericFlow *f,unsigned char *payload,int len){
	GSList *current = d->signatures;
	int ret;

	while(current!= NULL) {
		ST_Signature *sig = (ST_Signature*)current->data;

		ret = SGNT_Matchs(sig,payload,len);
		if(ret == 1) {
			ST_Available *av = NULL;
			struct timeval curr_time;

			f->detected = 1;
			gettimeofday(&curr_time,NULL);
			av = (ST_Available *)g_hash_table_lookup(d->available,(gchar*)sig->name);
			if( av == NULL) {
				av = g_new(ST_Available,1);
				av->sig = sig;
				av->arrive_time.tv_sec = curr_time.tv_sec;
				av->arrive_time.tv_usec = curr_time.tv_usec;
				
				g_hash_table_insert(d->available,g_strdup(sig->name),av);
			}
			av->current_time.tv_sec = curr_time.tv_sec;
			av->current_time.tv_usec = curr_time.tv_usec;
			
			return sig;
		}
		current = g_slist_next(current);
	}
	return NULL;
}
