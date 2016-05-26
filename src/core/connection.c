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

#include "connection.h"
#include "genericflow.h"

#define INCCLOG_CATEGORY_NAME INCC_INTERFACE
#include "log.h"

/**
 * COMN_SetFlowPool - Sets the reference of the flowpool on the ST_Connection.
 *
 * @param conn the ST_Connection 
 * @param flowpool 
 */

void COMN_SetFlowPool(ST_Connection *conn,ST_FlowPool *flowpool){
    conn->flowpool = flowpool;
}

/**
 * COMN_Stats - Show the statistics
 *
 * @param conn the ST_Connection 
 */

void COMN_Stats(ST_Connection *conn) {
 
    fprintf(stdout,"Connection statistics\n");
    fprintf(stdout,"\ttimeout:%d seconds\n",conn->inactivitytime);
    fprintf(stdout,"\treleases:%d\n",conn->releases);
    fprintf(stdout,"\tinserts:%d\n",conn->inserts);
    fprintf(stdout,"\texpires:%d\n",conn->expiretimers);
    return;
}


gint flow_cmp(ST_GenericFlow *f1, ST_GenericFlow *f2) {
    if (f1->current_time.tv_sec > f2->current_time.tv_sec)
        return 1;
    else
        return 0;
}

/**
 * COMN_ReleaseConnection - Release a ST_GenericFlow to the ST_Connection.
 *
 * @param conn the ST_Connection 
 * @param flow 
 */
void COMN_ReleaseConnection(ST_Connection *conn,ST_GenericFlow *flow) {
    unsigned long h = (flow->saddr^flow->sport^flow->protocol^flow->daddr^flow->dport);

    if(g_hash_table_remove(conn->table,GINT_TO_POINTER(h)) == FALSE) {
        h = (flow->daddr^flow->dport^flow->protocol^flow->saddr^flow->sport);
        g_hash_table_remove(conn->table,GINT_TO_POINTER(h));
    }

    // Execute the callback associated to the flow
    if(flow->release != NULL) 
        flow->release(flow,NULL);
    // TODO: This should be optimized maybe by a tree.
    conn->timers = g_list_remove(conn->timers,flow);
/*
#ifdef DEBUG
    LOG(INCCLOG_PRIORITY_DEBUG,
            "Release flow(0x%x) to flowpool(0x%x)",
            flow,conn->flowpool);
#endif
*/
    FLPO_AddFlow(conn->flowpool,flow);
    conn->current_connections--;
    conn->releases++;
    return;
}


/**
 * COMN_InsertConnection - Adds a ST_GenericFlow to the ST_Connection.
 *
 * @param conn the ST_Connection 
 * @param flow 
 * @param hash 
 */

void COMN_InsertConnection(ST_Connection *conn,ST_GenericFlow *flow,unsigned long *hash){
    struct in_addr a,b;

    a.s_addr = flow->saddr;
    b.s_addr = flow->daddr;

    unsigned long h = (flow->saddr^flow->sport^flow->protocol^flow->daddr^flow->dport);
    (*hash) = h;

    conn->current_connections++;
    conn->inserts++;

    g_hash_table_insert(conn->table,GINT_TO_POINTER(h),flow);
    conn->timers = g_list_insert_sorted(conn->timers,flow,(GCompareFunc)flow_cmp);
    return;
}

/**
 * COMN_UpdateTimers - Updates the flow list in order to release the flows.
 *
 * @param conn the ST_Connection 
 * @param currenttime 
 * 
 */
void COMN_UpdateTimers(ST_Connection *conn,struct timeval *currenttime){
    GList *f_update = NULL;
    GList *current = NULL;
    ST_GenericFlow *flow = NULL;

    while((current = g_list_first(conn->timers)) != NULL) {
        flow =(ST_GenericFlow*)current->data;
        conn->timers = g_list_remove_link(conn->timers,current);

        if(flow->current_time.tv_sec + conn->inactivitytime <= currenttime->tv_sec) {
                        /* The timer expires */
#ifdef DEBUG
            LOG(INCCLOG_PRIORITY_DEBUG,
                "Expire timer for flow(0x%x)secs(%d)curr(%d)",flow,flow->current_time.tv_sec,currenttime->tv_sec);
#endif
            COMN_ReleaseConnection(conn,flow);

            conn->expiretimers++; 
            continue;
        }
        f_update = g_list_insert_sorted(f_update,flow,(GCompareFunc)flow_cmp);
    }
    conn->timers = g_list_concat(f_update,conn->timers);
    return;
}

/**
 * COMN_Init - Creates a ST_Connection type.
 *
 * @return ST_Connection 
 * 
 */

ST_Connection *COMN_Init() {
    ST_Connection *conn= NULL;

    conn =(ST_Connection*)g_new(ST_Connection,1);
    conn->table = g_hash_table_new(g_direct_hash,g_direct_equal);
    conn->timers = NULL;
    conn->inactivitytime = 180;
    conn->expiretimers = 0;
    conn->releases = 0;
    conn->inserts = 0;
    conn->current_connections = 0;
    conn->flowpool = NULL;
    return conn;
};

/**
 * COMN_ReleaseFlows - Releases all the flows stored on the ST_Connection.
 *
 * @param conn 
 * 
 */

void COMN_ReleaseFlows(ST_Connection *conn){
    GHashTableIter iter;
    GList *l = NULL; 
    int items = 0;

    while((l = g_list_first(conn->timers)) != NULL) {
        ST_GenericFlow *flow =(ST_GenericFlow*)l->data;
        COMN_ReleaseConnection(conn,flow);
        items++;
    }   
/*
#ifdef DEBUG
    LOG(INCCLOG_PRIORITY_DEBUG,
            "Releasing %d flows to flowpool(0x%x)",
        items,conn->flowpool);
#endif
*/
    return;
}

/**
 * COMN_Destroy - Destroy the ST_Connection.
 *
 * @param conn 
 * 
 */

void COMN_Destroy(ST_Connection *conn) {
    g_hash_table_destroy(conn->table);
    g_list_free(conn->timers);
    g_free(conn); 
}

/**
 * COMN_FindConnection - Finds a ST_HttFlow associated to a tcp connection.
 *
 * @param conn 
 * @param saddr 
 * @param sport 
 * @param protocol 
 * @param daddr
 * @param dport 
 * @param hash 
 *
 * @return ST_GenericFlow
 * 
 */
ST_GenericFlow *COMN_FindConnection(ST_Connection *conn,u_int32_t saddr,u_int16_t sport,u_int16_t protocol,u_int32_t daddr,u_int16_t dport,unsigned long *hash){
    gpointer object;
    ST_GenericFlow *f = NULL;
    struct in_addr a,b;

    a.s_addr = saddr;
    b.s_addr = daddr;

    unsigned long h = (saddr^sport^protocol^daddr^dport);

    object = g_hash_table_lookup(conn->table,GINT_TO_POINTER(h));
    if (object != NULL){
        (*hash) = h;
    f = (ST_GenericFlow*)object;
        return f;
    }

    h = (daddr^dport^protocol^saddr^sport);

    object = g_hash_table_lookup(conn->table,GINT_TO_POINTER(h));
    if (object != NULL){
        (*hash) = h;
    f = (ST_GenericFlow*)object;
        return f;
    }
    return NULL;
}

