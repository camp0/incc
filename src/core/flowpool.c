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

#include "flowpool.h"

#define INCCLOG_CATEGORY_NAME INCC_INTERFACE
#include "log.h"
/**
 * FLPO_Init - Initialize a flow pool 
 *
 * @return ST_FlowPool
 */

ST_FlowPool *FLPO_Init() {
    ST_FlowPool *pool = NULL;

    pool = (ST_FlowPool*)g_new(ST_FlowPool,1);
    pool->flows = NULL; 
    pool->total_releases = 0;
    pool->total_acquires = 0;
    pool->total_errors = 0;

    FLPO_IncrementFlowPool(pool,MAX_FLOWS_PER_POOL);
    return pool;
}

/**
 * FLPO_Stats - Shows statistics of a ST_FlowPool
 *
 */

void FLPO_Stats(ST_FlowPool *p){
    int32_t value = MAX_FLOWS_PER_POOL * sizeof(ST_GenericFlow);
    char *unit = "Bytes";

    if((value / 1024)>0){
        unit = "KBytes";
        value = value / 1024;
    }
    if((value / 1024)>0){
        unit = "MBytes";
        value = value / 1024;
    }

    fprintf(stdout,"FlowPool statistics\n");
    fprintf(stdout,"\tflow size:%d bytes\n",sizeof(ST_GenericFlow));
    fprintf(stdout,"\tallocated memory:%d %s\n",value,unit);
    fprintf(stdout,"\tflows:%d\n\treleases:%d\n",g_slist_length(p->flows),p->total_releases);
    fprintf(stdout,"\tacquires:%d\n\terrors:%d\n",p->total_acquires,p->total_errors);
    return;
}

/**
 * FLPO_Destroy - free a ST_FlowPool
 *
 * @param p the ST_FlowPool to free
 */
void FLPO_Destroy(ST_FlowPool *p){
    FLPO_DecrementFlowPool(p,g_slist_length(p->flows));
    g_slist_free(p->flows);
    g_free(p);
    p = NULL;
}

int FLPO_GetNumberFlows(ST_FlowPool *p){
    return g_slist_length(p->flows);
}

/**
 * FLPO_IncrementFlowPool - Increments the items of a ST_FlowPool 
 *
 * @param p the ST_FlowPool
 * @param value the number of new ST_GenericFlows to alloc
 */

int FLPO_IncrementFlowPool(ST_FlowPool *p,int value){
    int i;

    if (value < 1)
        return FALSE;
    LOG(INCCLOG_PRIORITY_INFO,
        "Allocating %d flows on pool, current flows on pool %d",value,g_slist_length(p->flows));

    for (i = 0;i<value;i++){
        ST_GenericFlow *f = g_new0(ST_GenericFlow,1);
        GEFW_Reset(f);  
        p->flows = g_slist_prepend(p->flows,f);
    }
    return TRUE;
}

/**
 * FLPO_DecrementFlowPool - Decrements the items of a ST_FlowPool 
 *
 * @param p the ST_FlowPool
 * @param value the number of new ST_GenericFlows to free 
 */

int FLPO_DecrementFlowPool(ST_FlowPool *p,int value) {
    ST_GenericFlow *f;
    int i,r;

    if (value > g_slist_length(p->flows))
        r = g_slist_length(p->flows);
    else
        r = value;

    LOG(INCCLOG_PRIORITY_INFO,
        "Freeing %d flows on pool",r);
    for (i = 0;i<r;i++){
        GSList *item = g_slist_nth(p->flows,0);
        if (item != NULL) {
            p->flows = g_slist_remove_link(p->flows,item);
            f = (ST_GenericFlow*)item->data;
            GEFW_Destroy(f);
        }
    }
    return TRUE;
}

/**
 * FLPO_AddFlow - Adds a ST_GenericFlow to a ST_FlowPool 
 *
 * @param p the ST_FlowPool
 * @param flow e 
 */

void FLPO_AddFlow(ST_FlowPool *p,ST_GenericFlow *flow){
    if(flow != NULL){ 
        GEFW_Reset(flow);
        p->total_releases++;
        p->flows = g_slist_prepend(p->flows,flow);
    }
}

/**
 * FLPO_GetFlow - Gets a ST_GenericFlow from a ST_FlowPool 
 *
 * @param p the ST_FlowPool
 *
 * @return ST_GenericFlow  
 */

ST_GenericFlow *FLPO_GetFlow(ST_FlowPool *p){
    GSList *item = NULL;

    item = g_slist_nth(p->flows,0);
    if (item!= NULL) {
        p->flows = g_slist_remove_link(p->flows,item);
        p->total_acquires++;
        return (ST_GenericFlow*)item->data;
    }
    p->total_errors++;
    return NULL;
}


