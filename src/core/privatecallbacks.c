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

#include "incc.h"
#include "callbacks.h"

/* Used for the Property Dbus interface */
void __CMD_GenericPropertyGetter(DBusConnection *conn,DBusMessage *msg,int type, void *value) {
    DBusMessageIter args;
    DBusMessage *reply = NULL;

    reply = dbus_message_new_method_return(msg);

    dbus_message_iter_init(reply, &args);
    dbus_message_iter_init_append(reply, &args);
    if (!dbus_message_iter_append_basic(&args, type, &value)) {
        fprintf(stderr, "Out Of Memory!\n");
        return;
    }

    if (!dbus_connection_send(conn, reply, NULL)) {
        fprintf(stderr, "Out Of Memory!\n");
        return;
    }
    dbus_connection_flush(conn);
    dbus_message_unref(reply);

    return;
}

void __CMD_GenericMethodResponse(DBusConnection *conn,DBusMessage *reply,DBusMessageIter *args,int type, void *value){
    dbus_message_iter_init(reply, args);
    dbus_message_iter_init_append(reply, args);
    dbus_message_iter_append_basic(args,type,&value);

    if (!dbus_connection_send(conn, reply, NULL)) {
        fprintf(stderr, "Out Of Memory!\n");
        return;
    }
    dbus_connection_flush(conn);
    dbus_message_unref(reply);

    return;
}


/* Engine Methods */
void PRCA_Method_StartEngine(DBusConnection *conn,DBusMessage *msg, void *data){
    DBusMessageIter args;
    DBusMessage *reply = NULL;
    int value = 1;

    reply = dbus_message_new_method_return(msg);

    INCC_Start();
    
    dbus_message_iter_init(reply, &args);
    dbus_message_iter_init_append(reply, &args);
    dbus_message_iter_append_basic(&args,DBUS_TYPE_BOOLEAN,&value);

    if (!dbus_connection_send(conn, reply, NULL)) {
        fprintf(stderr, "Out Of Memory!\n");
        return;
    }
    dbus_connection_flush(conn);
    dbus_message_unref(reply);

    return;
}

void PRCA_Method_StopEngine(DBusConnection *conn,DBusMessage *msg, void *data){
    DBusMessageIter args;
    DBusMessage *reply = NULL;
    int value = 1;

    reply = dbus_message_new_method_return(msg);

    INCC_Stop();

    dbus_message_iter_init(reply, &args);
    dbus_message_iter_init_append(reply, &args);
    dbus_message_iter_append_basic(&args,DBUS_TYPE_BOOLEAN,&value);

    if (!dbus_connection_send(conn, reply, NULL)) {
        fprintf(stderr, "Out Of Memory!\n");
        return;
    }
    dbus_connection_flush(conn);
    dbus_message_unref(reply);

    return;
}


void PRCA_Method_SetSource(DBusConnection *conn,DBusMessage *msg, void *data){
    DBusMessageIter args;
    char *param = "";
    DBusMessage *reply = NULL;
    int value = 1;

    reply = dbus_message_new_method_return(msg);

    if (!dbus_message_iter_init(msg, &args))
        fprintf(stderr, "Message has no arguments!\n");
    else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
        fprintf(stderr, "Argument is not string!\n");
    else
        dbus_message_iter_get_basic(&args, &param);

    INCC_SetSource(param);

    dbus_message_iter_init(reply, &args);
    dbus_message_iter_init_append(reply, &args);
    dbus_message_iter_append_basic(&args,DBUS_TYPE_BOOLEAN,&value);

    if (!dbus_connection_send(conn, reply, NULL)) {
        fprintf(stderr, "Out Of Memory!\n");
        return;
    }
    dbus_connection_flush(conn);
    dbus_message_unref(reply);

    return;
}


void PRCA_Method_SendMessage(DBusConnection *conn,DBusMessage *msg, void *data){
    DBusMessageIter args;
    char *param = "";
    DBusMessage *reply = NULL;
    int value = 1;

    reply = dbus_message_new_method_return(msg);

    if (!dbus_message_iter_init(msg, &args))
        fprintf(stderr, "Message has no arguments!\n");
    else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
        fprintf(stderr, "Argument is not string!\n");
    else
        dbus_message_iter_get_basic(&args, &param);

    INCC_SendMessage(param);

    dbus_message_iter_init(reply, &args);
    dbus_message_iter_init_append(reply, &args);
    dbus_message_iter_append_basic(&args,DBUS_TYPE_BOOLEAN,&value);

    if (!dbus_connection_send(conn, reply, NULL)) {
        fprintf(stderr, "Out Of Memory!\n");
        return;
    }
    dbus_connection_flush(conn);
    dbus_message_unref(reply);

    return;
}


void PRCA_Method_ShowDetectedSignatures(DBusConnection *conn,DBusMessage *msg, void *data){
    ST_InCCEngine *p = (ST_InCCEngine*)data;
    GHashTableIter iter;
    gpointer k,v;
    DBusMessageIter args;
    char *param = "";
    DBusMessage *reply = NULL;
    int value = 1;

    reply = dbus_message_new_method_return(msg);

    /*if (!dbus_message_iter_init(msg, &args))
        fprintf(stderr, "Message has no arguments!\n");
    else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
        fprintf(stderr, "Argument is not string!\n");
    else
        dbus_message_iter_get_basic(&args, &param);
*/
    dbus_message_iter_init(reply, &args);
    dbus_message_iter_init_append(reply, &args);
 
    g_hash_table_iter_init (&iter, p->detect->available);
    while (g_hash_table_iter_next (&iter, &k, &v)) {
        ST_Available *av = (ST_Available*)v;
        char *name = av->sig->name;
        int duration = av->current_time.tv_sec-av->arrive_time.tv_sec;
              
        dbus_message_iter_append_basic(&args,DBUS_TYPE_STRING,&name);
        dbus_message_iter_append_basic(&args,DBUS_TYPE_INT16,&duration);
    }

    if (!dbus_connection_send(conn, reply, NULL)) {
        fprintf(stderr, "Out Of Memory!\n");
        return;
    }
    dbus_connection_flush(conn);
    dbus_message_unref(reply);

    return;
}


/* Properties */
void PRCA_Property_GetState(DBusConnection *conn,DBusMessage *msg, void *data){
    ST_InCCEngine *p = (ST_InCCEngine*)data;
    int status = p->incc_status;
    char *value = incc_states_str[status];  

    __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_STRING,(void*)value);
    return;
}

void PRCA_Property_GetSource(DBusConnection *conn,DBusMessage *msg, void *data){
    ST_InCCEngine *p = (ST_InCCEngine*)data;
    char *value = p->source->str; 

    __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_STRING,(void*)value);
    return;
}

/* Functions for the connection manager */
void PRCA_Property_GetTotalReleaseConnections(DBusConnection *conn,DBusMessage *msg, void *data){
    ST_InCCEngine *p =(ST_InCCEngine*)data;
    dbus_int32_t value = p->conn->releases;

    __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
    return;
}

void PRCA_Property_GetTotalCurrentConnections(DBusConnection *conn,DBusMessage *msg, void *data){
    ST_InCCEngine *p =(ST_InCCEngine*)data;
    dbus_int32_t value = p->conn->current_connections;

    __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);

    return;
}

void PRCA_Property_GetTotalInsertConnections(DBusConnection *conn,DBusMessage *msg, void *data){
    ST_InCCEngine *p =(ST_InCCEngine*)data;
    dbus_int32_t value = p->conn->inserts;

    __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);

    return;
}

void PRCA_Property_GetTotalTimeoutConnections(DBusConnection *conn,DBusMessage *msg, void *data){
    ST_InCCEngine *p =(ST_InCCEngine*)data;
    dbus_int32_t value = p->conn->expiretimers;

    __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);

    return;
}

void PRCA_Property_GetTotalFlowsOnFlowPool(DBusConnection *conn,DBusMessage *msg, void *data){
    ST_InCCEngine *p =(ST_InCCEngine*)data;
    dbus_int32_t value = 0;

    value = FLPO_GetNumberFlows(p->flowpool);
    __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
    return;
}
void PRCA_Property_GetFlowPoolTotalReleases(DBusConnection *conn,DBusMessage *msg, void *data){
    ST_InCCEngine *p =(ST_InCCEngine*)data;
    dbus_int32_t value = 0;

    value = p->flowpool->total_releases;
    __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
    return;
}

void PRCA_Property_GetFlowPoolTotalAcquires(DBusConnection *conn,DBusMessage *msg, void *data){
    ST_InCCEngine *p =(ST_InCCEngine*)data;
    dbus_int32_t value = 0;

    value = p->flowpool->total_acquires;
    __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
    return;
}

void PRCA_Property_GetFlowPoolTotalErrors(DBusConnection *conn,DBusMessage *msg, void *data){
    ST_InCCEngine *p =(ST_InCCEngine*)data;
    dbus_int32_t value = 0;

    value = p->flowpool->total_errors;
    __CMD_GenericPropertyGetter(conn,msg,DBUS_TYPE_INT32,(void*)value);
    return;
}

void PRCA_Method_IncreaseFlowPool(DBusConnection *conn,DBusMessage *msg, void *data){
    ST_InCCEngine *p = (ST_InCCEngine*)data;
    DBusMessageIter args;
    dbus_int32_t param;
    DBusMessage *reply = NULL;
    int value = 1;

    reply = dbus_message_new_method_return(msg);

    if (!dbus_message_iter_init(msg, &args))
        fprintf(stderr, "Message has no arguments!\n");
    else if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&args))
        fprintf(stderr, "Argument is not string!\n");
    else
        dbus_message_iter_get_basic(&args, &param);

    value = FLPO_IncrementFlowPool(p->flowpool,param);

    __CMD_GenericMethodResponse(conn,reply,&args,DBUS_TYPE_BOOLEAN,value);
    return;
}
void PRCA_Method_DecreaseFlowPool(DBusConnection *conn,DBusMessage *msg, void *data){
    ST_InCCEngine *p = (ST_InCCEngine*)data;
    DBusMessageIter args;
    dbus_int32_t param;
    DBusMessage *reply = NULL;
    int value = 1;

    reply = dbus_message_new_method_return(msg);

    if (!dbus_message_iter_init(msg, &args))
        fprintf(stderr, "Message has no arguments!\n");
    else if (DBUS_TYPE_INT32 != dbus_message_iter_get_arg_type(&args))
        fprintf(stderr, "Argument is not string!\n");
    else
        dbus_message_iter_get_basic(&args, &param);

    value = FLPO_DecrementFlowPool(p->flowpool,param);

    __CMD_GenericMethodResponse(conn,reply,&args,DBUS_TYPE_BOOLEAN,value);
    return;
}


