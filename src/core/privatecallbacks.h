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

#ifndef _PRIVATECALLBACKS_H_
#define _PRIVATECALLBACKS_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "interfaces.h"
#include "callbacks.h"
#include <glib.h>
#include "inccdbus.h"
#include <dbus/dbus.h>

/* Properties functions */
void PRCA_Property_GetState(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetSource(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_StartEngine(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_StopEngine(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_SetSource(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_ShowDetectedSignatures(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_SendMessage(DBusConnection *conn,DBusMessage *msg, void *data);

/* Functions related to the connection manager */
void PRCA_Property_GetTotalReleaseConnections(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetTotalCurrentConnections(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetTotalTimeoutConnections(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetTotalInsertConnections(DBusConnection *conn,DBusMessage *msg, void *data);

void PRCA_Property_GetFlowPoolTotalReleases(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetFlowPoolTotalAcquires(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetFlowPoolTotalErrors(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Property_GetTotalFlowsOnFlowPool(DBusConnection *conn,DBusMessage *msg, void *data);


static ST_Callback ST_StaticEngineMethods[] = {
    { 
        .name   =   "Start",
        .in     =   NULL,
        .out    =   "b",
        .func   =   PRCA_Method_StartEngine 
    },
    { 
        .name   =   "Stop",
        .in =   NULL,
        .out    =   "b",
        .func   =   PRCA_Method_StopEngine 
    },
    {   
        .name   =   "SetSource",
        .in     =   "s",
        .out    =   "b",
        .func   =   PRCA_Method_SetSource
    },
    {
        .name   =   "ShowAvailable",
        .in     =   NULL,
        .out    =   "a(si)",
        .func   =   PRCA_Method_ShowDetectedSignatures 
    },
    {
        .name   =   "SendMessage",
        .in     =   "s",
        .out    =   "b",
        .func   =   PRCA_Method_SendMessage
    },
    {} 
};

static ST_Callback ST_StaticPropertiesCallbacks [] = {
        { 
        .name   =   "State",
        .in =       NULL,
        .out    =   "s",       
        .func   =   PRCA_Property_GetState 
    },
        { 
        .name   =   "Source",
        .in =       "s",
        .out    =   "s",
        .func   =        PRCA_Property_GetSource 
    },
    {
        .name   =   "InsertConnections",
        .in     =   NULL,
        .out    =   "i",
        .func   =   PRCA_Property_GetTotalInsertConnections
    },
    {
        .name   =   "CurrentConnections",
        .in =   NULL,
        .out    =   "i",
        .func   =   PRCA_Property_GetTotalCurrentConnections
    },
    {
        .name   =   "ReleaseConnections",
        .in =   NULL,
        .out    =   "i",
        .func   =   PRCA_Property_GetTotalReleaseConnections
    },
    {
        .name   =   "TimeExpireConnections",
        .in =   NULL,
        .out    =   "i",
        .func   =   PRCA_Property_GetTotalTimeoutConnections
    },
        { 
        .name   =   "FlowsOnPool",
        .in =   NULL,
        .out    =   "i",
        .func   =       PRCA_Property_GetTotalFlowsOnFlowPool 
    },
        { 
        .name   =   "FlowReleases",
        .in =   NULL,
        .out    =   "i",
        .func   =       PRCA_Property_GetFlowPoolTotalReleases 
    },
        { 
        .name   =   "FlowAcquires",
        .in =       NULL,
        .out    =   "i",
        .func   =       PRCA_Property_GetFlowPoolTotalAcquires 
    },
    { 
        .name   =   "FlowErrors",
        .in =   NULL,
        .out    =   "i",
        .func   =       PRCA_Property_GetFlowPoolTotalErrors 
    },
    {}
};

void PRCA_Method_IncreaseFlowPool(DBusConnection *conn,DBusMessage *msg, void *data);
void PRCA_Method_DecreaseFlowPool(DBusConnection *conn,DBusMessage *msg, void *data);

static ST_Callback ST_StaticConnectionMethodCallbacks [] = {
    { 
        .name   =   "IncreaseFlowPool",
        .in     =   "i",
        .out    =   "b",
        .func   =   PRCA_Method_IncreaseFlowPool 
    },
    { 
        .name   =   "DecreaseFlowPool",
        .in     =   "i",
        .out    =   "b",
        .func   =   PRCA_Method_DecreaseFlowPool 
    },
    {}
};

static ST_Interface ST_PublicInterfaces [] = {
    { 
        .name           =   INCC_INTERFACE,
        .methods        =   ST_StaticEngineMethods,
        .signals        =   NULL,
        .properties     =   ST_StaticPropertiesCallbacks    
    },
    {}
};


#endif
