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

#ifndef _INCCDBUS_H_
#define _INCCDBUS_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <sys/poll.h>
#include "callbacks.h"
#include <sys/types.h>
#include "interfaces.h"

#define INCCLOG_CATEGORY_NAME INCC_BUS
#include "log.h"

#define MAX_WATCHES 4

struct ST_InCCDbusInterface{
	ST_Interface *iface;
	GHashTable *methods;
	GHashTable *properties;
};
typedef struct ST_InCCDbusInterface ST_InCCDbusInterface;

struct ST_InCCDbus{
	DBusWatch *watches[MAX_WATCHES];
	struct pollfd pollfds[MAX_WATCHES];
	int total_watches;
	GHashTable *interfaces;
	GHashTable *private_callbacks;
	GHashTable *properties;
};
typedef struct ST_InCCDbus ST_InCCDbus;

void ICDS_Init(void);
void ICDS_Destroy(void);

void ICDS_AddPublicMethod(ST_Interface *iface,ST_Callback *call);
void ICDS_AddPublicProperty(ST_Interface *iface,ST_Callback *call);

void ICDS_AddPrivateCallback(ST_Callback *call);
DBusConnection *ICDS_Connect(char *interface,void *engine);
int ICDS_GetTotalActiveDescriptors(void);
int ICDS_GetDescriptorByIndex(int i);
DBusWatch *ICDS_GetWatchByIndex(int i);
int ICDS_GetEventsByIndex(int i);
void ICDS_Handler(DBusConnection *conn,short events, DBusWatch *watch);

#endif
