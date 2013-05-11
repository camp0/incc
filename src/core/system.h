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

#ifndef _SYSTEM_H_
#define _SYSTEM_H_

#include <sys/utsname.h>
#include <sys/resource.h>

static struct utsname system_info;
static struct rusage usage_info;

void SYIN_Init(void);
void SYIN_Update(void);

char *SYIN_GetOSName(void);
char *SYIN_GetNodeName(void);
char *SYIN_GetReleaseName(void);
char *SYIN_GetVersionName(void);
char *SYIN_GetMachineName(void);
struct timeval *SYIN_GetUserTimeUsed(void);
struct timeval *SYIN_GetSystemTimeUsed(void);
long SYIN_GetMaximumResidentSetSize(void);
long SYIN_GetIntegralSharedMemorySize(void);
long SYIN_GetIntegralUnsharedDataSize(void);
long SYIN_GetIntegralUnsharedStackSize(void);

#endif
