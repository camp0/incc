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

#include "system.h"

void SYIN_Init(){
	uname(&system_info);
}
void SYIN_Update() {
	getrusage(RUSAGE_SELF,&usage_info);
}

char *SYIN_GetOSName(void) { return system_info.sysname;}
char *SYIN_GetNodeName(void) { return system_info.nodename;}
char *SYIN_GetReleaseName(void) { return system_info.release;}
char *SYIN_GetVersionName(void) { return system_info.version;}
char *SYIN_GetMachineName(void) { return system_info.machine;}

struct timeval *SYIN_GetUserTimeUsed() { return &usage_info.ru_utime;}
struct timeval *SYIN_GetSystemTimeUsed() { return &usage_info.ru_stime;}
long SYIN_GetMaximumResidentSetSize() { return usage_info.ru_maxrss;}
long SYIN_GetIntegralSharedMemorySize() { return usage_info.ru_ixrss;}
long SYIN_GetIntegralUnsharedDataSize() { return usage_info.ru_idrss; }
long SYIN_GetIntegralUnsharedStackSize() { return usage_info.ru_isrss; }

