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
#include <stdio.h>
#include <signal.h>
#include "incc.h"
#include <getopt.h>

static struct option long_options[] = {
        {"learning",    no_argument,        0, 'l'},
        {"interface",   required_argument,  0, 'i'},
        {"stats",   no_argument,        0, 'S'},
        {"exit",    no_argument,        0, 'e'},
        {"help",        no_argument,        0, 'h'},
        {"version",     no_argument,        0, 'V'},
        {0, 0, 0, 0}
};

static char *short_options = "li:p:hVfuces:S";

static char *show_options = {
    "The options are:\n"
    "\t-i, --interface=<device>             Device or pcapfile.\n"
    "\t-e, --exit                           Exits when analisys is done(for pcapfiles).\n"
    "\t-S, --stats                          Show statistics.\n"
    "\n"
    "\t-h, --help                           Display this information.\n"
    "\t-V, --version                        Display this program's version number.\n"
    "\n"
};

/* options of the daemon */
int show_statistics = FALSE;
int learning = FALSE;
int use_cache = FALSE;
int exit_on_pcap = FALSE;

void sigquit(int signal) {

    INCC_Stop();
    if(show_statistics == TRUE) {
        INCC_Stats();
    }
    INCC_StopAndExit();
    return;
}

void usage(char *prog){
    fprintf(stdout,"%s %s\n",INCC_ENGINE_NAME,VERSION);
    fprintf(stdout,"Usage: %s [option(s)]\n",prog);
    fprintf(stdout,"%s",show_options);
    fprintf(stdout,"%s",bugs_banner);
    return;
}



void main(int argc, char **argv) {
    int i,c,option_index;
    char *source = NULL;
    char *value;

    while((c = getopt_long(argc,argv,short_options,
        long_options, &option_index)) != -1) {
        switch (c) {
            case 'i':
                    source = optarg;
                    break;
            case 'p':
                    hport = atoi(optarg);
                    break;
            case 's':
                    sport = atoi(optarg);
                    break;
            case 'c':
                    use_cache = TRUE;   
                    break;
            case 'e':
                    exit_on_pcap = TRUE;    
                    break;
            case 'u':
                    show_unknown = TRUE;
                    break;
            case 'S':
                    show_statistics = TRUE;
                    break;
            case 'l':
                    learning = TRUE;
                    break;
            case 'f':
                    force_post = TRUE;
                    break;
            case 'h':
                usage(argv[0]);
                exit(0);
            case 'V':
                fprintf(stdout,"%s %s\n",INCC_ENGINE_NAME,VERSION);
                fprintf(stdout,"%s",version_banner);
                default:
                usage(argv[0]);
                exit(-1);
        }
    }

    if(source == NULL) {
        usage(argv[0]);
        exit(0);
    }

    INCC_Init();

    signal(SIGINT,sigquit);

    INCC_SetSource(source);

    INCC_AddSignature(1,"sig1","CA","epep",NULL);
    INCC_AddSignature(2,"sig2","^epep","epep",NULL);
//  INCC_AddSignature(4,"\\x01\\x10\\x00\\x01","bu",NULL);
//  INCC_AddSignature(4,"\x01\x10\x00\x01","bu",NULL);
//  INCC_AddSignature(4,"^{2}.\x01\x10\x00\x01","bu",NULL);

    INCC_SetExitOnPcap(exit_on_pcap);

    INCC_Start();

    INCC_Run();

    if(show_statistics == TRUE) {
            INCC_Stats();
    }
    INCC_StopAndExit();
    return;
}
