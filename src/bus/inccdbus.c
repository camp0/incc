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

#include "inccdbus.h"
#include "callbacks.h"

static ST_InCCDbus inccbus;

/**
 * ICDS_Init- Initalize the dbus wrapper library. 
 *
 */
void ICDS_Init(){
	inccbus.total_watches = 0;
	inccbus.private_callbacks = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);
	inccbus.interfaces = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);

	// The properties are reference on two hashes, the first one is for improve the 
	// efficiency of the system and the second is for ipython trait_names.
	inccbus.properties = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);
	return;
}

ST_InCCDbusInterface *ICDS_GetInterface(ST_Interface *iface) {
        ST_InCCDbusInterface *i = NULL;

        i = (ST_InCCDbusInterface*)g_hash_table_lookup(inccbus.interfaces,iface->name);
        if(i == NULL) {
                i = g_new(ST_InCCDbusInterface,1);
                i->methods = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);
                i->iface = iface;
//                i->signals = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);
                i->properties = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);
                g_hash_table_insert(inccbus.interfaces,g_strdup(iface->name),i);
        }
	return i;
}

void ICDS_AddPublicProperty(ST_Interface *iface,ST_Callback *call){
        ST_InCCDbusInterface *ipoly = ICDS_GetInterface(iface);

	// the property is added to two hashs
        g_hash_table_insert(ipoly->properties,g_strdup(call->name),call);
        g_hash_table_insert(inccbus.properties,g_strdup(call->name),call);
	return;
}

void ICDS_AddPublicMethod(ST_Interface *iface, ST_Callback *call){
        ST_InCCDbusInterface *ipoly = ICDS_GetInterface(iface);

	g_hash_table_insert(ipoly->methods,g_strdup(call->name),call);
	return;
}

void ICDS_AddPrivateCallback(ST_Callback *call){
	g_hash_table_insert(inccbus.private_callbacks,g_strdup(call->name),call);
	return;
}

void ICDS_Destroy() {
        GHashTableIter iter;
        gpointer k,v;

        g_hash_table_iter_init (&iter, inccbus.interfaces);
        while (g_hash_table_iter_next (&iter, &k, &v)) {
                ST_InCCDbusInterface *iface = (ST_InCCDbusInterface*)v;
                g_hash_table_destroy(iface->methods);
        }
	
	g_hash_table_destroy(inccbus.properties);
	g_hash_table_destroy(inccbus.interfaces);
	g_hash_table_destroy(inccbus.private_callbacks);
	return;
}

int ICDS_GetTotalActiveDescriptors() {
	return inccbus.total_watches;
}

int ICDS_GetDescriptorByIndex(int i){
	return inccbus.pollfds[i].fd;
}

DBusWatch *ICDS_GetWatchByIndex(int i) {
	return inccbus.watches[i];
}

int ICDS_GetEventsByIndex(int i){
	return inccbus.pollfds[i].events;
}

void ICDS_ExecuteCallback(GHashTable *h, DBusConnection *c,DBusMessage *msg,char *key, void *data) {
        ST_Callback *callback = NULL;
        const char *destination = dbus_message_get_destination(msg);
        const char *interface = dbus_message_get_interface(msg);
        const char *member = dbus_message_get_member(msg);
        //const char VARIABLE_IS_NOT_USED *path = dbus_message_get_path(msg);

        callback = (ST_Callback*)g_hash_table_lookup(h,(gchar*)key);
        if(callback != NULL) {
                callback->func(c,msg,data);
        }else{
		DBusMessage *reply = NULL;
		char error_str[128];

		snprintf(error_str,128,"Method '%s' not found",key);
		reply = dbus_message_new_error(msg, INCC_BUS ".Error", error_str);

		dbus_connection_send(c, reply, NULL);
        	dbus_connection_flush(c);
		dbus_message_unref(reply);

		LOG(INCCLOG_PRIORITY_INFO,	
                	"Method not found '%s'\n",key);
        }
	return;
}

DBusHandlerResult DB_FilterDbusFunctionMessage(DBusConnection *c, DBusMessage *msg, void *data){
	register int i;
        const char *destination = dbus_message_get_destination(msg);
        const char *interface = dbus_message_get_interface(msg);
        const char *member = dbus_message_get_member(msg);
        const char *path = dbus_message_get_path(msg);
	ST_InCCDbusInterface *iface = NULL; 
	char *real_interface;

	if(interface == NULL){ // ipython generates no interface.
		real_interface = path;
	}else{
		real_interface = interface;
	}	
#ifdef DEBUG
	LOG(INCCLOG_PRIORITY_DEBUG,
		"i(%s)d(%d)p(%s)m(%s)ri(%s)",interface,destination,path,member,real_interface);
#endif

        if (dbus_message_is_method_call (msg, "org.freedesktop.DBus.Introspectable", "Introspect")) {
		ICDS_Method_Instrospect(c,msg,data);
                return DBUS_HANDLER_RESULT_HANDLED;
        }

        if (dbus_message_is_method_call (msg,"org.freedesktop.DBus.Properties","Get")){
                char *property_interface = "";
                char *property = "";
                DBusError err;

                dbus_error_init(&err);
                dbus_message_get_args(msg,&err,DBUS_TYPE_STRING,&property_interface,DBUS_TYPE_STRING,&property);
		iface = (ST_InCCDbusInterface*)g_hash_table_lookup(inccbus.interfaces,property_interface);
		if (iface == NULL){
			LOG(INCCLOG_PRIORITY_INFO,
                		"No interface %s available for property %s",property_interface,property);
			return DBUS_HANDLER_RESULT_HANDLED;
		}
		// The properties should only visible on their interface, not globaly
		LOG(INCCLOG_PRIORITY_INFO,
               		"Get property '%s' from interface '%s'",property,property_interface);
                ICDS_ExecuteCallback(iface->properties,c,msg,property,data);
                return DBUS_HANDLER_RESULT_HANDLED;
        }

        if (dbus_message_is_method_call (msg,"org.freedesktop.DBus.Properties","GetAll")) {
                char *property_interface = "";
                DBusError err;

                dbus_error_init(&err);
                dbus_message_get_args(msg,&err,DBUS_TYPE_STRING,&property_interface);
                iface = (ST_InCCDbusInterface*)g_hash_table_lookup(inccbus.interfaces,property_interface);
                if (iface == NULL){
			LOG(INCCLOG_PRIORITY_INFO,
                        	"GetAll interface '%s' not available",property_interface);
                        return DBUS_HANDLER_RESULT_HANDLED;
                }
		LOG(INCCLOG_PRIORITY_INFO,
                       	"GetAll properties from interface '%s'",property_interface);
		ICDS_ShowAllPropertiesOfInterface(iface,c,msg);
                return DBUS_HANDLER_RESULT_HANDLED;
        }

	// Should exist almost one interface
	iface = (ST_InCCDbusInterface*)g_hash_table_lookup(inccbus.interfaces,real_interface);
	if (iface == NULL){
		return DBUS_HANDLER_RESULT_HANDLED;
	}
        if (dbus_message_is_method_call (msg, real_interface, "trait_names")) { // method used by ipython 
		ICDS_ShowPublicMethodsOfInterface(c,msg,real_interface);
                return DBUS_HANDLER_RESULT_HANDLED;
        }
        if (dbus_message_is_method_call (msg, real_interface, "_getAttributeNames")) { // method used by ipython
		ICDS_ShowPublicMethodsOfInterface(c,msg,real_interface);
                return DBUS_HANDLER_RESULT_HANDLED;
        }
        if (dbus_message_is_method_call (msg, real_interface, "GetProperties")) { // method used by ipython
		ICDS_ShowAllPropertiesOfInterface(iface,c,msg);
                return DBUS_HANDLER_RESULT_HANDLED;
        }
        if (dbus_message_is_method_call (msg, real_interface, "GetProperty")) { // method used by ipython
                char *property = "";
                DBusError err;

                dbus_error_init(&err);
                dbus_message_get_args(msg,&err,DBUS_TYPE_STRING,&property);
		LOG(INCCLOG_PRIORITY_INFO,
                        "Get property '%s' from interface '%s'",property,real_interface);
                ICDS_ExecuteCallback(iface->properties,c,msg,property,data);
                return DBUS_HANDLER_RESULT_HANDLED;
        }
	
	LOG(INCCLOG_PRIORITY_INFO,
               	"Executing method '%s' from interface '%s'",member,real_interface);
	ICDS_ExecuteCallback(iface->methods,c,msg,member,data);	
	return DBUS_HANDLER_RESULT_HANDLED;
}

void ICDS_Handler(DBusConnection *conn,short events, DBusWatch *watch)
{
        unsigned int flags = 0;

        if (events & POLLIN)
                flags |= DBUS_WATCH_READABLE;
        if (events & POLLOUT)
                flags |= DBUS_WATCH_WRITABLE;
        if (events & POLLHUP)
                flags |= DBUS_WATCH_HANGUP;
        if (events & POLLERR)
                flags |= DBUS_WATCH_ERROR;

        while (!dbus_watch_handle(watch, flags)) {
                printf("dbus_watch_handle needs more memory/n");
                sleep(1);
        }

        dbus_connection_ref(conn);
        while (dbus_connection_dispatch(conn) == DBUS_DISPATCH_DATA_REMAINS);
        dbus_connection_unref(conn);
}


static dbus_bool_t _addWatchFunction(DBusWatch *watch, void *data){
        short cond = POLLHUP | POLLERR;
        int fd;
        unsigned int flags;

        //printf(" add watch %p on slot %d\n", (void*)watch,total_watches);
        fd = dbus_watch_get_fd(watch);
        flags = dbus_watch_get_flags(watch);

        if (flags & DBUS_WATCH_READABLE)
                cond |= POLLIN;
        if (flags & DBUS_WATCH_WRITABLE)
                cond |= POLLOUT;

        inccbus.pollfds[inccbus.total_watches].fd = fd;
        inccbus.pollfds[inccbus.total_watches].events = cond;
        inccbus.pollfds[inccbus.total_watches].revents = 0;
        inccbus.watches[inccbus.total_watches] = watch;
        inccbus.total_watches ++;
        return 1;
}

static void _removeWatchFunction(DBusWatch *watch, void *data){
       	register int i;
 
	//DEBUG0("remove dbus watch %p\n", (void*)watch);
        for (i = 0; i < inccbus.total_watches; i++) {
                if (inccbus.watches[i] == watch) {
			memset(&inccbus.pollfds[i],0,sizeof(inccbus.pollfds[i]));
			inccbus.watches[i] = NULL;
			inccbus.total_watches --;	
                        return;
                }
        }
	return;
}

DBusConnection *ICDS_Connect(char *interface,void *engine) {
	DBusConnection *bus;
        DBusError err;
        int ret;
        char* sigvalue;

        dbus_error_init(&err);
        bus = dbus_bus_get(DBUS_BUS_SESSION, &err);
        if (dbus_error_is_set(&err)) {
                fprintf(stderr, "Connection Error (%s)\n", err.message);
                dbus_error_free(&err);
        }
        if (NULL == bus) {
                fprintf(stderr, "Connection to dbus failed\n");
                return NULL;
        }

        ret = dbus_bus_request_name(bus,interface, DBUS_NAME_FLAG_REPLACE_EXISTING , &err);
        if (dbus_error_is_set(&err)) {
                fprintf(stderr, "Name Error (%s)\n", err.message);
                dbus_error_free(&err);
        }
        if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret) {
                fprintf(stderr, "Not Primary Owner (%d)\n", ret);
                return NULL;
        }

        if (!dbus_connection_set_watch_functions(bus, _addWatchFunction,
                     _removeWatchFunction, NULL, NULL, NULL)) {
                fprintf(stderr,"dbus_connection_set_watch_functions failed\n");
                return NULL;
        }

        if (!dbus_connection_add_filter(bus, DB_FilterDbusFunctionMessage, engine, NULL))
        {
                printf("Failed to register signal handler callback/n");
                return NULL;
        }

        dbus_bus_add_match(bus, "type='signal'", NULL);
        dbus_bus_add_match(bus, "type='method_call'", NULL);

	//DEBUG0("registered %s \n", interface);

        return bus;
}

void ICDS_ShowAllPropertiesOfInterface(ST_InCCDbusInterface *ipoly,DBusConnection *conn, DBusMessage *msg) {
        DBusMessageIter args;
        DBusMessage *reply = NULL;
	GHashTableIter iter;
	gpointer v,k;

        reply = dbus_message_new_method_return(msg);

        dbus_message_iter_init(reply, &args);
        dbus_message_iter_init_append(reply, &args);

        g_hash_table_iter_init (&iter, ipoly->properties);
        while (g_hash_table_iter_next (&iter, &k, &v)) {
		const char *value = k;
                if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &value)) {
                	fprintf(stderr, "Out Of Memory!\n");
                        return;
                }
	}
	if (!dbus_connection_send(conn, reply, NULL)) {
		fprintf(stderr, "Out Of Memory!\n");
		return;
	}
	dbus_connection_flush(conn);
	dbus_message_unref(reply);

	return;
}

void ICDS_ShowPublicMethodsOfInterface(DBusConnection *conn,DBusMessage *msg, char *interface){
        GHashTableIter iter;
        gpointer k,v;
        DBusMessageIter args;
        DBusMessage *reply = NULL;
        int i = 0;
        ST_InCCDbusInterface *ipoly = NULL;

        ipoly = (ST_InCCDbusInterface*)g_hash_table_lookup(inccbus.interfaces,interface);
        if(ipoly != NULL) {
        	reply = dbus_message_new_method_return(msg);

        	dbus_message_iter_init(reply, &args);
        	dbus_message_iter_init_append(reply, &args);

        	g_hash_table_iter_init (&iter, ipoly->methods);
        	while (g_hash_table_iter_next (&iter, &k, &v)) {
			const char *value = k;
                	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &value)) {
                        	fprintf(stderr, "Out Of Memory!\n");
                        	return;
                	}
		}
        	g_hash_table_iter_init (&iter, ipoly->properties);
        	while (g_hash_table_iter_next (&iter, &k, &v)) {
			const char *value = k;
                	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &value)) {
                        	fprintf(stderr, "Out Of Memory!\n");
				return;
			}
		}
        	if (!dbus_connection_send(conn, reply, NULL)) {
                	fprintf(stderr, "Out Of Memory!\n");
                	return;
        	}
        	dbus_connection_flush(conn);
        	dbus_message_unref(reply);
	}
        return;
}

static const char *instrospect_header = "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
        "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
        "<node>\n"
        "<interface name=\"org.freedesktop.DBus.Introspectable\">\n"
        "  <method name=\"Introspect\">\n"
        "    <arg name=\"xml_data\" direction=\"out\" type=\"s\"/>\n"
        "  </method>\n"
        "</interface>\n"
        "<interface name=\"org.freedesktop.DBus.Properties\">\n"
        "  <method name=\"Get\">\n"
        "    <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
        "    <arg name=\"propname\" direction=\"in\" type=\"s\"/>\n"
        "    <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"
        "  </method>\n"
        "  <method name=\"Set\">\n"
        "    <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
        "    <arg name=\"propname\" direction=\"in\" type=\"s\"/>\n"
        "    <arg name=\"value\" direction=\"in\" type=\"v\"/>\n  </method>\n"
        "  <method name=\"GetAll\">\n"
        "    <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
        "    <arg name=\"props\" direction=\"out\" type=\"a{sv}\"/>\n"
        "  </method>\n"
        "</interface>\n"
;

void ICDS_Method_Instrospect(DBusConnection *conn,DBusMessage *msg, void *data) {
        DBusMessageIter iter;
        DBusMessage *reply = NULL;
        ST_Callback *current = NULL;
        ST_Interface *interfaces = NULL;
	GList *item = g_hash_table_get_values(inccbus.interfaces);
        GString* xml_data;
        int i,j,offset;

        reply = dbus_message_new_method_return(msg);

        dbus_message_iter_init_append (reply, &iter);

        /* xml header instropection format */
        xml_data = g_string_new (instrospect_header);
        /* Now for every interface we publish their methods, signals and properties */
	
	while(item!= NULL) {
		interfaces = ((ST_InCCDbusInterface *)item->data)->iface;	

                /* Now the methods supported by the interface of the agent */
                g_string_append_printf (xml_data," \n<interface name=\"%s\">\n  ",interfaces->name);

                current = &interfaces->methods[0];
		j = 0;
		while((current!=NULL)&&(current->name != NULL)) {
                        g_string_append_printf(xml_data,"<method name=\"%s\">\n",current->name);

                        /* adding the format parameters */
                        if(current->in != NULL) {
                                g_string_append_printf(xml_data,"    <arg name=\"%s\" type=\"%s\" direction=\"in\"/>\n",
                                        current->in,current->in);
                        }
                        if(current->out != NULL) {
                                g_string_append_printf(xml_data,"    <arg name=\"result\" type=\"%s\" direction=\"out\"/>\n",
                                       current->out);
                        }

                        g_string_append(xml_data,"  </method>\n");
			j++;
                	current = &interfaces->methods[j];
                }

                /* now check for signals */
                /* TODO not implemented jet */
		current = &interfaces->signals[0];
		
                /* now check for properties */
                current = &interfaces->properties[0];
		j = 0;
		while((current!=NULL)&&(current->name != NULL)) {
                        char *access = "read";
                        char *type = "";
                        g_string_append_printf(xml_data,"  <property name=\"%s\" ",
                               current->name);
                        if(current->in == NULL)
                                access = "read";
                        else
                                access = "readwrite";
                        type = current->out;
                        g_string_append_printf(xml_data,"type=\"%s\" access=\"%s\"/>\n",type,access);
			j++;
                	current = &interfaces->properties[j];
                }

                g_string_append(xml_data,"</interface>\n");
		item = g_list_next(item);
        }
        g_string_append(xml_data, "</node>\n");
//      printf("%s",xml_data->str);
        dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &xml_data->str);
        g_string_free (xml_data, TRUE);

        if (!dbus_connection_send(conn, reply, NULL)) {
                fprintf(stderr, "Out Of Memory!\n");
                return;
        }
        dbus_connection_flush(conn);
        dbus_message_unref(reply);
        return;
}

