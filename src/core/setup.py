import os
from distutils.core import setup, Extension

temp_includes = os.popen("pkg-config --cflags dbus-1 glib-2.0 libssl").read().replace("-I","").split()
temp_includes.append("../utils")
temp_includes.append("../bus")
temp_includes.append("../../.")

source_files = ['incc_wrap.c', 'incc.c','flowpool.c','connection.c','signature.c','protocol.c']
source_files = source_files + ['privatecallbacks.c','packetdecoder.c','system.c','detection.c']
source_files = source_files + ['../bus/inccdbus.c','payload.c','packet.c']

incc_module = Extension('_incc',
	sources = source_files,
	include_dirs = temp_includes,
#	library_dirs = [ '../opcodes/.libs'],
	libraries = ['glib-2.0','pcap','dbus-1','log4c','ssl'],
	define_macros=[('HAVE_LIBDBUS_1','1'),('HAVE_CONFIG','1'),('HAVE_LIBLOG4C','1'),('DEBUG','1')],
	#define_macros=[('HAVE_LIBDBUS_1','1'),('PACKAGE','\"test\"'),('PCRE_HAVE_JIT','0'),('__LINUX__','1'),('PACKAGE_BUGREPORT','test')],
	#define_macros=[('HAVE_LIBDBUS_1','1'),('DEBUG0','1')],
	#define_macros=[('HAVE_LIBDBUS_1','1'),('DEBUG0','1'),('DEBUG1','1')],
#        define_macros=[('DEBUG', '1')],
	)

setup (name = 'incc',
       version = '0.1',
       author      = "Luis Campo Giralte",
       description = """Simple wrapper for the InCC engine""",
       ext_modules = [incc_module],
       py_modules = ["incc"],
       )

