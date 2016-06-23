import os
from distutils.core import setup, Extension

temp_includes = os.popen("pkg-config --cflags dbus-1 glib-2.0").read().replace("-I","").split()
temp_includes.append("../src/utils")
temp_includes.append("../src/bus")
temp_includes.append("../src/core")
temp_includes.append("../../.")
temp_includes.append("../.")

source_files = ['incc_test_wrap.c', '../src/core/flowpool.c','../src/core/connection.c','../src/core/signature.c']
source_files = source_files + ['../src/core/payload.c','../src/core/protocol.c','../src/core/packet.c']
source_files = source_files + ['../src/core/incc.c','../src/core/privatecallbacks.c']
source_files = source_files + ['../src/core/detection.c','../src/core/packetdecoder.c']
source_files = source_files + ['../src/core/system.c']
source_files = source_files + ['../src/bus/inccdbus.c']

#source_files = source_files + ['privatecallbacks.c','packetdecoder.c','system.c','detection.c']
#source_files = source_files + ['../bus/inccdbus.c','payload.c','packet.c']

incc_test_module = Extension('_incc_test',
	sources = source_files,
	include_dirs = temp_includes,
	libraries = ['glib-2.0','pcap','dbus-1','log4c','ssl'],
	define_macros=[('HAVE_LIBDBUS_1','1'),('HAVE_CONFIG','1'),('DEBUG','1')],
	#define_macros=[('HAVE_LIBDBUS_1','1'),('HAVE_CONFIG','1'),('DEBUG','1'),('HAVE_LIBLOG4C','1')],
	)

setup (name = 'incc_test',
       version = '0.1',
       author      = "Luis Campo Giralte",
       description = """Simple wrapper for the InCC engine""",
       ext_modules = [incc_test_module],
       py_modules = ["incc_test"],
       )

