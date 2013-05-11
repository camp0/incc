%module incc

%{
#include "incc.h"
%}

%apply unsigned int { uint32_t }
%apply int { int32_t }
%apply unsigned short { uint16_t }
%apply unsigned long long { uint64_t }
%apply char * { unsigned char*}
%apply unsigned int { time_t }

#define __attribute__(x)
%include "incc.h"
