%module rina
%{
/* additions */
#include "rina/api.h"
%}

%include "stdint.i"

%rename("%(strip:[rina_])s") "";

%include "rina/api.h"
