%module rlite
%{
/* AGGIUNTE */
#include "rina/api.h"
%}

%rename("%(strip:[rina_])s") "";

%include "rina/api.h"
