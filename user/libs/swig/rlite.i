%module rlite
%{
/* AGGIUNTE */
#include "rlite/api.h"
%}

%rename("%(strip:[rina_])s") "";

%include "rlite/api.h"
