%module rlite
%{
/* AGGIUNTE */
#include "rlite/api.h"
%}

%rename("%(strip:[rl_])s") "";

%include "rlite/api.h"
