%module rlite
%{
/* AGGIUNTE */
#include "rlite/rlite.h"
#include "rlite/common.h"
#include "rlite/utils.h"
%}

/* This removes the __attribute__((packed)) when SWIG parses
 * the header files. This define is never passed to the C
 * compiler, it's only seen by SWIG for the purpose of
 * generating its code.
 */
#define __attribute__(x)

%include "rlite/common.h"
%include "rlite/rlite.h"
%include "rlite/utils.h"
