%module rlite_cdap
%{
#include "rlite/cdap.hpp"
%}

#define __attribute__(x)

/* SWIG does not directly deals with conversion operators.
 * Just rename it to a regular method. */
%rename(toGPB) "operator gpb::CDAPMessage";

%include "rlite/cdap.hpp"
