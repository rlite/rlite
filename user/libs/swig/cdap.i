%module cdap
%{
#include "rina/cdap.hpp"
%}

/* https://stackoverflow.com/questions/27693812/how-to-handle-unique-ptrs-with-swig */
%include "std_unique_ptr.i"
wrap_unique_ptr(CDAPMessageUniquePtr, CDAPMessage)

#define __attribute__(x)

/* SWIG does not directly deals with conversion operators.
 * Just rename it to a regular method. */
%rename(toGPB) "operator gpb::CDAPMessage";

%include "rina/cdap.hpp"
