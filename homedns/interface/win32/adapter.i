%module adapter

%{
/* Includes the header in the wrapper code */
#include "adapter.h"
%}

/* Parse the header file to generate wrappers */
%include <windows.i>
%include <std_string.i>
%include <std_wstring.i>
%include <std_vector.i>

%include "adapter.h"

namespace std {
   %template(IntVector) vector<int>;
   %template(DoubleVector) vector<double>;
   %template(StringVector) vector<string>;
}
%template(InterfaceVector) std::vector<PADAPTER_INFO>;
