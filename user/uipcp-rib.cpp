#include <vector>
#include <map>
#include <iostream>

#include "uipcp-rib.h"

using namespace std;


static void f(int x)
{
    vector<int> v;

    v.push_back(x);

    cout << "CXX_F CALLED" << endl;
}

extern "C" void cxx_f(int x)
{
    f(x);
}
