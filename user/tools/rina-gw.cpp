#include <iostream>
#include <map>
#include <fstream>
#include <sstream>

#include "rlite/common.h"

using namespace std;


int main()
{
    const char *confname = "rina-gw.conf";
    ifstream fin(confname);

    if (fin.fail()) {
        PE("Failed to open configuration file '%s'\n", confname);
        return -1;
    }

    while (!fin.eof()) {
        string line;
        string token;

        getline(fin, line);

        istringstream iss(line);

        while (iss >> token) {
            cout << token << " ";
        }
    }

    return 0;
}
