#include "IPAddress.h"
#include <bitset>
#include <string>
using namespace std;

int main() {
    string s;
    cin >> s;
    IPAddress *ip = new IPv6Address(s);

    // int arr[8] = {0};
    // for(int i = 0; i < 8; i++)
    	// cout << arr[i] << endl;
    return 0;
}
