#include <string>
using namespace std;


/* Simple class for next hop representation. Object of this class corresponds
 * to SCION Packet and is processed within routing context.
 *  :ivar addr: the next hop address.
 *  :vartype addr: str
 *  :ivar port: the next hop port number.
 *  :vartype port: int
 */
class NextHop {
    string addr;
    int port;
};
