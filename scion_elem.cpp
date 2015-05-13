/* Copyright 2014 ETH Zurich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * :mod:`scion_elem` --- Base class for SCION servers
 *  ==================================================
 *
 * Module docstring here.
 *
 * .. note::
 * Fill in the docstring.
 */

#include <map>

#define SCION_UDP_PORT 30040
#define SCION_UDP_EH_DATA_PORT 30041
#define BUFLEN 8092


class SCIONElement {
    /*
     * Base class for the different kind of servers the SCION infrastructure
     * provides.
     *
     * :ivar topology: the topology of the AD as seen by the server.
     * :vartype topology: :class:`Topology`
     * :ivar config: the configuration of the AD in which the server is located.
     * :vartype config: :class:`lib.config.Config`
     * :ivar ifid2addr: a dictionary mapping interface identifiers to the
     *     corresponding border router addresses in the server's AD.
     * :vartype ifid2addr: dict
     * :ivar addr: a `SCIONAddr` object representing the server address.
     * :vartype addr: :class:`lib.packet.scion_addr.SCIONAddr`
     */
    type _addr;
    type topology;
    type config;
    map<type, type> ifid2addr;
    type addr;
    type _local_socket;
    type _sockets;

public:
    SCIONElement(type host_addr, type topo_file, type config_file = NULL) {
        /*
         * Create a new ServerBase instance.
         * :param host_addr: the (local) address of the server.
         * :type host_addr: :class:`ipaddress._BaseAddress`
         * :param topo_file: the name of the topology file.
         * :type topo_file: str
         * :param config_file: the name of the configuration file.
         * :type config_file: str
         *
         * :returns: the newly-created ServerBase instance
         * :rtype: ServerBase
         */
        _addr = "";
        topology = NULL;
        config = NULL;
        // ifid2addr = {}

        parse_topology(topo_file);
        addr = SCIONAddr.from_values(topology.isd_id,
                topology.ad_id, host_addr);
        if (config_file)
            parse_config(config_file);
        construct_ifid2addr_map();
        _local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
        _local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
        _local_socket.bind((str(self.addr.host_addr), SCION_UDP_PORT));
        _sockets = [self._local_socket];
        // logging.info("Bound %s:%u", self.addr.host_addr, SCION_UDP_PORT)
    }

    type get_addr() {
        /* The address of the server as a :class:`lib.packet.scion_addr.SCIONAddr`
         * object.
        */
        return _addr;
    }

    void set_addr(type addr){
        /* Set the address of the server.
         * :param addr: the new server address.
         * :type addr: :class:`lib.packet.scion_addr.SCIONAddr`
         */
        // should assert(addr != NULL)??
        _addr = addr;
    }

    void parse_topology(string topo_file) {
        /* Instantiate a Topology object given 'topo_file'.
         * 
         * :param topo_file: the topology file name.
         * :type topo_file: string
         */
        topology = Topology(topo_file);
    }

    void parse_config(string config_file) {
        /* Instantiate a Config object given 'config_file'.
         * 
         * :param config_file: the configuration file name.
         * :type config_file: str
         */
        config = Config(config_file);
    }

    void construct_ifid2addr_map() {
        /* Construct the mapping between the local interface IDs and the address
         * of the neighbors connected to those interfaces.
         */
        assert(topology != NULL);
        for edge_router in self.topology.get_all_edge_routers():
            self.ifid2addr[edge_router.interface.if_id] = edge_router.addr
    }

    void handle_request(type packet, type sender, bool from_local_socket=true) {
        /* Main routine to handle incoming SCION packets. Subclasses have to
         * override this to provide their functionality.
         */
    }

    type get_first_hop(type spkt) {
        /* Returns first hop addr of down-path or end-host addr.
         */
        opaque_field = spkt.hdr.path.get_first_hop_of();
        if opaque_field is None:  # EmptyPath
            return (spkt.hdr.dst_addr.host_addr, SCION_UDP_PORT)
        else:
            if spkt.hdr.is_on_up_path():
                return (self.ifid2addr[opaque_field.ingress_if], SCION_UDP_PORT)
            else:
                return (self.ifid2addr[opaque_field.egress_if], SCION_UDP_PORT)
    }

    void send(type packet, string dst, int dst_port=SCION_UDP_PORT){
        /* Send *packet* to *dst* (to port *dst_port*) using the local socket.
         * Calling ``packet.pack()`` should return :class:`bytes`, and
         * ``dst.__str__()`` should return a string representing an IPv4 address.
         *
         * :param packet: the packet to be sent to the destination.
         * :type packet:
         * :param dst: the destination IPv4 address.
         * :type dst: str
         * :param dst_port: the destination port number.
         * :type dst_port: int
         */
        _local_socket.sendto(packet.pack(), (str(dst), dst_port));
    } 

    void run() {
        /* Main routine to receive packets and pass them to
         * :func:`handle_request()`.
         */
        while (true) {
            recvlist, _, _ = select.select(self._sockets, [], [])
            for sock in recvlist:
                packet, addr = sock.recvfrom(BUFLEN)
                self.handle_request(packet, addr, sock == self._local_socket)
        }
    }

    void clean() {
        /* Close open sockets. 
         */
        for s in self._sockets:
            s.close()
    }

};
