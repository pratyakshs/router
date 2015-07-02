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
#ifndef SCION_ELEM_CPP
#define SCION_ELEM_CPP

#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "IPAddress.h"
#include "lib/topology.cpp"
#include "lib/config.cpp"
#include "lib/packet/scion_addr.cpp"
#include "lib/packet/opaque_field.cpp"
#include "lib/packet/scion.cpp"

#define SCION_UDP_PORT 30040
#define SCION_UDP_EH_DATA_PORT 30041
#define BUFLEN 8092


class SCIONElement {
    /**
     * Base class for the different kind of servers the SCION infrastructure
     * provides.
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
public:
    Topology topology;
    Config config;
    std::map<int, IPAddress> ifid2addr;
    SCIONAddr addr;
    std::string id;
    int local_socket;
    std::vector<int> sockets;

    SCIONElement(const std::string &server_type, const std::string &topo_file, 
                 const std::string &config_file, const std::string &server_id) {
        /**
         * Create a new ServerBase instance.
         * :param server_type: a shorthand of the server type, e.g. "bs" for a
         *                     beacon server.
         * :type server_type: str
         * :param topo_file: the name of the topology file.
         * :type topo_file: str
         * :param config_file: the name of the configuration file.
         * :type config_file: str
         * :param server_id: the local id of the server, e.g. for bs1-10-3, the 
         *                   id would be '3'. Used to look up config from 
         *                   topology file.
         * :type server_id: str
         * :param host_addr: the interface to bind to. Only used if server_id 
         *                   isn't specified.
         * :type host_addr: :class:`ipaddress._BaseAddress`
         * :returns: the newly-created ServerBase instance
         * :rtype: ServerBase
         */
        IPAddress host_addr;
        parse_topology(topo_file);
        if (server_id.length()) {
            ServerElement own_config = topology.get_own_config(server_type, server_id);
            id = server_type + std::to_string(topology.isd_id) + "-" 
                     + std::to_string(topology.ad_id) + "-" + own_config.name;
            host_addr = *(own_config.addr);
        }
        else{
            id = server_type;
        }
        addr = SCIONAddr(topology.isd_id, topology.ad_id, &host_addr);
        

        if (config_file.length())
            parse_config(config_file);
        construct_ifid2addr_map();
        local_socket = socket(AF_INET, SOCK_DGRAM, 0);
        int val = 1;
        setsockopt(local_socket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        inet_pton(AF_INET, addr.host_addr->to_string().c_str(), 
                    &serv_addr.sin_addr.s_addr);
        serv_addr.sin_port = htons(SCION_UDP_PORT);
        if (bind(local_socket, (struct sockaddr *) &serv_addr, 
            sizeof(serv_addr)) < 0) {
            // log error on binding            
        }
        sockets.push_back(local_socket);
        LOG(INFO) << server_id << ": bound " << addr.host_addr->to_string() 
                  << ":" << SCION_UDP_PORT;
    }

    void parse_topology(const std::string &topo_file) {
        /* Instantiate a Topology object given 'topo_file'.
         * 
         * :param topo_file: the topology file name.
         * :type topo_file: string
         */
        topology = Topology(topo_file);
    }

    void parse_config(const std::string &config_file) {
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
        ///? assert(topology != NULL);
        for (auto edge_router : topology.get_all_edge_routers())
            ifid2addr[edge_router.interface.if_id] = *(edge_router.addr);
    }

    void handle_request(SCIONPacket packet, struct sockaddr * sender, 
                        bool from_local_socket=true) {
        /* Main routine to handle incoming SCION packets. Subclasses have to
         * override this to provide their functionality.
         */
        ///? incorrect type for `sender`
    }

    std::pair<IPAddress, int> get_first_hop(SCIONPacket spkt) {
        /* Returns first hop addr of down-path or end-host addr.
         */
        HopOpaqueField *opaque_field = spkt.hdr.path.get_first_hop_of();
        if (opaque_field == NULL)  // EmptyPath
            return std::make_pair(*(spkt.hdr.dst_addr.host_addr),
                                  SCION_UDP_PORT);
        else {
            if (spkt.hdr.is_on_up_path())
                return std::make_pair(ifid2addr[opaque_field->ingress_if], 
                                 SCION_UDP_PORT);
            else
                return std::make_pair(ifid2addr[opaque_field->egress_if], 
                                 SCION_UDP_PORT);
        }
    }

    void send(SCIONPacket packet, std::string dst, 
                     int dst_port=SCION_UDP_PORT) {
        /* Send *packet* to *dst* (to port *dst_port*) using the local socket.
         * Calling ``packet.pack()`` should return :class:`bytes`, and
         * ``dst.to_string()`` should return a string representing an IPv4 address.
         *
         * :param packet: the packet to be sent to the destination.
         * :type packet:
         * :param dst: the destination IPv4 address.
         * :type dst: str
         * :param dst_port: the destination port number.
         * :type dst_port: int
         */
        std::string buf = packet.pack();
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        inet_pton(AF_INET, dst.c_str(), &dest.sin_addr.s_addr);
        dest.sin_port = htons(dst_port);

        sendto(local_socket, buf.c_str(), buf.length(), 0, 
               (struct sockaddr *)&dest, sizeof(struct sockaddr_in));
    } 

    void run() {
        /* Main routine to receive packets and pass them to
         * :func:`handle_request()`.
         */
        fd_set rfds;
        while (true) {
            FD_ZERO(&rfds);
            int nfds = -1;
            for (int s : sockets) {
                FD_SET(s, &rfds);
                nfds = max(s, nfds);
            }
            int n = select(nfds, &rfds, 0, 0, 0); ///? timeout shouldn't be NULL
            for (int s : sockets) {
                if (FD_ISSET(s, &rfds)) {
                    char buf[BUFLEN+1];
                    struct sockaddr_in src_addr;
                    socklen_t addr_len = sizeof(struct sockaddr_in);
                    recvfrom(s, buf, BUFLEN, 0, (struct sockaddr*)&src_addr, 
                             &addr_len);
                    handle_request(SCIONPacket(std::string(buf)), 
                        (struct sockaddr*)&src_addr, s == local_socket);
                }
            }
        }
    }

    void clean() {
        /* Close open sockets. 
         */
        for (int s : sockets)
            close(s);
    }

};

#endif // SCION_ELEM_CPP
