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
 * :mod:`topology` --- SCION topology parser
 * ===========================================
 */

#include <algorithm>
#include <string>
#include "rapidjson/document.h"
#include "rapidjson/filereadstream.h"
#include "IPAddress.h"

using namespace std;

class Element {
    /*
     * The Element class is the base class for elements specified in the topology
     * file.
     * 
     * :ivar addr: IP or SCION address of a server or edge router.
     * :type addr: :class:`IPv4Address` or :class:`IPv6Address`
     * :ivar to_addr: destination IP or SCION address of an edge router.
     * :type to_addr: :class:`IPv4Address` or :class:`IPv6Address`
     * :ivar name: element name or id
     * :type name: str
     */

    IPAddress * addr; 
    IPAddress * to_addr;
    string name;

    Element(string addr, string addr_type, string to_addr, string name) {
        /* 
         * Initialize an instance of the class Element.
         * 
         * :param addr: IP or SCION address of a server or edge router.
         * :type addr: str
         * :param addr_type: type of the given address.
         * :type addr_type: str
         * :param to_addr: destination IP or SCION address of an edge router.
         * :type to_addr: str
         * :param name: element name or id
         * :type name: str
         * :returns: the newly created Element instance.
         * :rtype: :class:`Element`
         */
        transform(addr_type.begin(), addr_type.end(), addr_type.begin(), ::tolower);
        if (addr_type == "ipv4") {
            this->addr = new IPv4Address(addr);
            if (to_addr.length())
                this->to_addr = new IPv4Address(to_addr);
        }
        else if (addr_type == "ipv6") {
            this->addr = new IPv6Address(addr);
            if (to_addr.length())
                this->to_addr = new IPv6Address(to_addr);
        }
        this->name = name;

    }
};

class ServerElement : public Element {
    /*
     * The ServerElement class represents one of the servers in the AD.
     */
    ServerElement (map<string, string> server_dict, string name) 
        : Element(server_dict["Addr"], server_dict["AddrType"], "", name) {
        /* 
         * Initialize an instance of the class ServerElement.
         * 
         * :param server_dict: contains information about a particular server.
         * :type server_dict: dict
         * :param name: server element name or id
         * :type name: str
         */
     }
};

class InterfaceElement : public Element {
    /* 
     * The InterfaceElement class represents one of the interfaces of an edge
     * router.
     * 
     * :ivar if_id: the interface ID.
     * :type if_id: int
     * :ivar neighbor_ad: the AD identifier of the neighbor AD.
     * :type neighbor_ad: int
     * :ivar neighbor_isd: the ISD identifier of the neighbor AD.
     * :type neighbor_isd: int
     * :ivar neighbor_type: the type of the neighbor relative to the AD to which
     *                      the interface belongs.
     * :type neighbor_type: str
     * :ivar to_udp_port: the port number receiving UDP traffic on the other end of
     *                    the interface.
     * :type to_udp_port: int
     * :ivar udp_port: the port number used to send UDP traffic.
     * :type udp_port: int
     */

    int if_id;
    int neighbor_ad;
    int neighbor_isd;
    string neighbor_type;
    int to_udp_port;
    int udp_port;

    InterfaceElement (map<string, string> interface_dict) 
        : Element(interface_dict["Addr"], interface_dict["AddrType"], 
            interface_dict["ToAddr"], "") {
        /*
         * Initialize an instance of the class InterfaceElement.
         * 
         * :param interface_dict: contains information about the interface.
         * :type interface_dict: dict
         * :returns: the newly created InterfaceElement instance.
         * :rtype: :class:`InterfaceElement`
         */
        this->if_id = interface_dict['IFID'];
        this->neighbor_ad = interface_dict['NeighborAD'];
        this->neighbor_isd = interface_dict['NeighborISD'];
        this->neighbor_type = interface_dict['NeighborType'];
        this->to_udp_port = interface_dict['ToUdpPort'];
        this->udp_port = interface_dict['UdpPort'];
    }
};

class RouterElement : public Element {
    /* 
     * The RouterElement class represents one of the edge routers.
     * 
     * :ivar interface: one of the interfaces of the edge router.
     * :type interface: :class:`InterfaceElement`
     */ 
    InterfaceElement interface;

    RouterElement(map<string, string> router_dict, string name) 
        : Element(router_dict["Addr"], router_dict["AddrType"],
                        "", name=name) {
        /* 
         * Initialize an instance of the class RouterElement.
         * 
         * :param router_dict: contains information about an edge router.
         * :type router_dict: dict
         * :param name: router element name or id
         * :type name: str
         * :returns: the newly created RouterElement instance.
         * :rtype: :class:`RouterElement`
         */
        this->interface = InterfaceElement(router_dict["Interface"]);
    }
};

class Topology {
    /* 
     * The Topology class parses the topology file of an AD and stores such
     * information for further use.
     * 
     * :ivar is_core_ad: tells whether an AD is a core AD or not.
     * :vartype is_core_ad: bool
     * :ivar isd_id: the ISD identifier.
     * :vartype isd_id: int
     * :ivar ad_id: the AD identifier.
     * :vartype ad_id: int
     * :ivar beacon_servers: beacons servers in the AD.
     * :vartype beacon_servers: list
     * :ivar certificate_servers: certificate servers in the AD.
     * :vartype certificate_servers: list
     * :ivar path_servers: path servers in the AD.
     * :vartype path_servers: list
     * :ivar parent_edge_routers: edge routers linking the AD to its parents.
     * :vartype parent_edge_routers: list
     * :ivar child_edge_routers: edge routers linking the AD to its children.
     * :vartype child_edge_routers: list
     * :ivar peer_edge_routers: edge router linking the AD to its peers.
     * :vartype peer_edge_routers: list
     * :ivar routing_edge_routers: edge router linking the core AD to another core
     *                             AD.
     * :vartype routing_edge_routers: list
     */
    
    bool is_core_ad;
    int isd_id;
    int ad_id;
    vector<??> beacon_servers;
    vector<??> certificate_servers;
    vector<??> path_servers;
    vector<??> parent_edge_routers;
    vector<??> child_edge_routers;
    vector<??> peer_edge_routers;
    vector<??> routing_edge_routers;

    Topology() {
        /*
         * Initialize an instance of the class Topology.
         * 
         * :returns: the newly created Topology instance.
         * :rtype: :class:`Topology`
         */
        this->is_core_ad = false;
        this->isd_id = 0;
        this->ad_id = 0;
    }

    Topology(string topology_file) {
        /*
         * Create a Topology instance from the file.
         * 
         * :param topology_file: path to the topology file
         * :type topology_file: str
         */
        try:
            with open(topology_file) as topo_fh:
                topology_dict = json.load(topo_fh)
        except (ValueError, KeyError, TypeError):
            logging.error("Topology: JSON format error.")
            return
        return cls.from_dict(topology_dict)


        try{
            FILE* fp = fopen(topology_file, "r");
            char readBuffer[65536];
            FileReadStream is(fp, readBuffer, sizeof(readBuffer));
            Document d;
            d.ParseStream(is);
            fclose(fp);
        }
        catch(int e) {
            logging.error("Config: JSON format error.")
            return;
        }
    }

    Topology(map<??,??> topology_dict) {
        /*
         * Create a Topology instance from the dictionary.
         * 
         * :param topology_dict: dictionary representation of a topology
         * :type topology_dict: dict
         */
        parse_dict(topology_dict);
    }

    void parse_dict(map<??,??> topology){
        /*
         * Parse a topology dictionary and populate the instance's attributes.
         * 
         * :param topology: dictionary representation of a topology
         * :type topology: dict
         */
        is_core_ad = (topology["Core"] == 1)
        isd_id = topology["ISDID"];
        ad_id = topology["ADID"];
        for bs_key in topology["BeaconServers"]:
            b_server = ServerElement(topology["BeaconServers"][bs_key],
                                     bs_key);
            beacon_servers.append(b_server);
        for cs_key in topology["CertificateServers"]:
            c_server = ServerElement(topology["CertificateServers"][cs_key],
                                     cs_key);
            certificate_servers.append(c_server)
        for ps_key in topology["PathServers"]:
            p_server = ServerElement(topology["PathServers"][ps_key],
                                     ps_key);
            path_servers.append(p_server);
        for er_key in topology["EdgeRouters"]:
            edge_router = RouterElement(topology["EdgeRouters"][er_key],
                                        er_key);
            if edge_router.interface.neighbor_type == "PARENT":
                parent_edge_routers.append(edge_router);
            elif edge_router.interface.neighbor_type == "CHILD":
                child_edge_routers.append(edge_router);
            elif edge_router.interface.neighbor_type == "PEER":
                peer_edge_routers.append(edge_router);
            elif edge_router.interface.neighbor_type == "ROUTING":
                routing_edge_routers.append(edge_router);
            else:
                logging.warning("Encountered unknown neighbor type")
    }

    vector<??> get_all_edge_routers(){
        /*
         * Return all edge routers associated to the AD.
         * 
         * :returns: all edge routers associated to the AD.
         * :rtype: vector
         */
        vector<??> all_edge_routers;
        all_edge_routers.reserve(parent_edge_routers.size() + 
            child_edge_routers.size() + peer_edge_routers.size() + 
            routing_edge_routers.size());

        all_edge_routers.insert(all_edge_routers.end(), 
            parent_edge_routers.begin(), parent_edge_routers.end());
        all_edge_routers.extend(all_edge_routers.end(), 
            child_edge_routers.begin(), child_edge_routers.end());
        all_edge_routers.extend(all_edge_routers.end(), 
            peer_edge_routers.begin(), peer_edge_routers.end());
        all_edge_routers.extend(all_edge_routers.end(), 
            routing_edge_routers.begin(), routing_edge_routers.end());
        return all_edge_routers;
    }
};