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
#ifndef TOPOLOGY_CPP
#define TOPOLOGY_CPP

#include <algorithm>
#include <string>
#include <map>
#include "rapidjson/document.h"
#include "rapidjson/filereadstream.h"
#include "IPAddress.h"


typedef std::string S;
typedef std::map<S,S> MSS;

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
    IPAddress* addr; 
    IPAddress* to_addr;
    std::string name;

public:
    Element() {}

    Element(std::string addr, std::string addr_type, std::string to_addr,
            std::string name) {
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
        transform(addr_type.begin(), addr_type.end(), addr_type.begin(), 
                  ::tolower);
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
    /**
     * The ServerElement class represents one of the servers in the AD.
     */
 public:
    ServerElement (std::map<std::string, std::string> server_dict, 
                   std::string name) : Element(server_dict["Addr"], 
                   server_dict["AddrType"], "", name) {
        /**
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
    /**
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
    int to_udp_port;
    int udp_port;

public:
    std::string neighbor_type;

    InterfaceElement() {}

    InterfaceElement (std::map<std::string, std::string> interface_dict) 
        : Element(interface_dict["Addr"], interface_dict["AddrType"], 
            interface_dict["ToAddr"], "") 
        {
        /**
         * Initialize an instance of the class InterfaceElement.
         * 
         * :param interface_dict: contains information about the interface.
         * :type interface_dict: dict
         * :returns: the newly created InterfaceElement instance.
         * :rtype: :class:`InterfaceElement`
         */
        if_id = stoi(interface_dict["IFID"]);
        neighbor_ad = stoi(interface_dict["NeighborAD"]);
        neighbor_isd = stoi(interface_dict["NeighborISD"]);
        neighbor_type = interface_dict["NeighborType"];
        to_udp_port = stoi(interface_dict["ToUdpPort"]);
        udp_port = stoi(interface_dict["UdpPort"]);
    }
};

class RouterElement : public Element {
    /**
     * The RouterElement class represents one of the edge routers.
     * 
     * :ivar interface: one of the interfaces of the edge router.
     * :type interface: :class:`InterfaceElement`
     */ 
public:
    InterfaceElement interface;

    RouterElement(std::map<std::string, std::string> router_dict, 
                  std::map<std::string, std::string> interface_dict,
                  std::string name) : Element(router_dict["Addr"], 
                  router_dict["AddrType"], "", name) {
        /** 
         * Initialize an instance of the class RouterElement.
         * 
         * :param router_dict: contains information about an edge router.
         * :type router_dict: dict
         * :param name: router element name or id
         * :type name: str
         * :returns: the newly created RouterElement instance.
         * :rtype: :class:`RouterElement`
         */
        ///? interface dict is basically router_dict["interface"]
        interface = InterfaceElement(interface_dict);
    }
};

class Topology {
    /**
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
    uint16_t isd_id;
    int64_t ad_id;
    std::vector<ServerElement> beacon_servers;
    std::vector<ServerElement> certificate_servers;
    std::vector<ServerElement> path_servers;
    std::vector<RouterElement> parent_edge_routers;
    std::vector<RouterElement> child_edge_routers;
    std::vector<RouterElement> peer_edge_routers;
    std::vector<RouterElement> routing_edge_routers;

    Topology() {
        /**
         * Initialize an instance of the class Topology.
         * 
         * :returns: the newly created Topology instance.
         * :rtype: :class:`Topology`
         */
        is_core_ad = false;
        isd_id = 0;
        ad_id = 0;
    }

    Topology(std::string topology_file) {
        /*
         * Create a Topology instance from the file.
         * 
         * :param topology_file: path to the topology file
         * :type topology_file: str
         */
        // try:
        //     with open(topology_file) as topo_fh:
        //         topology_dict = json.load(topo_fh)
        // except (ValueError, KeyError, TypeError):
        //     logging.error("Topology: JSON format error.")
        //     return
        // return cls.from_dict(topology_dict)


        // try{
        //     FILE* fp = fopen(topology_file, "r");
        //     char readBuffer[65536];
        //     FileReadStream is(fp, readBuffer, sizeof(readBuffer));
        //     Document d;
        //     d.ParseStream(is);
        //     fclose(fp);
        // }
        // catch(int e) {
        //     logging.error("Config: JSON format error.")
        //     return;
        // }
        std::cerr << "***UNIMPLEMENTED***" << std::endl;
        exit(-1);
    }

    Topology(std::map<std::string, uint64_t> topology, 
                    std::map<S, MSS> bs, 
                    std::map<S, MSS> cs,
                    std::map<S, MSS> ps, 
                    std::map<S, std::pair<MSS, MSS>> er) {
        /*
         * Create a Topology instance from the dictionary.
         * 
         * :param topology: dictionary representation of a topology
         * :type topology: std::map<std::string, uint64_t>
         * :param bs: dictionary representation of beacon servers
         * :type bs: std::map<std::string, std::map<std::string, std::string>>
         * :param cs: dictionary representation of certificate servers
         * :type cs: std::map<std::string, std::map<std::string, std::string>>
         * :param ps: dictionary representation of path servers
         * :type ps: std::map<std::string, std::map<std::string, std::string>>
         * :param er: dictionary representation of edge routers
         * :type er: std::map<std::string, 
                              pair<std::map<std::string, std::string>>, 
                                   std::map<std::string, std::string>>>
         */
        parse_dict(topology, bs, cs, ps, er);
    }

    void parse_dict(std::map<std::string, uint64_t> topology, 
                    std::map<S, MSS> bs, 
                    std::map<S, MSS> cs,
                    std::map<S, MSS> ps, 
                    std::map<S, std::pair<MSS, MSS>> er) {
        /*
         * Parse a topology dictionary and populate the instance's attributes.
         * 
         * :param topology: dictionary representation of a topology
         * :type topology: std::map<std::string, uint64_t>
         * :param bs: dictionary representation of beacon servers
         * :type bs: std::map<std::string, std::map<std::string, std::string>>
         * :param cs: dictionary representation of certificate servers
         * :type cs: std::map<std::string, std::map<std::string, std::string>>
         * :param ps: dictionary representation of path servers
         * :type ps: std::map<std::string, std::map<std::string, std::string>>
         * :param er: dictionary representation of edge routers
         * :type er: std::map<std::string, 
                              pair<std::map<std::string, std::string>>, 
                                   std::map<std::string, std::string>>>
         */
        is_core_ad = (topology["Core"] == 1);
        isd_id = topology["ISDID"];
        ad_id = topology["ADID"];
        for (auto it = bs.begin(); it != bs.end(); it++) 
            beacon_servers.push_back(ServerElement(it->second, it->first));
        for (auto it = cs.begin(); it != cs.end(); it++) 
            certificate_servers.push_back(ServerElement(it->second, it->first));
        for (auto it = ps.begin(); it != ps.end(); it++) 
            path_servers.push_back(ServerElement(it->second, it->first));
        for (auto it = er.begin(); it != er.end(); it++) {
            RouterElement edge_router(it->second.first, it->second.second, 
                                      it->first);
            if (edge_router.interface.neighbor_type == "PARENT")
                parent_edge_routers.push_back(edge_router);
            else if (edge_router.interface.neighbor_type == "CHILD")
                child_edge_routers.push_back(edge_router);
            else if (edge_router.interface.neighbor_type == "PEER")
                peer_edge_routers.push_back(edge_router);
            else if (edge_router.interface.neighbor_type == "ROUTING")
                routing_edge_routers.push_back(edge_router);
            else {
                // logging.warning("Encountered unknown neighbor type")
            }
        }
    }

    std::vector<RouterElement> get_all_edge_routers() {
        /*
         * Return all edge routers associated to the AD.
         * 
         * :returns: all edge routers associated to the AD.
         * :rtype: std::vector<RouterElement>
         */
        std::vector<RouterElement> all_edge_routers;
        all_edge_routers.reserve(parent_edge_routers.size() + 
            child_edge_routers.size() + peer_edge_routers.size() + 
            routing_edge_routers.size());

        all_edge_routers.insert(all_edge_routers.end(), 
            parent_edge_routers.begin(), parent_edge_routers.end());
        all_edge_routers.insert(all_edge_routers.end(), 
            child_edge_routers.begin(), child_edge_routers.end());
        all_edge_routers.insert(all_edge_routers.end(), 
            peer_edge_routers.begin(), peer_edge_routers.end());
        all_edge_routers.insert(all_edge_routers.end(), 
            routing_edge_routers.begin(), routing_edge_routers.end());
        return all_edge_routers;
    }

    void get_own_config(std::string server_type, std::string server_id) {
        // target = None
        // if server_type == "bs":
        //     target = beacon_servers
        // elif server_type == "cs":
        //     target = certificate_servers
        // elif server_type == "ps":
        //     target = path_servers
        // elif server_type == "er":
        //     target = get_all_edge_routers()
        // else:
        //     logging.error("Unknown server type: \"%s\"", server_type)

        // for i in target:
        //     if i.name == server_id:
        //         return i
        // else:
        //     logging.error("Could not find server %s%s-%s-%s", server_type,
        //                   self.isd_id, self.ad_id, server_id)
        std::cerr << "***UNIMPLEMENTED***" << std::endl;
        exit(-1);
    }
};

#endif // TOPOLOGY_CPP