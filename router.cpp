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
 * :mod:`router` --- SCION edge router
 * ===========================================
 */
#include <thread>
#include "scion_elem.cpp"
#include "lib/packet/pcb.cpp"

#define IFID_PKT_TOUT 0.5

class NextHop;
typedef void (*HandlerFunction)(SCIONPacket, NextHop);


class NextHop {
    /**
     * Simple class for next hop representation. Object of this class corresponds
     * to SCION Packet and is processed within routing context.
     *  :ivar addr: the next hop address.
     *  :vartype addr: str
     *  :ivar port: the next hop port number.
     *  :vartype port: int
     */
public:
    std::string addr;
    int port;

    NextHop() {
        addr = "";
        port = SCION_UDP_PORT;
    }

    std::string to_string() {
        return addr + ":" + std::to_string(port);
    }
};


class Router : public SCIONElement {
    /**
     * The SCION Router.
     * 
     * :ivar addr: the router address.
     * :vartype addr: :class:`SCIONAddr`
     * :ivar topology: the AD topology as seen by the router.
     * :vartype topology: :class:`Topology`
     * :ivar config: the configuration of the router.
     * :vartype config: :class:`Config`
     * :ivar ifid2addr: a map from interface identifiers to the corresponding
     *    border router addresses in the server's AD.
     * :vartype ifid2addr: dict
     * :ivar interface: the router's inter-AD interface, if any.
     * :vartype interface: :class:`lib.topology.InterfaceElement`
     * :ivar pre_ext_handlers: a map of extension header types to handlers for
     *     those extensions that execute before routing.
     * :vartype pre_ext_handlers: dict
     * :ivar post_ext_handlers: a map of extension header types to handlers for
     *     those extensions that execute after routing.
     * :vartype post_ext_handlers: dict
     */
    InterfaceElement interface;
    std::map<int, HandlerFunction> pre_ext_handlers;
    std::map<int, HandlerFunction> post_ext_handlers;
    int remote_socket;
    std::vector<int> sockets;

public:
    Router(std::string router_id, std::string topo_file, 
           std::string config_file, 
           std::map<int, HandlerFunction> pre_ext_handlers,
           std::map<int, HandlerFunction> post_ext_handlers) 
            : SCIONElement("er", topo_file, config_file, router_id) {
        /**
         * Constructor.
         * :param addr: the router address.
         * :type addr: :class:`ipaddress.IPv4Address`
         * :param topo_file: the topology file name.
         * :type topo_file: str
         * :param config_file: the configuration file name.
         * :type config_file: str
         * :param pre_ext_handlers: a map of extension header types to handlers
         *     for those extensions that execute before routing.
         * :type pre_ext_handlers: dict
         * :param post_ext_handlers: a map of extension header types to handlers
         *     for those extensions that execute after routing.
         * :type post_ext_handlers: dict
         */
        for (auto edge_router : topology.get_all_edge_routers()) {
            if (*edge_router.addr == *addr.host_addr) {
                interface = edge_router.interface;
                break;
            }
        }
        ///? assert self.interface is not None
        // logging.info("Interface: %s", self.interface.__dict__)

        this->pre_ext_handlers = pre_ext_handlers;
        this->post_ext_handlers = post_ext_handlers;
        
        remote_socket = socket(AF_INET, SOCK_DGRAM, 0);
        int val = 1;
        setsockopt(remote_socket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        inet_pton(AF_INET, interface.addr->to_string().c_str(), 
                  &serv_addr.sin_addr.s_addr);
        serv_addr.sin_port = htons(interface.udp_port);
        if (bind(remote_socket, (struct sockaddr *) &serv_addr, 
            sizeof(serv_addr)) < 0) {
            // log error on binding            
        }
        sockets.push_back(remote_socket);
        // logging.info("IP %s:%u", self.interface.addr, self.interface.udp_port)
    }

    void run() {
        std::thread t(&Router::sync_interface, this);
        t.detach();
        ///? should run/start be called explicitly?
        SCIONElement::run();
    }

    void send(SCIONPacket packet, NextHop next_hop, bool use_local_socket=true) {
        /**
         * Sends packet to next_hop.addr (class of that object must implement
         * __str__ which returns IPv4 addr) using next_hop.port and local or remote
         * socket.
         * :param packet: the
         * :type packet:
         * :param next_hop: the next hop of the packet.
         * :type next_hop: :class:`NextHop`
         * :param use_local_socket: whether to use the local socket (as opposed to
         *     a remote socket).
         * :type use_local_socket: bool
         */
        // logging.info("Sending packet to %s", next_hop)
        handle_extensions(packet, next_hop, false);
        if (use_local_socket)
            SCIONElement::send(packet, next_hop.addr, next_hop.port);
        else {
            std::string buf = packet.pack().get_string();
            struct sockaddr_in dest;
            dest.sin_family = AF_INET;
            inet_pton(AF_INET, next_hop.addr.c_str(), &dest.sin_addr.s_addr);
            dest.sin_port = htons(next_hop.port);
            sendto(remote_socket, buf.c_str(), buf.length(), 0, 
               (struct sockaddr *)&dest, sizeof(struct sockaddr_in));
        }
    }

    void handle_extensions(SCIONPacket spkt, NextHop next_hop, 
                           bool pre_routing_phase) {
        /**
         * Handles SCION Packet extensions. Handlers can be defined for pre- and
         * post-routing.
         * Handler takes two parameters: packet (SCIONPacket), next_hop (NextHop).
         * :param spkt:
         * :type spkt:
         * :param next_hop:
         * :type next_hop:
         * :param pre_routing_phase:
         * :type pre_routing_phase:
         */
        map<int, HandlerFunction> * handlers;
        if (pre_routing_phase)
            handlers = &pre_ext_handlers;
        else
            handlers = &post_ext_handlers;

        int ext = spkt.hdr.common_hdr.next_hdr, l = 0;
        while (ext != 0 && l < spkt.hdr.extension_hdrs.size()) {
            if (handlers->find(ext) != handlers->end())
                (*handlers)[ext](spkt, next_hop);
            ///? ext = ext.next_ext;
            l += 1;
        }

        if (ext || l < spkt.hdr.extension_hdrs.size()) {
            // logging.warning("Extensions terminated incorrectly.")
        }
    }

    void sync_interface() {
        /**
         * Synchronize and initialize the router's interface with that of a
         * neighboring router.
         */
        NextHop next_hop;
        next_hop.addr = interface.to_addr->to_string();
        next_hop.port = interface.to_udp_port;
        SCIONAddr src(topology.isd_id, topology.ad_id, interface.addr);
        std::pair<uint16_t, uint64_t> dst_isd_ad(interface.neighbor_isd,
                                                 interface.neighbor_ad);
        IFIDPacket ifid_req(src, dst_isd_ad, interface.if_id);
        while (true) {
            send(ifid_req, next_hop, false);
            // logging.info('Sending IFID_PKT to router: req_id:%d, rep_id:%d',
                         // ifid_req.request_id, ifid_req.reply_id)
            usleep(1000000 * IFID_PKT_TOUT);
        }
    }

    void process_ifid_request(std::string packet, NextHop next_hop) {
        /**
         * After receiving IFID_PKT from neighboring router it is completed (by
         * iface information) and passed to local BSes.
         * :param packet: the IFID request packet to send.
         * :type packet: bytes
         * :param next_hop: the next hop of the request packet.
         * :type next_hop: :class:`NextHop`
         */
        // logging.info('IFID_PKT received, len %u', len(packet))
        IFIDPacket ifid_req(packet);
        // Forward 'alive' packet to all BSes (to inform that neighbor is alive).
        ifid_req.reply_id = interface.if_id;  // BS must determine interface.
        // logging.debug("Forwarding IFID_PKT to BSes")
        for (auto bs : topology.beacon_servers) {
            next_hop.addr = bs.addr->to_string();
            send(ifid_req, next_hop);
        }
    }

    void process_pcb(std::string packet, NextHop next_hop, bool from_bs) {
        /**
         * Depending on scenario: a) sends PCB to all beacon servers, or b) to
         * neighboring router.
         * :param packet:
         * :type packet:
         * :param next_hop:
         * :type next_hop:
         * :param from_bs:
         * :type from_bs: bool
         */
        PathConstructionBeacon beacon(packet);
        if (from_bs) {
            if (interface.if_id != beacon.pcb.trcf.if_id) {
                // logging.error("Wrong interface set by BS.")
                return;
            }
            next_hop.addr = interface.to_addr->to_string();
            next_hop.port = interface.to_udp_port;
            send(beacon, next_hop, false);
        }
        else {
            // TODO Multiple BS scenario
            beacon.pcb.trcf.if_id = interface.if_id;
            next_hop.addr = topology.beacon_servers[0].addr->to_string();
            send(beacon, next_hop);
        }
    }

    void relay_cert_server_packet(SCIONPacket spkt, NextHop next_hop, 
                                  bool from_local_ad) {
        /**
         * Relay packets for certificate servers.
         * :param spkt: the SCION packet to forward.
         * :type spkt: :class:`lib.packet.scion.SCIONPacket`
         * :param next_hop: the next hop of the packet.
         * :type next_hop: :class:`NextHop`
         * :param from_local_ad: whether or not the packet is from the local AD.
         * :type from_local_ad: bool
         */
        if (from_local_ad) {
            next_hop.addr = interface.to_addr->to_string();
            next_hop.port = interface.to_udp_port;
        }
        else
            // TODO Multiple CS scenario
            next_hop.addr = topology.certificate_servers[0].addr->to_string();
        send(spkt, next_hop);
    }

    bool verify_of(CommonOpaqueField *hof, CommonOpaqueField *prev_hof, int ts) {
        /**
         * Verifies freshness and authentication of an opaque field.
         * :param hof: the hop opaque field that is verified.
         * :type hof: :class:`lib.packet.opaque_field.HopOpaqueField`
         * :param prev_hof: previous hop opaque field (according to order of PCB
         *     propagation) required for verification.
         * :type prev_hof: :class:`lib.packet.opaque_field.HopOpaqueField` or None
         * :param ts: timestamp against which the opaque field is verified.
         * :type ts: int
         */
        // if (std::time(0) <= ts + hof.exp_time * EXP_TIME_UNIT) {
        //     if (verify_of_mac(of_gen_key, hof, prev_hof, ts))
        //         return true;
        //     else {
        //         // logging.warning("Dropping packet due to incorrect MAC.")
        //     }
        // }
        // else {
        //     logging.warning("Dropping packet due to expired OF.")
        // }
        // return true;
        return true;
    }

    void normal_forward(SCIONPacket spkt, NextHop next_hop, bool from_local_ad, 
                        IPv4Address ptype) {
        /**
         * Process normal forwarding.
         * :param spkt: the SCION packet to forward.
         * :type spkt: :class:`lib.packet.scion.SCIONPacket`
         * :param next_hop: the next hop of the packet.
         * :type next_hop: :class:`NextHop`
         * :param from_local_ad: whether or not the packet is from the local AD.
         * :type from_local_ad: bool
         * :param ptype: the type of the packet.
         * :type ptype: :class:`lib.packet.scion.PacketType`
         */
        CommonOpaqueField *curr_hof = spkt.hdr.get_current_of();
        CommonOpaqueField *prev_hof = NULL;
        bool is_on_up_path = spkt.hdr.is_on_up_path();
        int timestamp = spkt.hdr.get_current_iof()->timestamp;
        int iface;
        if (is_on_up_path) {
            iface = curr_hof->ingress_if;
            prev_hof = spkt.hdr.get_relative_of(1);
        }
        else {
            iface = curr_hof->egress_if;
            if (spkt.hdr.get_relative_of(-1)->is_regular())
                prev_hof = spkt.hdr.get_relative_of(-1);
        }
        if (from_local_ad) {
            if (iface == interface.if_id) {
                next_hop.addr = interface.to_addr->to_string();
                next_hop.port = interface.to_udp_port;
                spkt.hdr.increase_of(1);
                if (verify_of(curr_hof, prev_hof, timestamp))
                    send(spkt, next_hop, false);
            }
            else {
                // logging.error("1 interface mismatch %u != %u", iface,
                              // self.interface.if_id)
            }
        }
        else {
            if (iface)
                next_hop.addr = ifid2addr[iface].to_string();
            else if (ptype == PacketType::PATH_MGMT)
                next_hop.addr = topology.path_servers[0].addr->to_string();
            else {  // last opaque field on the path, send the packet to the dst
                next_hop.addr = spkt.hdr.dst_addr.host_addr->to_string();
                next_hop.port = SCION_UDP_EH_DATA_PORT;  // data packet to endhost
            }
            if (verify_of(curr_hof, prev_hof, timestamp))
                send(spkt, next_hop);
        }
        // logging.debug("normal_forward()")
    }

    void crossover_forward(SCIONPacket spkt, NextHop next_hop, 
                           bool from_local_ad, uint32_t info) {
        /**
         * Process crossover forwarding.
         * :param spkt: the SCION packet to forward.
         * :type spkt: :class:`lib.packet.scion.SCIONPacket`
         * :param next_hop: the next hop of the packet.
         * :type next_hop: :class:`NextHop`
         * :param from_local_ad: whether or not the packet is from the local AD.
         * :type from_local_ad: bool
         * :param info: the type of opaque field.
         * :type info: :class:`lib.packet.opaque_field.OpaqueFieldType`
         */
        // logging.debug("crossover_forward()")
        CommonOpaqueField *curr_hof = spkt.hdr.get_current_of();
        CommonOpaqueField *prev_hof = NULL;
        bool is_on_up_path = spkt.hdr.is_on_up_path();
        bool timestamp = spkt.hdr.get_current_iof()->timestamp;

        if (info == OpaqueFieldType::TDC_XOVR) {
            if (is_on_up_path)
                prev_hof = spkt.hdr.get_relative_of(-1);
            if (verify_of(curr_hof, prev_hof, timestamp)) {
                spkt.hdr.increase_of(1);
                CommonOpaqueField *next_iof = spkt.hdr.get_current_of();
                CommonOpaqueField *opaque_field = spkt.hdr.get_relative_of(1);
                if (next_iof->up_flag)  // TODO replace by get_first_hop
                    next_hop.addr = 
                      ifid2addr[opaque_field->ingress_if].to_string();
                else next_hop.addr = 
                       ifid2addr[opaque_field->egress_if].to_string();
                // logging.debug("send() here, find next hop0.")
                send(spkt, next_hop);
            }
            else {
                // logging.error("Mac verification failed.")
            }
        }
        else if (info == OpaqueFieldType::NON_TDC_XOVR) {
            prev_hof = spkt.hdr.get_relative_of(1);
            if (verify_of(curr_hof, prev_hof, timestamp)) {
                spkt.hdr.increase_of(2);
                CommonOpaqueField *opaque_field = spkt.hdr.get_relative_of(2);
                next_hop.addr = 
                    ifid2addr[opaque_field->egress_if].to_string();
                // logging.debug("send() here, find next hop1");
                send(spkt, next_hop);
            }
        }
        else if (info == OpaqueFieldType::INPATH_XOVR) {
            if (verify_of(curr_hof, prev_hof, timestamp)) {
                bool is_regular = true;
                while (is_regular) {
                    spkt.hdr.increase_of(2);
                    is_regular = spkt.hdr.get_current_of()->is_regular();
                }
                spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p;    
                // logging.debug("TODO send() here, find next hop2")
            }
        }
        else if (info == OpaqueFieldType::INTRATD_PEER 
                 || info == OpaqueFieldType::INTERTD_PEER) {
            spkt.hdr.increase_of(1);
            prev_hof = spkt.hdr.get_relative_of(1);
            if (verify_of(curr_hof, prev_hof, timestamp)) {
                next_hop.addr = 
                    ifid2addr[spkt.hdr.get_current_of()->ingress_if].to_string();
                // logging.debug("send() here, next: %s", next_hop)
                send(spkt, next_hop);
            }
        }
        else {
            // logging.warning("Unknown case %u", info)
        }
    }

    void forward_packet(SCIONPacket spkt, NextHop next_hop, bool from_local_ad, IPv4Address ptype) {
        /**
         * Forward packet based on the current opaque field.
         * :param spkt: the SCION packet to forward.
         * :type spkt: :class:`lib.packet.scion.SCIONPacket`
         * :param next_hop: the next hop of the packet.
         * :type next_hop: :class:`NextHop`
         * :param from_local_ad: whether or not the packet is from the local AD.
         * :type from_local_ad: bool
         * :param ptype: the type of the packet.
         * :type ptype: :class:`lib.packet.scion.PacketType`
         */
        bool new_segment = false;
        while (!spkt.hdr.get_current_of()->is_regular()) {
            spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p;
            spkt.hdr.increase_of(1);
            new_segment = true;
        }

        while (spkt.hdr.get_current_of()->is_continue())
            spkt.hdr.increase_of(1);

        int info = spkt.hdr.get_current_iof()->info;
        int curr_iof_p = spkt.hdr.common_hdr.curr_iof_p;
        // Case: peer path and first opaque field of a down path. We need to
        // increase opaque field pointer as that first opaque field is used for
        // MAC verification only.
        if (!spkt.hdr.is_on_up_path() &&
                (info == OpaqueFieldType::INTRATD_PEER 
                    || info == OpaqueFieldType::INTERTD_PEER) &&
                spkt.hdr.common_hdr.curr_of_p == curr_iof_p + OpaqueField::LEN)
            spkt.hdr.increase_of(1);

        if (spkt.hdr.get_current_of()->info == OpaqueFieldType::LAST_OF
            && !spkt.hdr.is_last_path_of() && !new_segment)
            crossover_forward(spkt, next_hop, from_local_ad, info);
        else
            normal_forward(spkt, next_hop, from_local_ad, ptype);
    }

    void write_to_egress_iface(SCIONPacket spkt, NextHop next_hop) {
        /**
         * Forwards packet to neighboring router.
         * :param spkt: the SCION packet to forward.
         * :type spkt: :class:`lib.packet.scion.SCIONPacket`
         * :param next_hop: the next hop of the packet.
         * :type next_hop: :class:`NextHop`
         * :param from_local_ad: whether or not the packet is from the local AD.
         * :type from_local_ad: bool
         */
        int of_info = spkt.hdr.get_current_of()->info;

        if (of_info == OpaqueFieldType::TDC_XOVR) {
            spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p;
            spkt.hdr.increase_of(1);
        }
        else if (of_info == OpaqueFieldType::NON_TDC_XOVR) {
            spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p;
            spkt.hdr.increase_of(2);
        }

        spkt.hdr.increase_of(1);
        int iof_info = spkt.hdr.get_current_iof()->info;
        if (iof_info == OpaqueFieldType::INTRATD_PEER || iof_info == OpaqueFieldType::INTERTD_PEER) {
            if (spkt.hdr.is_on_up_path()) {
                    int rel_info = spkt.hdr.get_relative_of(1)->info;
                if (rel_info == OpaqueFieldType::INTRATD_PEER || rel_info == OpaqueFieldType::INTERTD_PEER)
                    spkt.hdr.increase_of(1);
            }
            else {
                if (spkt.hdr.get_current_of()->info == OpaqueFieldType::LAST_OF)
                    spkt.hdr.increase_of(1);
            }
        }

        next_hop.addr = interface.to_addr->to_string();
        next_hop.port = interface.to_udp_port;
        // logging.debug("sending to dst6 %s", next_hop);
        send(spkt, next_hop, false);
    }

    void process_packet(SCIONPacket spkt, NextHop next_hop, bool from_local_ad,
                        IPv4Address ptype) {
        /**
         * Inspects current opaque fields and decides on forwarding type.
         * 
         * :param spkt: the SCION packet to process.
         * :type spkt: :class:`lib.packet.scion.SCIONPacket`
         * :param next_hop: the next hop of the packet.
         * :type next_hop: :class:`NextHop`
         * :param from_local_ad: whether or not the packet is from the local AD.
         * :type from_local_ad: bool
         * :param ptype: the type of the packet.
         * :type ptype: :class:`lib.packet.scion.PacketType`
         */
        if (!spkt.hdr.is_first_path_of() &&
                ptype == PacketType::DATA && from_local_ad)
            write_to_egress_iface(spkt, next_hop);
        else
            forward_packet(spkt, next_hop, from_local_ad, ptype);
    }

    void handle_request(std::string packet, int sender, 
                        bool from_local_socket=true) {
        /**
         * Main routine to handle incoming SCION packets.
         * 
         * :param packet: the incoming packet to handle.
         * :type packet: SCIONPacket
         * :param sender:
         * :type sender:
         * :param from_local_socket: whether the request is coming from a local
         *     socket.
         * :type from_local_socket: bool
         * 
         * .. note::
         *     `sender` is not used in this function at the moment.
         */
        bool from_local_ad = from_local_socket;
        SCIONPacket spkt(packet);
        IPv4Address ptype = get_type(spkt);
        NextHop next_hop;
        handle_extensions(spkt, next_hop, true);
        if (ptype == PacketType::IFID_PKT && !from_local_ad)
            process_ifid_request(packet, next_hop);
        else if (ptype == PacketType::BEACON)
            process_pcb(packet, next_hop, from_local_ad);
        else if (ptype == PacketType::CERT_CHAIN_REQ 
                 || ptype == PacketType::CERT_CHAIN_REP
                 || ptype == PacketType::TRC_REQ 
                 || ptype == PacketType::TRC_REP)
            relay_cert_server_packet(spkt, next_hop, from_local_ad);
        else {
            if (ptype == PacketType::DATA) {
                // logging.debug("DATA type %s, %s", ptype, spkt)
            }
            process_packet(spkt, next_hop, from_local_ad, ptype);
        }
    }
};

int main(int argc, char* argv[]) {
    /**
     * Initializes and starts router.
     */
    // init_logging()
    // handle_signals()
    if (argc != 4) {
        // logging.error("run: %s router_id topo_file conf_file", sys.argv[0])
        exit(-1);
    }
    // for pre_ext_handlers and post_ext_handlers.
    std::map<int, HandlerFunction> temp; 
    
    std::vector<std::string> params(argv, argv+argc);
    Router router(params[1], params[2], params[3], temp, temp);
    // logging.info("Started: %s", datetime.datetime.now())
    router.run();
}
