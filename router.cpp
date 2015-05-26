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

#include <string>
#include <assert.h>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include "scion_elem.h"
#include "topology.h"
using namespace std;

#define IFID_PKT_TOUT 0.5

class NextHop {
    /* Simple class for next hop representation. Object of this class corresponds
     * to SCION Packet and is processed within routing context.
     *  :ivar addr: the next hop address.
     *  :vartype addr: str
     *  :ivar port: the next hop port number.
     *  :vartype port: int
     */

    string addr;
    int port;

public:
    NextHop(){
        addr = "";
        port = SCION_UDP_PORT;
    }

    string to_string(){
        return addr + to_string(port);
    }
};

class Router : public SCIONElement {
    /* 
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

    SCIONAddr addr;
    Topology topology;
    Constructor config;
    map<??, SCIONAddr> ifid2addr;
    InterfaceElement interface;
    map<??,??> pre_ext_handlers;
    map<??,??> post_ext_handlers;
    int _remote_socket;
    vector<int> _sockets;

public:
    Router(IPv4Address addr, string topo_file, string config_file, 
    		map<??,??> pre_ext_handlers, map<??,??> post_ext_handlers=None) 
    		: SCIONElement(addr, topo_file, config_file) {
        /*
         * Constructor.
		 * 
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
        
        ////? this->interface = None
        vector<??> all_edge_routers = topology.get_all_edge_routers();
        bool interface_set = false;
        for (auto it = all_edge_routers.begin(); it != all_edge_routers.end(); it++) {
            if (it->addr == this->addr.host_addr) {
                interface = it->interface;
                interface_set = true;
                break;
            }
        }

        assert(interface_set == true);
        //// logging.info("Interface: %s", this->interface.__dict__)

        this->pre_ext_handlers = pre_ext_handlers;
        // make sure that all arguments are passed properly to the constructor
        this->post_ext_handlers = post_ext_handlers;

        _remote_socket = socket(AF_INET, SOCK_DGRAM, 0);
        const char val = 1;
        int err = setsockopt(_remote_socket, SOL_SOCKET, SO_REUSEADDR, 
        			(char *)&val, sizeof(val));
        assert(err == 0);

        struct sockaddr_in saddr; 
        bzero((char *)&saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_port = interface.udp_port;
        saddr.sin_addr.s_addr = interface.addr->to_ulong();
        saddr.sin_port = htons(interface->udp_port);
        err = bind(_remote_socket, (struct sockaddr *) &saddr,
        			sizeof(saddr));
        assert(err == 0);
        this->_sockets.push_back(this->_remote_socket);

        logging.info("IP %s:%u", this->interface.addr, this->interface.udp_port)
    }

    void run() {
        thread t(sync_interface);
        t.detach();
        ///? should run/start be called explicitly?

        // threading.Thread(target=this->sync_interface, daemon=True).start()

        SCIONElement::run();
    }

    void send(PakcetType packet, NextHop next_hop, bool use_local_socket = true) {
        /* 
         * Sends packet to next_hop.addr (class of that object must implement
         * to_string which returns IPv4 addr) using next_hop.port and local or remote
         * socket.
		 * 
         * :param packet: the
         * :type packet:
         * :param next_hop: the next hop of the packet.
         * :type next_hop: :class:`NextHop`
         * :param use_local_socket: whether to use the local socket (as opposed to
         *     a remote socket).
         * :type use_local_socket: bool
        */
        logging.info("Sending packet to %s", next_hop);
        this->handle_extensions(packet, next_hop, false);
        if (use_local_socket)
            SCIONElement::send(packet, next_hop.addr, next_hop.port);
        else
            _remote_socket.sendto(packet.pack(), (str(next_hop.addr),
                next_hop.port));
    }

   //  def handle_extensions(self, spkt, next_hop, pre_routing_phase) {
   //      /* 
   //       * Handles SCION Packet extensions. Handlers can be defined for pre- and
   //       * post-routing.
   //       * Handler takes two parameters: packet (SCIONPacket), next_hop (NextHop).
		 // * 
   //       * :param spkt:
   //       * :type spkt:
   //       * :param next_hop:
   //       * :type next_hop:
   //       * :param pre_routing_phase:
   //       * :type pre_routing_phase:
   //       */ 

   //      if pre_routing_phase:
   //          handlers = this->pre_ext_handlers
   //      else:
   //          handlers = this->post_ext_handlers

   //      ext = spkt.hdr.common_hdr.next_hdr
   //      l = 0
   //      while ext and l < len(spkt.hdr.extension_hdrs):
   //          if ext in handlers:
   //              handlers[ext](spkt, next_hop)
   //          ext = ext.next_ext
   //          l += 1

   //      if ext or l < len(spkt.hdr.extension_hdrs):
   //          logging.warning("Extensions terminated incorrectly.")
   //  }

   //  @thread_safety_net("sync_interface")
   //  def sync_interface() {
   //      /* 
   //       * Synchronize and initialize the router's interface with that of a
   //       * neighboring router.
   //       */ 

   //      next_hop = NextHop()
   //      next_hop.addr = this->interface.to_addr
   //      next_hop.port = this->interface.to_udp_port
   //      src = SCIONAddr.from_values(this->topology.isd_id, this->topology.ad_id,
   //                                  this->interface.addr)
   //      dst_isd_ad = ISD_AD(this->interface.neighbor_isd,
   //                          this->interface.neighbor_ad)
   //      ifid_req = IFIDPacket.from_values(src, dst_isd_ad,
   //                                         this->interface.if_id)
   //      while True:
   //          this->send(ifid_req, next_hop, False)
   //          logging.info('Sending IFID_PKT to router: req_id:%d, rep_id:%d',
   //                       ifid_req.request_id, ifid_req.reply_id)
   //          time.sleep(IFID_PKT_TOUT)
   //  }

   //  def process_ifid_request(self, packet, next_hop) {
   //      /*
   //       * After receiving IFID_PKT from neighboring router it is completed (by
   //       * iface information) and passed to local BSes.
   //       * 
   //       * :param packet: the IFID request packet to send.
   //       * :type packet: bytes
   //       * :param next_hop: the next hop of the request packet.
   //       * :type next_hop: :class:`NextHop`
   //       */ 
   //      logging.info('IFID_PKT received, len %u', len(packet))
   //      ifid_req = IFIDPacket(packet)
   //      # Forward 'alive' packet to all BSes (to inform that neighbor is alive).
   //      ifid_req.reply_id = this->interface.if_id  # BS must determine interface.
   //      logging.debug("Forwarding IFID_PKT to BSes")
   //      for bs in this->topology.beacon_servers:
   //          next_hop.addr = bs.addr
   //          this->send(ifid_req, next_hop)
   //  }

   //  def process_pcb(self, packet, next_hop, from_bs) {
   //      /*
   //       * Depending on scenario: a) sends PCB to all beacon servers, or b) to
   //       * neighboring router.
		 // * 
   //       * :param packet:
   //       * :type packet:
   //       * :param next_hop:
   //       * :type next_hop:
   //       * :param from_bs:
   //       * :type from_bs: bool
   //       */
   //      beacon = PathConstructionBeacon(packet)
   //      if from_bs:
   //          if this->interface.if_id != beacon.pcb.trcf.if_id:
   //              logging.error("Wrong interface set by BS.")
   //              return
   //          next_hop.addr = this->interface.to_addr
   //          next_hop.port = this->interface.to_udp_port
   //          this->send(beacon, next_hop, False)
   //      else:
   //          # TODO Multiple BS scenario
   //          beacon.pcb.trcf.if_id = this->interface.if_id
   //          next_hop.addr = this->topology.beacon_servers[0].addr
   //          this->send(beacon, next_hop)
   //  }

   //  def relay_cert_server_packet(self, spkt, next_hop, from_local_ad) {
   //      /* 
   //       * Relay packets for certificate servers.
		 // * 
   //       * :param spkt: the SCION packet to forward.
   //       * :type spkt: :class:`lib.packet.scion.SCIONPacket`
   //       * :param next_hop: the next hop of the packet.
   //       * :type next_hop: :class:`NextHop`
   //       * :param from_local_ad: whether or not the packet is from the local AD.
   //       * :type from_local_ad: bool
   //       */
   //      if from_local_ad:
   //          next_hop.addr = this->interface.to_addr
   //          next_hop.port = this->interface.to_udp_port
   //      else:
   //          # TODO Multiple CS scenario
   //          next_hop.addr = this->topology.certificate_servers[0].addr
   //      this->send(spkt, next_hop)
   //  }

   //  // TODO
   //  def verify_of(self, spkt) {
   //      /* 
   //       * Verifies authentication of current opaque field.
		 // * 
   //       * :param spkt: the SCION packet in which to verify the opaque field.
   //       * :type spkt: :class:`lib.packet.scion.SCIONPacket`
		 // * 
   //       * .. warning::
   //       *    This method has not yet been implemented and always returns
   //       *    ``True``.
   //       */ 
   //      return True
   //  }

   //  def normal_forward(self, spkt, next_hop, from_local_ad, ptype) {
   //      /* 
   //       * Process normal forwarding.
		 // * 	
   //       * :param spkt: the SCION packet to forward.
   //       * :type spkt: :class:`lib.packet.scion.SCIONPacket`
   //       * :param next_hop: the next hop of the packet.
   //       * :type next_hop: :class:`NextHop`
   //       * :param from_local_ad: whether or not the packet is from the local AD.
   //       * :type from_local_ad: bool
   //       * :param ptype: the type of the packet.
   //       * :type ptype: :class:`lib.packet.scion.PacketType`
   //       */
   //      if not this->verify_of(spkt):
   //          return
   //      if spkt.hdr.is_on_up_path():
   //          iface = spkt.hdr.get_current_of().ingress_if
   //      else:
   //          iface = spkt.hdr.get_current_of().egress_if
   //      if from_local_ad:
   //          if iface == this->interface.if_id:
   //              next_hop.addr = this->interface.to_addr
   //              next_hop.port = this->interface.to_udp_port
   //              spkt.hdr.increase_of(1)
   //              this->send(spkt, next_hop, False)
   //          else:
   //              logging.error("1 interface mismatch %u != %u", iface,
   //                      this->interface.if_id)
   //      else:
   //          if iface:
   //              next_hop.addr = this->ifid2addr[iface]
   //          elif ptype in [PT.PATH_MGMT, PT.PATH_MGMT]:
   //              next_hop.addr = this->topology.path_servers[0].addr
   //          elif not spkt.hdr.is_last_path_of():  # next path segment
   //              spkt.hdr.increase_of(1)  # this is next SOF
   //              spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p
   //              spkt.hdr.increase_of(1)  # first HOF of the new path segment
   //              if spkt.hdr.is_on_up_path():  # TODO replace by get_first_hop
   //                  iface = spkt.hdr.get_current_of().ingress_if
   //              else:
   //                  iface = spkt.hdr.get_current_of().egress_if
   //              next_hop.addr = this->ifid2addr[iface]
   //          else:  # last opaque field on the path, send the packet to the dst
   //              next_hop.addr = spkt.hdr.dst_addr.host_addr
   //              next_hop.port = SCION_UDP_EH_DATA_PORT  # data packet to endhost
   //          this->send(spkt, next_hop)
   //      logging.debug("normal_forward()")
   //  }

   //  def crossover_forward(self, spkt, next_hop, from_local_ad, info) {
         
   //       * Process crossover forwarding.
		 // * 
   //       * :param spkt: the SCION packet to forward.
   //       * :type spkt: :class:`lib.packet.scion.SCIONPacket`
   //       * :param next_hop: the next hop of the packet.
   //       * :type next_hop: :class:`NextHop`
   //       * :param from_local_ad: whether or not the packet is from the local AD.
   //       * :type from_local_ad: bool
   //       * :param info: the type of opaque field.
   //       * :type info: :class:`lib.packet.opaque_field.OpaqueFieldType`
         
   //      logging.debug("crossover_forward()")
   //      if info == OFT.TDC_XOVR:
   //          if this->verify_of(spkt):
   //              spkt.hdr.increase_of(1)
   //              next_iof = spkt.hdr.get_current_of()
   //              opaque_field = spkt.hdr.get_relative_of(1)
   //              if next_iof.up_flag:  # TODO replace by get_first_hop
   //                  next_hop.addr = this->ifid2addr[opaque_field.ingress_if]
   //              else:
   //                  next_hop.addr = this->ifid2addr[opaque_field.egress_if]
   //              logging.debug("send() here, find next hop0.")
   //              this->send(spkt, next_hop)
   //          else:
   //              logging.error("Mac verification failed.")
   //      elif info == OFT.NON_TDC_XOVR:
   //          spkt.hdr.increase_of(2)
   //          opaque_field = spkt.hdr.get_relative_of(2)
   //          next_hop.addr = this->ifid2addr[opaque_field.egress_if]
   //          logging.debug("send() here, find next hop1")
   //          this->send(spkt, next_hop)
   //      elif info == OFT.INPATH_XOVR:
   //          if this->verify_of(spkt):
   //              is_regular = True
   //              while is_regular:
   //                  spkt.hdr.increase_of(2)
   //                  is_regular = spkt.hdr.get_current_of().is_regular()
   //              spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p
   //              if this->verify_of(spkt):
   //                  logging.debug("TODO send() here, find next hop2")
   //      elif info == OFT.INTRATD_PEER or info == OFT.INTERTD_PEER:
   //          if spkt.hdr.is_on_up_path():
   //              spkt.hdr.increase_of(1)
   //          if this->verify_of(spkt):
   //              if not spkt.hdr.is_on_up_path():
   //                  spkt.hdr.increase_of(2)
   //              next_hop.addr = (
   //                      this->ifid2addr[spkt.hdr.get_current_of().ingress_if])
   //              logging.debug("send() here, next: %s", next_hop)
   //              this->send(spkt, next_hop)
   //      else:
   //          logging.warning("Unknown case %u", info)
   //  }

   //  def forward_packet(self, spkt, next_hop, from_local_ad, ptype) {
   //      /*
   //       * Forward packet based on the current opaque field.
		 // * 
   //       * :param spkt: the SCION packet to forward.
   //       * :type spkt: :class:`lib.packet.scion.SCIONPacket`
   //       * :param next_hop: the next hop of the packet.
   //       * :type next_hop: :class:`NextHop`
   //       * :param from_local_ad: whether or not the packet is from the local AD.
   //       * :type from_local_ad: bool
   //       * :param ptype: the type of the packet.
   //       * :type ptype: :class:`lib.packet.scion.PacketType`
   //       */
   //      while not spkt.hdr.get_current_of().is_regular():
   //          spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p
   //          spkt.hdr.increase_of(1)

   //      while spkt.hdr.get_current_of().is_continue():
   //          spkt.hdr.increase_of(1)

   //      info = spkt.hdr.get_current_iof().info
   //      curr_iof_p = spkt.hdr.common_hdr.curr_iof_p
   //      # Case: peer path and first opaque field of a down path. We need to
   //      # increase opaque field pointer as that first opaque field is used for
   //      # MAC verification only.
   //      if (not spkt.hdr.is_on_up_path() and
   //          info in [OFT.INTRATD_PEER, OFT.INTERTD_PEER] and
   //          spkt.hdr.common_hdr.curr_of_p == curr_iof_p + OpaqueField.LEN):
   //          spkt.hdr.increase_of(1)

   //      # if spkt.hdr.get_current_of().is_xovr():
   //      if spkt.hdr.get_current_of().info == OFT.LAST_OF:
   //          this->crossover_forward(spkt, next_hop, from_local_ad, info)
   //      else:
   //          this->normal_forward(spkt, next_hop, from_local_ad, ptype)
   //  }

   //  def write_to_egress_iface(self, spkt, next_hop, from_local_ad) {
   //      /*
   //       * Forwards packet to neighboring router.
		 // * 
   //       * :param spkt: the SCION packet to forward.
   //       * :type spkt: :class:`lib.packet.scion.SCIONPacket`
   //       * :param next_hop: the next hop of the packet.
   //       * :type next_hop: :class:`NextHop`
   //       * :param from_local_ad: whether or not the packet is from the local AD.
   //       * :type from_local_ad: bool
   //       */
   //      if spkt.hdr.is_on_up_path():
   //          iface = spkt.hdr.get_current_of().ingress_if
   //      else:
   //          iface = spkt.hdr.get_current_of().egress_if

   //      info = spkt.hdr.get_current_iof().info
   //      spkt.hdr.increase_of(1)
   //      if info in [OFT.INTRATD_PEER, OFT.INTERTD_PEER]:
   //          of1_info = spkt.hdr.get_relative_of(1).info
   //          of2_info = spkt.hdr.get_current_of().info
   //          if ((of1_info in [OFT.INTRATD_PEER, OFT.INTERTD_PEER] and
   //               spkt.hdr.is_on_up_path()) or
   //              (of2_info == OFT.LAST_OF and not spkt.hdr.is_on_up_path())):
   //              spkt.hdr.increase_of(1)

   //      if this->interface.if_id != iface:  # TODO debug
   //          logging.error("0 interface mismatch %u != %u", iface,
   //                  this->interface.if_id)
   //          return

   //      next_hop.addr = this->interface.to_addr
   //      next_hop.port = this->interface.to_udp_port
   //      logging.debug("sending to dst6 %s", next_hop)
   //      this->send(spkt, next_hop, False)
   //  }

   //  def process_packet(self, spkt, next_hop, from_local_ad, ptype) {
   //      /* 
   //       * Inspects current opaque fields and decides on forwarding type.
		 // * 
   //       * :param spkt: the SCION packet to process.
   //       * :type spkt: :class:`lib.packet.scion.SCIONPacket`
   //       * :param next_hop: the next hop of the packet.
   //       * :type next_hop: :class:`NextHop`
   //       * :param from_local_ad: whether or not the packet is from the local AD.
   //       * :type from_local_ad: bool
   //       * :param ptype: the type of the packet.
   //       * :type ptype: :class:`lib.packet.scion.PacketType`
   //       */
   //      if (spkt.hdr.get_current_of() != spkt.hdr.path.get_of(0) and  # TODO PSz
   //          ptype == PT.DATA and from_local_ad):
   //          of_info = spkt.hdr.get_current_of().info
   //          if of_info == OFT.TDC_XOVR:
   //              spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p
   //              spkt.hdr.increase_of(1)
   //          elif of_info == OFT.NON_TDC_XOVR:
   //              spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p
   //              spkt.hdr.increase_of(2)
   //          this->write_to_egress_iface(spkt, next_hop, from_local_ad)
   //      else:
   //          this->forward_packet(spkt, next_hop, from_local_ad, ptype)
   //  }

   //  def handle_request(self, packet, sender, from_local_socket=True)  {
   //      /* 
   //       * Main routine to handle incoming SCION packets.
		 // * 
   //       * :param packet: the incoming packet to handle.
   //       * :type packet: SCIONPacket
   //       * :param sender:
   //       * :type sender:
   //       * :param from_local_socket: whether the request is coming from a local
   //       *     socket.
   //       * :type from_local_socket: bool
		 // * 
   //       * .. note::
   //       *     `sender` is not used in this function at the moment.
   //       */
   //      from_local_ad = from_local_socket
   //      spkt = SCIONPacket(packet)
   //      ptype = get_type(spkt)
   //      next_hop = NextHop()
   //      this->handle_extensions(spkt, next_hop, True)
   //      if ptype == PT.IFID_PKT and not from_local_ad:
   //          this->process_ifid_request(packet, next_hop)
   //      elif ptype == PT.BEACON:
   //          this->process_pcb(packet, next_hop, from_local_ad)
   //      elif ptype in [PT.CERT_CHAIN_REQ, PT.CERT_CHAIN_REP, PT.TRC_REQ,
   //                     PT.TRC_REP]:
   //          this->relay_cert_server_packet(spkt, next_hop, from_local_ad)
   //      else:
   //          if ptype == PT.DATA:
   //              logging.debug("DATA type %s, %s", ptype, spkt)
   //          this->process_packet(spkt, next_hop, from_local_ad, ptype)
   //  }
};

int main() {
    /*
     * Initializes and starts router.
     */
    init_logging();
    handle_signals();
    if len(sys.argv) != 4:
        logging.error("run: %s IP topo_file conf_file", sys.argv[0])
        sys.exit();

    router = Router(IPv4Address(sys.argv[1]), sys.argv[2], sys.argv[3]);

    logging.info("Started: %s", datetime.datetime.now());
    router.run();

    return 0;
}

// if __name__ == "__main__":
//     try:
//         main()
//     except SystemExit:
//         logging.info("Exiting")
//         raise
//     except:
//         log_exception("Exception in main process:")
//         logging.critical("Exiting")
//         sys.exit(1)
