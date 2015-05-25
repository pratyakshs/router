/*
 * Copyright 2014 ETH Zurich
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
/* :mod:`scion` --- SCION packets
 * ===========================================
 */

#include <vector>
#include <cstdlib>
#include "IPAddress.h"
#include "BitArray.h"
#include "ext_hdr.cpp"
#include "path.cpp"
#include "packet_base.cpp"
#include "scion_addr.cpp"

using namespace std;

class PacketType {
    /*
     * Defines constants for the SCION packet types.
     */
    static const int DATA = -1;  // Data packet
    static const IPv4Address BEACON ; // Path Construction Beacon
    static const IPv4Address PATH_MGMT;  // Path management packet from/to PS
    static const IPv4Address TRC_REQ; // TRC file request to parent AD
    static const IPv4Address TRC_REQ_LOCAL;  // TRC file request to lCS
    static const IPv4Address TRC_REP;  // TRC file reply from parent AD
    static const IPv4Address CERT_CHAIN_REQ;  // cert chain request to parent AD
    static const IPv4Address CERT_CHAIN_REQ_LOCAL;  // local cert chain request
    static const IPv4Address CERT_CHAIN_REP; // cert chain reply from lCS
    static const IPv4Address IFID_PKT; // IF ID packet to the peer router
    static const vector<IPv4Address> SRC;
    static const vector<IPv4Address> DST;
};

const IPv4Address PacketType::BEACON = IPv4Address("10.224.0.1");  // Path Construction Beacon
const IPv4Address PacketType::PATH_MGMT = IPv4Address("10.224.0.2");  // Path management packet from/to PS
const IPv4Address PacketType::TRC_REQ = IPv4Address("10.224.0.3");  // TRC file request to parent AD
const IPv4Address PacketType::TRC_REQ_LOCAL = IPv4Address("10.224.0.4");  // TRC file request to lCS
const IPv4Address PacketType::TRC_REP = IPv4Address("10.224.0.5");  // TRC file reply from parent AD
const IPv4Address PacketType::CERT_CHAIN_REQ = IPv4Address("10.224.0.6");  // cert chain request to parent AD
const IPv4Address PacketType::CERT_CHAIN_REQ_LOCAL = IPv4Address("10.224.0.7");  // local cert chain request
const IPv4Address PacketType::CERT_CHAIN_REP = IPv4Address("10.224.0.8");  // cert chain reply from lCS
const IPv4Address PacketType::IFID_PKT = IPv4Address("10.224.0.9");  // IF ID packet to the peer router
const vector<IPv4Address> PacketType::SRC = {BEACON, PATH_MGMT, CERT_CHAIN_REP, TRC_REP};
const vector<IPv4Address> PacketType::DST = {PATH_MGMT, TRC_REQ, TRC_REQ_LOCAL, CERT_CHAIN_REQ,
    CERT_CHAIN_REQ_LOCAL, IFID_PKT};

class SCIONCommonHdr : public HeaderBase {
    /* Encapsulates the common header for SCION packets.
     */
    static const LEN = 8;
    int version;
    uint32_t src_addr_len;
    uint32_t dst_addr_len;
    uint32_t total_len;
    int curr_iof_p;
    int curr_of_p;
    int next_hdr;
    uint32_t hdr_len;

    SCIONCommonHdr(char *raw) :  HeaderBase() {
        version = 0;  // Version of SCION packet.
        src_addr_len = 0;  // Length of the src address.
        dst_addr_len = 0;  // Length of the dst address.
        total_len = 0;  // Total length of the packet.
        curr_iof_p = 0;  // Pointer inside the packet to the current IOF.
        curr_of_p = 0;  // Pointer to the current opaque field.
        next_hdr = 0;  // Type of the next hdr field (IP protocol numbers).
        hdr_len = 0;  // Header length including the path.

        if (raw)
            parse(raw);
    }

    SCIONCommonHdr(uint32_t src_addr_len, uint32_t dst_addr_len, int next_hdr) {
        /**
         * Constructor for SCIONCommonHdr with the values specified.
         */
        this->src_addr_len = src_addr_len;
        this->dst_addr_len = dst_addr_len;
        this->next_hdr = next_hdr;
        this->curr_of_p = this->src_addr_len + this->dst_addr_len;
        this->curr_iof_p = this->curr_of_p;
        this->hdr_len = SCIONCommonHdr::LEN + src_addr_len + dst_addr_len;
        this->total_len = this->hdr_len;
    }

    void parse(char *raw) {
        /**
         * Parses the raw data and populates the fields accordingly.
         */
        int dlen = strlen(raw);
        if (dlen < SCIONCommonHdr::LEN) {
            // logging.warning("Data too short to parse SCION common header: "
            // "data len %u", dlen)
            return;
        }
        BitArray bits(raw);
        uint32_t types = bits.get_subarray(0, 16);
        total_len = bits.get_subarray(16, 16);
        curr_iof_p = bits.get_subarray(32, 8);
        curr_of_p = bits.get_subarray(40, 8);
        next_hdr = bits.get_subarray(48, 8);
        hdr_len = bits.get_subarray(56, 8);
        version = (types & 0xf000) >> 12;
        src_addr_len = (types & 0x0fc0) >> 6;
        dst_addr_len = types & 0x003f;
        parsed = true;
    }

    BitArray pack() {
        /**
         * Returns the common header as 8 byte binary string.
         */
        types = ((version << 12) | (dst_addr_len << 6) |
                src_addr_len);

        BitArray res;
        res.append(types, 16);
        res.append(total_len, 16);
        res.append(curr_iof_p, 8);
        res.append(curr_of_p, 8);
        res.append(next_hdr, 8);
        res.append(hdr_len, 8);
        return res;
    }

    string __str__() {
        cerr << "***UNIMPLEMENTED***" << endl;
        exit(-1);
        // res = ("[CH ver: %u, src len: %u, dst len: %u, total len: %u bytes, "
        //        "TS: %u, current OF: %u, next hdr: %u, hdr len: %u]") % (
        //            version, src_addr_len, dst_addr_len,
        //            total_len, curr_iof_p, curr_of_p,
        //            next_hdr, hdr_len)
        // return res
    }
};

class SCIONHeader : public HeaderBase {
    /**
     * The SCION packet header.
     */
    static const int MIN_LEN = 16;  // Update when values are fixed.
    SCIONCommonHdr common_hdr;
    SCIONAddr src_addr;
    SCIONAddr dst_addr;
    PathBase path;
    vector<ExtensionHeader> extension_hdrs;
    bool path_set;

public:
    SCIONHeader(char *raw) : HeaderBase() {
        if (raw)
            parse(raw);
    }

    SCIONHeader(SCIONAddr src, SCIONAddr dst, PathBase path, 
                vector<type> ext_hdrs, int next_hdr=0) {
        /**
         * Constructor with the values specified.
         */
        common_hdr = SCIONCommonHdr(src.addr_len, dst.addr_len,
                                    next_hdr);
        src_addr = src;
        dst_addr = dst;
        this->path = path;
        extension_hdrs = ext_hdrs;
        path_set = 1;
    }

    PathBase get_path() {
        /** 
         * Returns the path in the header.
         */
        return path;
    }

    void set_path(PathBase path) {
        /**
         * Sets path to 'path' and updates necessary fields..
         */
        if (path_set) {
            int path_len = path.pack() {:LENgth();
            common_hdr.hdr_len -= path_len;
            common_hdr.total_len -= path_len;
        }
        this->path = path;
        if path is not None:
            path_len = len(path.pack());
            common_hdr.hdr_len += path_len;
            common_hdr.total_len += path_len;
    }

    vector<ExtensionHeader> get_extension_hdrs() {
        /**
         * Returns the extension headers.
         */
        return extension_hdrs;
    }

    void set_ext_hdrs(vector<ExtensionHeader> ext_hdrs) {
        /**
         * Sets extension headers and updates necessary fields.
         */
        while _extension_hdrs:
            pop_ext_hdr()
        for ext_hdr in ext_hdrs:
            append_ext_hdr(ext_hdr)
    }

    void append_ext_hdr(ExtensionHeader ext_hdr) {
        /**
         * Appends an extension header and updates necessary fields.
         */
        extension_hdrs.push_back(ext_hdr);
        common_hdr.total_len += ext_hdr.__len__();
    }

    ExtensionHeader pop_ext_hdr() {
        /**
         * Pops and returns the last extension header and updates necessary fields.
         */
        if (extension_hdrs.empty())
            return ExtensionHeader();
        ExtensionHeader ext_hdr = extension_hdrs.back();
        extension_hdrs.pop_back();
        common_hdr.total_len -= ext_hdr.__len__();
        return ext_hdr;
    }

    void parse(char *raw) {
        /**
         * Parses the raw data and populates the fields accordingly.
         */
        int dlen = strlen(raw);
        if (dlen < SCIONHeader::MIN_LEN) {
            // logging.warning("Data too short to parse SCION header: "
                            // "data len %u", dlen)
            return;
        }
        int offset = 0;
        string raw_str(raw);
        common_hdr = SCIONCommonHdr(raw_str.substr(offset, 
                                    SCIONCommonHdr::LEN).c_str());
        offset += SCIONCommonHdr::LEN;
        assert(common_hdr.parsed); 
        // Create appropriate SCIONAddr objects.
        int src_addr_len = common_hdr.src_addr_len;
        src_addr = SCIONAddr(raw_str.substr(offset, src_addr_len).c_str());
        offset += src_addr_len;
        int dst_addr_len = common_hdr.dst_addr_len;
        dst_addr = SCIONAddr(raw_str.substr(offset, dst_addr_len).c_str());
        offset += dst_addr_len;
        // Parse opaque fields.
        // PSz: UpPath-only case missing, quick fix:
        if (offset == common_hdr.hdr_len)
            path = EmptyPath();
        else {
            info = InfoOpaqueField(raw_str.substr(offset, 
                                   InfoOpaqueField::LEN).c_str());
            if (info.info == OFT::TDC_XOVR)
                path = CorePath(raw_str.substr(offset, 
                                common_hdr.hdr_len).c_str());
            else if (info.info == OFT::NON_TDC_XOVR)
                path = CrossOverPath(raw_str.substr(offset, 
                                     common_hdr.hdr_len));
            else if (info.info == OFT::INTRATD_PEER
                     || info.info == OFT::INTERTD_PEER)
                path = PeerPath(raw_str.substr(offset, 
                                common_hdr.hdr_len).c_str());
            else{
                // logging.info("Can not parse path in packet: Unknown type %x",
                             // info.info)
            }
        }
        offset = common_hdr.hdr_len;
        // Parse extensions headers.
        // FIXME: The last extension header should be a layer 4 protocol header.
        // At the moment this is not support and we just indicate the end of the
        // extension headers by a 0 in the type field.
        int cur_hdr_type = common_hdr.next_hdr;
        while (cur_hdr_type != 0) {
            BitArray bits(raw_str.substr(offset, 2).c_str());
            next_hdr_type = bits.get_subarray(0, 8);
            hdr_len = bits.get_subarray(8, 8);
            // logging.info("Found extension hdr of type %u with len %u",
                         // cur_hdr_type, hdr_len)
            if (cur_hdr_type == ICNExtHdr::TYPE) 
                extension_hdrs.push_back(
                    ICNExtHdr(raw_str.substr(offset, hdr_len).c_str()));
            else
                extension_hdrs.push_back(
                    ExtensionHeader(raw_str.substr(offset, hdr_len).c_str()));
            cur_hdr_type = next_hdr_type;
            offset += hdr_len;
        }
        parsed = true;
    }

    BitArray pack() {
        /**
         * Packs the header and returns a byte array.
         */
        BitArray res = common_hdr.pack() + src_addr.pack() + dst_addr.pack();
        // if path is not None:
        if (true) // should check if path isn't empty
            res += path.pack();
        for (auto it = extension_hdrs.begin(); 
                it != extension_hdrs.end(); it++) {
            res += it->pack();
        }
        return res;
    }

    CommonOpaqueField* get_current_of() {
        /**
         * Returns the current opaque field as pointed by the current_of field in
         * the common_hdr.
         */
        if (false) // check if path is none
            return NULL;
        int offset = (common_hdr.curr_of_p - (common_hdr.src_addr_len +
                  common_hdr.dst_addr_len));
        return path.get_of(offset / OpaqueField::LEN);
    }

    CommonOpaqueField* get_current_iof() {
        /**
         * Returns the Info Opaque Field as pointed by the current_iof_p field in
         * the common_hdr.
         */
        if (false) // check if path is None
            return NULL;
        int offset = (common_hdr.curr_iof_p -
                  (common_hdr.src_addr_len + common_hdr.dst_addr_len));
        return path.get_of(offset / OpaqueField::LEN);
    }

    CommonOpaqueField* get_relative_of(int n) {
        /**
         * Returns (number_of_current_of + n)th opaque field. n may be negative.
         */
        if (false) // check if path is None
            return NULL;
        int offset = (common_hdr.curr_of_p - (common_hdr.src_addr_len +
                  common_hdr.dst_addr_len));
        return path.get_of(offset / OpaqueField::LEN + n);
    }

    CommonOpaqueField* get_next_of() {
        /*
         * Returns the opaque field after the one pointed by the current_of field
         * in the common hdr or 'None' if there exists no next opaque field.
         */
        if (false) // check if path is None
            return NULL;
        int offset = (common_hdr.curr_of_p - (common_hdr.src_addr_len +
                  common_hdr.dst_addr_len));
        return path.get_of(offset / OpaqueField::LEN + 1);
    }

    void increase_of(int number) {
        /**
         * Increases pointer of current opaque field by number of opaque fields.
         */
        common_hdr.curr_of_p += number * OpaqueField::LEN;
    }

    void set_downpath() {  // FIXME probably not needed
        /**
         * Sets down path flag.
         */
        CommonOpaqueField *iof = get_current_iof();
        if (iof)
            iof->up_flag = false;
    }

    bool is_on_up_path() {
        /**
         * Returns 'True' if the current opaque field should be interpreted as an
         * up-path opaque field and 'False' otherwise.
         *
         * 
         * Currently this is indicated by a bit in the LSB of the 'type' field in
         * the common header.
         */
        CommonOpaqueField *iof = get_current_iof();
        if (iof)
            return iof->up_flag;
        else
            return true;  // FIXME for now True for EmptyPath.
    }

    bool is_last_path_of() {
        /**
         * Returs 'True' if the current opaque field is the last opaque field,
         * 'False' otherwise.
         */
        int offset = (SCIONCommonHdr::LEN + OpaqueField::LEN);
        return common_hdr.curr_of_p + offset == common_hdr.hdr_len;
    }

    void reverse() {
        /**
         * Reverses the header.
         */
        SCIONAddr temp = src_addr;
        src_addr = dst_addr;
        dst_addr = temp;
        path.reverse();
        common_hdr.curr_of_p = (common_hdr.src_addr_len +
                                     common_hdr.dst_addr_len);
        common_hdr.curr_iof_p = common_hdr.curr_of_p;
    }

    int __len__() {
        int length = common_hdr.hdr_len;
        for (int i = 0; i < extension_hdrs.size(); i++) 
            length += extension_hdrs[i].__len__();
        return length;
    }

    string __str__() {
        // sh_list = []
        // sh_list.append(str(common_hdr) + "\n")
        // sh_list.append(str(src_addr) + " >> " + str(dst_addr) + "\n")
        // sh_list.append(str(path) + "\n")
        // for ext_hdr in extension_hdrs:
        //     sh_list.append(str(ext_hdr) + "\n")
        // return "".join(sh_list)
        cerr << "***UNIMPLEMENTED***" << endl;
        exit(-1);
        return "";
    }
};



class SCIONPacket : public PacketBase {
    /**
     * Class for creating and manipulation SCION packets.
     */
 public:
    static const int MIN_LEN = 8;
    int payload_len = 0;

    SCIONPacket(char *raw) : PacketBase() {
        payload_len = 0;
        if (raw)
            parse(raw);
    }

    SCIONPacket(SCIONAddr src, SCIONAddr dst, PacketBase *payload, PathBase path,
                    vector<ExtensionHeader> ext_hdrs, int next_hdr = 0, 
                    int pkt_type = PacketType::DATA) : PacketBase() {
        /**
         *  SCIONPacket constructor with the values specified.
         * :param src: Source address (must be a 'SCIONAddr' object)
         * :param dst: Destination address (must be a 'SCIONAddr' object)
         * :param payload: Payload of the packet (either 'bytes' or 'PacketBase')
         * :param path: The path for this packet.
         * :param ext_hdrs: A list of extension headers.
         * :param next_hdr: If 'ext_hdrs' is not None then this must be the type
         *                  of the first extension header in the list.
         * :param pkt_type: The type of the packet.
         */
        hdr = SCIONHeader(src, dst, path, ext_hdrs, next_hdr);
        payload = payload;
    }

    void set_payload(PacketBase *payload) {
        PacketBase.set_payload(payload);
        // Update payload_len and total len of the packet.
        hdr.common_hdr.total_len -= payload_len;
        payload_len = payload->__len__();
        hdr.common_hdr.total_len += payload_len;
    }

    void parse(char *raw) {
        /**
         * Parses the raw data and populates the fields accordingly.
         */
        int dlen = strlen(raw);
        this->raw = new char[dlen];
        strcpy(this->raw, raw);
        if (dlen < SCIONPacket::MIN_LEN) {
            // logging.warning("Data too short to parse SCION packet: "
                            // "data len %u", dlen)
            return;
        }
        hdr = SCIONHeader(raw);
        hdr_len = hdr.__len__();
        payload_len = dlen - hdr_len;
        payload = string(raw).substr(hdr_len).c_str();
        parsed = true;

        cerr << "***UNIMPLEMENTED***" << endl;
        exit(-1);
    }

    BitArray pack() {
        /**
         * Packs the header and the payload and returns a byte array.
         */
        return hdr.pack() + payload.pack();
        // if isinstance(self.payload, PacketBase) {
        //     data.append(self.payload.pack())
        // else:
        //     data.append(self.payload)
    }
};

class IFIDPacket : public SCIONPacket {
    /**
     * IFID packet.
     */
    int reply_id;
    int request_id;
public:
    IFIDPacket(char *raw) : SCIONPacket() {
        reply_id = 0;  // Always 0 for initial request.
        if (raw)
            parse(raw);
    }

    void parse(char *raw) {
        SCIONPacket::parse(raw);
        reply_id = (int(payload[1]) << 8) + int(payload[0]);
        request_id = (int(payload[3]) << 8) + int(payload[2]);
        ///? this assumes payload is a char array.
    }

    IFIDPacket(SCIONAddr src, pair<uint16_t, uint64_t> dst_isd_ad,
               int request_id) {
        /**
         * Returns a IFIDPacket with the values specified.
         * @param src: Source address (must be a 'SCIONAddr' object)
         * @param dst_isd_ad: Destination's 'ISD_AD' namedtuple.
         * @param request_id: interface number of src (neighboring router).
         */
        this->request_id = request_id;
        SCIONAddr dst(dst_isd_ad.first, dst_isd_ad.second, 
                      PacketType::IFID_PKT);
        SCIONHeader hdr(src, dst);
        payload = new char[4];
        payload[0] = reply_id & 0xFF;
        payload[1] = reply_id >> 8;
        payload[2] = request_id & 0xFF;
        payload[3] = request_id >> 8;
    }

    BitArray pack() {
        payload[0] = reply_id & 0xFF;
        payload[1] = reply_id >> 8;
        payload[2] = request_id & 0xFF;
        payload[3] = request_id >> 8;
        return SCIONPacket::pack();
    }
};

class CertChainRequest : public SCIONPacket {
    /**
     * Certificate Chain Request packet.
     * :ivar ingress_if: ingress interface where the beacon comes from.
     * :type ingress_if: int
     * :ivar src_isd: ISD identifier of the requester.
     * :type src_isd: int
     * :ivar src_ad: AD identifier of the requester.
     * :type src_ad: int
     * :ivar isd_id: Target certificate chain's ISD identifier.
     * :type isd_id: int
     * :ivar ad_id, ad: Target certificate chain's AD identifier.
     * :type ad_id: int
     * :ivar version: Target certificate chain's version.
     * :type version: int
     */
    int ingress_if;
    int src_isd;
    int src_ad;
    int isd_id;
    int ad_id;
    int version;
public:
    CertChainRequest(char* raw) : SCIONPacket() {
        /**
         * Initialize an instance of the class CertChainRequest.
         * :param raw: packed packet.
         * :type raw: bytes
         * :returns: the newly created CertChainRequest instance.
         * :rtype: :class:`CertChainRequest`
         */
        ingress_if = 0;
        src_isd = 0;
        src_ad = 0;
        isd_id = 0;
        ad_id = 0;
        version = 0;
        if (raw)
            parse(raw);
    }

    void parse(char *raw) {
        /**
         * Parse a string of bytes and populate the instance variables.
         * :param raw: packed packet.
         * :type raw: bytes
         */
        SCIONPacket::parse(raw);
        BitArray bits(payload);
        bits = BitArray(bytes=self.payload)
        ingress_if = bits.get_subarray(0, 16);
        src_isd = bits.get_subarray(16, 16);
        src_ad = bits.get_subarray(32, 64);
        isd_id = bits.get_subarray(96, 16);
        ad_id = bits.get_subarray(112, 64);
        version = bits.get_subarray(176, 32);
    }

    CertChainRequest(int req_type, SCIONAddr src, int ingress_if, int src_isd,
                     int  src_ad, int isd_id, int ad_id, 
                     int version) : SCIONPacket() {
        /**
         * Return a Certificate Chain Request with the values specified.
         * :param req_type: Either CERT_CHAIN_REQ_LOCAL (request comes from BS or
         *                  user) or CERT_CHAIN_REQ.
         * :type req_type: int
         * :param src: Source address.
         * :type src: :class:`SCIONAddr`
         * :param ingress_if: ingress interface where the beacon comes from.
         * :type ingress_if: int
         * :param src_isd: ISD identifier of the requester.
         * :type src_isd: int
         * :param src_ad: AD identifier of the requester.
         * :type src_ad: int
         * :param isd_id: Target certificate chain's ISD identifier.
         * :type isd_id: int
         * :param ad_id, ad: Target certificate chain's AD identifier.
         * :type ad_id: int
         * :param version: Target certificate chain's version.
         * :type version: int
         * :returns: the newly created CertChainRequest instance.
         * :rtype: :class:`CertChainRequest`
         */
        SCIONAddr dst(isd_id, src_ad, req_type);
        this->hdr = SCIONHeader(src, dst);
        this->ingress_if = ingress_if;
        this->src_isd = src_isd;
        this->src_ad = src_ad;
        this->isd_id = isd_id;
        this->ad_id = ad_id;
        this->version = version;
        BitArray bits;
        bits.append(ingress_if, 16);
        bits.append(src_isd, 16);
        bits.append(src_ad, 64);
        bits.append(isd_id, 16);
        bits.append(ad_id, 64);
        bits.append(version, 32);
        this->payload = bits.get_string().c_str();
    }
};

class CertChainReply : public SCIONPacket {
    /**
     * Certificate Chain Reply packet.
     * :cvar MIN_LEN: minimum length of the packet.
     * :type MIN_LEN: int
     * :ivar isd_id: Target certificate chain's ISD identifier.
     * :type isd_id: int
     * :ivar ad_id: Target certificate chain's AD identifier.
     * :type ad_id: int
     * :ivar version: Target certificate chain's version.
     * :type version: int
     * :ivar cert_chain: requested certificate chain's content.
     * :type cert_chain: bytes
     */
    int isd_id;
    uint64_t ad_id;
    int version;
    string cert_chain;
 public:
    static const int MIN_LEN = 14;

    CertChainReply(char *raw) : SCIONPacket() {
        /**
         * Initialize an instance of the class CertChainReply.
         * :param raw: packed packet.
         * :type raw: bytes
         * :returns: the newly created CertChainReply instance.
         * :rtype: :class:`CertChainReply`
         */
        isd_id = 0;
        ad_id = 0;
        version = 0;
        cert_chain = "";
        if (raw)
            parse(raw);
    }

    void parse(char *raw) {
        /**
         * Parse a string of bytes and populate the instance variables.
         * :param raw: packed packet.
         * :type raw: bytes
         */
        SCIONPacket::parse(raw);
        BitArray bits(payload);
        isd_id = bits.get_subarray(0, 16);
        ad_id = bits.get_subarray(16, 64);
        version = bits.get_subarray(80, 32);
        cert_chain = string(payload).substr(CertChainReply::MIN_LEN);
    }

    CertChainReply(SCIONAddr dst, int isd_id, uint64_t ad_id, 
                   int version, char *cert_chain) : SCIONPacket() {
        /**
         * Constructor for Certificate Chain Reply with the values specified.
         * :param dst: Destination address.
         * :type dst: :class:`SCIONAddr`
         * :param isd_id: Target certificate chain's ISD identifier.
         * :type isd_id: int
         * :param ad_id, ad: Target certificate chain's AD identifier.
         * :type ad_id: int
         * :param version: Target certificate chain's version.
         * :type version: int
         * :param cert_chain: requested certificate chain's content.
         * :type cert_chain: bytes
         */
        SCIONAddr src(isd_id, ad_id, PacketType::CERT_CHAIN_REP);
        hdr = SCIONHeader(src, dst);
        this->isd_id = isd_id
        this->ad_id = ad_id
        this->version = version
        this->cert_chain = string(cert_chain);
        BitArray bits;
        bits.append(isd_id, 16);
        bits.append(ad_id, 64);
        bits.append(version, 32);
        strcpy(payload, bits.get_string + string(cert_chain));
    }
};

class TRCRequest : public SCIONPacket {
    /**
     * TRC Request packet.
     * :ivar ingress_if: ingress interface where the beacon comes from.
     * :type ingress_if: int
     * :ivar src_isd: ISD identifier of the requester.
     * :type src_isd: int
     * :ivar src_ad: AD identifier of the requester.
     * :type src_ad: int
     * :ivar isd_id: Target TRC's ISD identifier.
     * :type isd_id: int
     * :ivar version: Target TRC's version.
     * :type version: int
     */
    int ingress_if;
    int src_isd;
    int src_ad;
    int isd_id;
    int version;
public:
    TRCRequest(char *raw) : SCIONPacket() {
        /**
         * Initialize an instance of the class TRCRequest.
         * :param raw: packed packet.
         * :type raw: bytes
         */
    }
};

