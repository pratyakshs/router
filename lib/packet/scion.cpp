/*
 * Copyright 2014 ETH Zurich
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, sOpaqueFieldTypeware
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/* :mod:`scion` --- SCION packets
 * ===========================================
 */
#ifndef SCION_CPP
#define SCION_CPP

#include <vector>
#include <cstdlib>
#include <iomanip>
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
 public:
    static const IPv4Address DATA;  // Data packet
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

const IPv4Address PacketType::DATA = IPv4Address("0.0.0.0");
const IPv4Address PacketType::BEACON = IPv4Address("10.224.0.1");
const IPv4Address PacketType::PATH_MGMT = IPv4Address("10.224.0.2");
const IPv4Address PacketType::TRC_REQ = IPv4Address("10.224.0.3");
const IPv4Address PacketType::TRC_REQ_LOCAL = IPv4Address("10.224.0.4");
const IPv4Address PacketType::TRC_REP = IPv4Address("10.224.0.5");
const IPv4Address PacketType::CERT_CHAIN_REQ = IPv4Address("10.224.0.6");
const IPv4Address PacketType::CERT_CHAIN_REQ_LOCAL = IPv4Address("10.224.0.7");
const IPv4Address PacketType::CERT_CHAIN_REP = IPv4Address("10.224.0.8");
const IPv4Address PacketType::IFID_PKT = IPv4Address("10.224.0.9");
const vector<IPv4Address> PacketType::SRC = {BEACON, PATH_MGMT, 
                                             CERT_CHAIN_REP, TRC_REP};
const vector<IPv4Address> PacketType::DST = {PATH_MGMT, TRC_REQ, 
                                             TRC_REQ_LOCAL, CERT_CHAIN_REQ,
                                             CERT_CHAIN_REQ_LOCAL, IFID_PKT};

class SCIONCommonHdr : public HeaderBase {
    /* Encapsulates the common header for SCION packets.
     */
    int version; // Version of SCION packet.
    
public:
    static const int LEN = 8;
    int next_hdr; // Type of the next hdr field (IP protocol numbers).
    uint32_t src_addr_len; // Length of the src address.
    uint32_t dst_addr_len; // Length of the dst address.
    uint32_t hdr_len; // Header length including the path.
    uint32_t total_len; // Total length of the packet.
    int curr_iof_p; // Pointer inside the packet to the current IOF.
    int curr_of_p; // Pointer to the current opaque field.

    SCIONCommonHdr() : HeaderBase() {
        version = 0;
        src_addr_len = 0;
        dst_addr_len = 0;
        total_len = 0;
        curr_iof_p = 0;
        curr_of_p = 0;
        next_hdr = 0;
        hdr_len = 0;
    }

    SCIONCommonHdr(const std::string &raw) :  HeaderBase() {
        version = 0;
        src_addr_len = 0;
        dst_addr_len = 0;
        total_len = 0;
        curr_iof_p = 0;
        curr_of_p = 0;
        next_hdr = 0;
        hdr_len = 0;
        if (raw.length())
            parse(raw);
    }

    SCIONCommonHdr(const uint32_t &src_addr_len, const uint32_t &dst_addr_len, 
                   const int &next_hdr) : HeaderBase() {
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

    void parse(const std::string &raw) {
        /**
         * Parses the raw data and populates the fields accordingly.
         */
        int dlen = raw.length();
        if (dlen < SCIONCommonHdr::LEN) {
            LOG(WARNING) 
              << "Data too short to parse SCION common header: data len " 
              << dlen;
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

    BitArray pack() const {
        /**
         * Returns the common header as 8 byte binary string.
         */
        uint64_t types = ((version << 12) | (dst_addr_len << 6) |
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

    std::string to_string() {
        return "[CH ver: " + std::to_string(version) + ", src len: "
                + std::to_string(src_addr_len) + ", dst len: " 
                + std::to_string(dst_addr_len) + ", total len: " 
                + std::to_string(total_len) + " bytes, "
                + "TS: " + std::to_string(curr_iof_p) + ", current OF: " 
                + std::to_string(curr_of_p) + ", next hdr: " 
                + std::to_string(next_hdr) + ", hdr len: " 
                + std::to_string(hdr_len) + "]";
    }
};

class SCIONHeader : public HeaderBase {
    /**
     * The SCION packet header.
     */
public:
    PathBase path;
    SCIONAddr dst_addr;
    static const int MIN_LEN = 16;  // Update when values are fixed.
    SCIONAddr src_addr;
    vector<ExtensionHeader> extension_hdrs;
    bool path_set;

    SCIONCommonHdr common_hdr;

    SCIONHeader() {
        SCIONHeader("");
    }

    SCIONHeader(const std::string &raw) : HeaderBase() {
        if (raw.length())
            parse(raw);
    }

    SCIONHeader(const SCIONAddr &src, const SCIONAddr &dst, 
                const PathBase &path, const vector<ExtensionHeader> &ext_hdrs, 
                int next_hdr=0) : HeaderBase() {
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

    SCIONHeader(const SCIONAddr &src, const SCIONAddr &dst) : HeaderBase() {
        /**
         * Constructor with the values specified.
         */
        common_hdr = SCIONCommonHdr(src.addr_len, dst.addr_len, 0);
        src_addr = src;
        dst_addr = dst;
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
            int path_len = path.pack().length();
            common_hdr.hdr_len -= path_len;
            common_hdr.total_len -= path_len;
        }
        this->path = path;
        if (true) {// check if path is not none
            int path_len = path.pack().length();
            common_hdr.hdr_len += path_len;
            common_hdr.total_len += path_len;
        }
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
        ///? can use std::vector::clear() too!
        while (!extension_hdrs.empty())
            pop_ext_hdr();
        for (int i = 0; i < ext_hdrs.size(); i++)
            append_ext_hdr(ext_hdrs[i]);
    }

    void append_ext_hdr(ExtensionHeader ext_hdr) {
        /**
         * Appends an extension header and updates necessary fields.
         */
        extension_hdrs.push_back(ext_hdr);
        common_hdr.total_len += ext_hdr.length();
    }

    ExtensionHeader pop_ext_hdr() {
        /**
         * Pops and returns the last extension header and 
         * updates necessary fields.
         */
        if (extension_hdrs.empty())
            return ExtensionHeader();
        ExtensionHeader ext_hdr = extension_hdrs.back();
        extension_hdrs.pop_back();
        common_hdr.total_len -= ext_hdr.length();
        return ext_hdr;
    }

    void parse(const std::string &raw) {
        /**
         * Parses the raw data and populates the fields accordingly.
         */
        int dlen = raw.length();
        if (dlen < SCIONHeader::MIN_LEN) {
            LOG(WARNING) << "Data too short to parse SCION header: data len "
                         << dlen;
            return;
        }
        int offset = 0;
        common_hdr = SCIONCommonHdr(raw.substr(offset, SCIONCommonHdr::LEN));
        offset += SCIONCommonHdr::LEN;
        assert(common_hdr.parsed); 
        // Create appropriate SCIONAddr objects.
        int src_addr_len = common_hdr.src_addr_len;
        src_addr = SCIONAddr(raw.substr(offset, src_addr_len));
        offset += src_addr_len;
        int dst_addr_len = common_hdr.dst_addr_len;
        dst_addr = SCIONAddr(raw.substr(offset, dst_addr_len));
        offset += dst_addr_len;
        // Parse opaque fields.
        // PSz: UpPath-only case missing, quick fix:
        if (offset == common_hdr.hdr_len)
            path = EmptyPath();
        else {
            InfoOpaqueField info(raw.substr(offset, 
                                   InfoOpaqueField::LEN));
            if (info.info == OpaqueFieldType::TDC_XOVR)
                path = CorePath(raw.substr(offset, 
                                common_hdr.hdr_len));
            else if (info.info == OpaqueFieldType::NON_TDC_XOVR)
                path = CrossOverPath(raw.substr(offset, 
                                     common_hdr.hdr_len));
            else if (info.info == OpaqueFieldType::INTRATD_PEER
                     || info.info == OpaqueFieldType::INTERTD_PEER)
                path = PeerPath(raw.substr(offset, 
                                common_hdr.hdr_len));
            else{
                LOG(INFO) << "Can not parse path in packet: Unknown type "
                          << std::hex << info.info << std::dec;
            }
        }
        offset = common_hdr.hdr_len;
        // Parse extensions headers.
        // FIXME: The last extension header should be a layer 4 protocol header.
        // At the moment this is not support and we just indicate the end of the
        // extension headers by a 0 in the type field.
        int cur_hdr_type = common_hdr.next_hdr;
        while (cur_hdr_type != 0) {
            BitArray bits(raw.substr(offset, 2));
            int next_hdr_type = bits.get_subarray(0, 8);
            int hdr_len = bits.get_subarray(8, 8);
            LOG(INFO) << "Found extension hdr of type " << cur_hdr_type 
                          << " with len " << hdr_len;
            if (cur_hdr_type == ICNExtHdr::TYPE) 
                extension_hdrs.push_back(
                    ICNExtHdr(raw.substr(offset, hdr_len)));
            else
                extension_hdrs.push_back(
                    ExtensionHeader(raw.substr(offset, hdr_len)));
            cur_hdr_type = next_hdr_type;
            offset += hdr_len;
        }
        parsed = true;
    }

    BitArray pack() const {
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
         * Returns the current opaque field as pointed by the 
         * current_of field in the common_hdr.
         */
        if (false) // check if path is none
            return NULL;
        int offset = (common_hdr.curr_of_p - (common_hdr.src_addr_len +
                  common_hdr.dst_addr_len));
        return path.get_of(offset / OpaqueField::LEN);
    }

    CommonOpaqueField* get_current_iof() {
        /**
         * Returns the Info Opaque Field as pointed by the current_iof_p
         *  field in the common_hdr.
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
         * Returns the opaque field after the one pointed by the current_of 
         * field in the common hdr or 'None' if there exists no next
         * opaque field.
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
         * Returns 'True' if the current opaque field should be interpreted as 
         * an up-path opaque field and 'False' otherwise.
         *
         * 
         * Currently this is indicated by a bit in the LSB of the 'type' field 
         * in the common header.
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

    bool is_first_path_of() {
        /**
         * Returs 'True' if the current opaque field is the very first opaque field
         * (i.e., InfoOpaqueField), 'False' otherwise.
         */
        return common_hdr.curr_of_p == (common_hdr.src_addr_len +
                                             common_hdr.dst_addr_len);
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

    int length() {
        int length = common_hdr.hdr_len;
        for (int i = 0; i < extension_hdrs.size(); i++) 
            length += extension_hdrs[i].length();
        return length;
    }

    std::string to_string() {
        std::string res = common_hdr.to_string() + "\n" + src_addr.to_string() 
                            + " >> " + dst_addr.to_string() + "\n"
                            + path.to_string() + "\n";
        for (int i = 0; i < extension_hdrs.size(); i++) 
            res += extension_hdrs[i].to_string() + "\n";
        return res;
    }
};

class SCIONPacket : public PacketBase {
    /**
     * Class for creating and manipulation SCION packets.
     */
public:
    static const int MIN_LEN = 8;
    int payload_len;
    SCIONHeader hdr;

    SCIONPacket() {
        SCIONPacket("");
    }

    SCIONPacket(const std::string &raw) : PacketBase() {
        payload_len = 0;
        if (raw.length())
            parse(raw);
    }

    SCIONPacket(const SCIONAddr &src, const SCIONAddr &dst, 
                const std::string &payload, PathBase path,
                vector<ExtensionHeader> &ext_hdrs, int next_hdr=0, 
                IPv4Address pkt_type=PacketType::DATA) : PacketBase() {
        /**
         * Returns a SCIONPacket with the values specified.
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
        this->payload = payload;
    }

    void set_payload(const std::string &payload) {
        PacketBase::set_payload(payload);
        // Update payload_len and total len of the packet.
        hdr.common_hdr.total_len -= payload_len;
        payload_len = payload.length();
        hdr.common_hdr.total_len += payload_len;
    }

    void parse(const std::string &raw) {
        /**
         * Parses the raw data and populates the fields accordingly.
         */
        int dlen = raw.length();
        this->raw = raw;
        if (dlen < SCIONPacket::MIN_LEN) {
            LOG(WARNING) 
              << "Data too short to parse SCION packet: data len " << dlen;
            return;
        }
        hdr = SCIONHeader(raw);
        int hdr_len = hdr.length();
        payload_len = dlen - hdr_len;
        payload = raw.substr(hdr_len);
        parsed = true;
    }

    BitArray pack() const {
        /**
         * Packs the header and the payload and returns a byte array.
         */
        BitArray res = hdr.pack();
        res += BitArray(payload);
        return res;
    }
};

class IFIDPacket : public SCIONPacket {
    /**
     * IFID packet.
     */
public:
    int reply_id;
    int request_id;

    IFIDPacket(const std::string &raw) : SCIONPacket() {
        reply_id = 0;  // Always 0 for initial request.
        request_id = 0;
        if (raw.length())
            parse(raw);
    }

    void parse(const std::string &raw) {
        SCIONPacket::parse(raw);
        reply_id = (payload[0] << 8) | payload[1];
        request_id = (payload[2] << 8) | payload[3];
    }

    IFIDPacket(SCIONAddr src, std::pair<uint16_t, uint64_t> dst_isd_ad,
               int request_id) : SCIONPacket() {
        /**
         * Returns a IFIDPacket with the values specified.
         * @param src: Source address (must be a 'SCIONAddr' object)
         * @param dst_isd_ad: Destination's 'ISD_AD' namedtuple.
         * @param request_id: interface number of src (neighboring router).
         */
        this->request_id = request_id;
        SCIONAddr dst(dst_isd_ad.first, dst_isd_ad.second,
                      &PacketType::IFID_PKT);
        hdr = SCIONHeader(src, dst, PathBase(), std::vector<ExtensionHeader>());
        payload = "";
        payload.push_back(reply_id >> 8);
        payload.push_back(reply_id & 0xFF);
        payload.push_back(request_id >> 8);
        payload.push_back(request_id & 0xFF);
    }

    BitArray pack() {
        payload = "";
        payload.push_back(reply_id >> 8);
        payload.push_back(reply_id & 0xFF);
        payload.push_back(request_id >> 8);
        payload.push_back(request_id & 0xFF);
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
public:
    int ingress_if;
    int src_isd;
    int src_ad;
    int isd_id;
    int ad_id;
    int version;

    CertChainRequest(const std::string &raw) : SCIONPacket() {
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
        if (raw.length())
            parse(raw);
    }

    void parse(const std::string &raw) {
        /**
         * Parse a string of bytes and populate the instance variables.
         * :param raw: packed packet.
         * :type raw: bytes
         */
        SCIONPacket::parse(raw);
        BitArray bits(payload);
        ingress_if = bits.get_subarray(0, 16);
        src_isd = bits.get_subarray(16, 16);
        src_ad = bits.get_subarray(32, 64);
        isd_id = bits.get_subarray(96, 16);
        ad_id = bits.get_subarray(112, 64);
        version = bits.get_subarray(176, 32);
    }

    CertChainRequest(IPv4Address* req_type, SCIONAddr src, uint16_t ingress_if, 
                     uint16_t src_isd, uint64_t src_ad, uint16_t isd_id,
                     uint64_t ad_id, uint32_t version) : SCIONPacket() {
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
        this->hdr = SCIONHeader(src, dst, PathBase(), 
                                std::vector<ExtensionHeader>());
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
        payload = bits.to_string();
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
 public:
    static const int MIN_LEN = 14;
    uint16_t isd_id;
    uint64_t ad_id;
    uint32_t version;
    std::string cert_chain;

    CertChainReply() {
        CertChainReply("");
    }

    CertChainReply(const std::string &raw) : SCIONPacket() {
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
        if (raw.length())
            parse(raw);
    }

    void parse(const std::string &raw) {
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
        cert_chain = payload.substr(CertChainReply::MIN_LEN);
    }

    CertChainReply(SCIONAddr dst, uint16_t isd_id, uint64_t ad_id, 
                   uint32_t version, std::string cert_chain) {
        /**
         * Return a Certificate Chain Reply with the values specified.
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
         * :returns: the newly created CertChainReply instance.
         * :rtype: :class:`CertChainReply`
         */
        SCIONAddr src(isd_id, ad_id, &PacketType::CERT_CHAIN_REP);
        hdr = SCIONHeader(src, dst, PathBase(), std::vector<ExtensionHeader>());
        this->isd_id = isd_id;
        this->ad_id = ad_id;
        this->version = version;
        this->cert_chain = cert_chain;
        BitArray bits;
        bits.append(isd_id, 16);
        bits.append(ad_id, 64);
        bits.append(version, 32);
        payload = bits.to_string();
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
public:
    uint16_t ingress_if;
    uint16_t src_isd;
    uint64_t src_ad;
    uint16_t isd_id;
    uint32_t version;

    TRCRequest(const std::string &raw) : SCIONPacket() {
        /**
         * Initialize an instance of the class TRCRequest.
         * :param raw: packed packet.
         * :type raw: bytes
         * :returns: the newly created TRCRequest instance.
         * :rtype: :class:`TRCRequest`
         */
        ingress_if = 0;
        src_isd = 0;
        src_ad = 0;
        isd_id = 0;
        version = 0;
        if (raw.length())
            parse(raw);
    }

    void parse(const std::string &raw) {
        /**
         * Parse a string of bytes and populate the instance variables.
         * :param raw: packed packet.
         * :type raw: bytes
         */
        SCIONPacket::parse(raw);
        BitArray bits(payload);
        ingress_if = bits.get_subarray(0, 16);
        src_isd = bits.get_subarray(16, 16);
        src_ad = bits.get_subarray(32, 64);
        isd_id = bits.get_subarray(96, 16);
        version = bits.get_subarray(112, 32);
    }

    TRCRequest(IPv4Address* req_type, SCIONAddr src, uint16_t ingress_if, 
               uint16_t src_isd, uint64_t src_ad, uint16_t isd_id,
               uint32_t version) : SCIONPacket() {
        /**
         * Return a TRC Request with the values specified.
         * :param req_type: Either TRC_REQ_LOCAL (request comes from BS or user)
         *                  or TRC_REQ.
         * :type req_type: int
         * :param src: Source address.
         * :type src: :class:`SCIONAddr`
         * :param ingress_if: ingress interface where the beacon comes from.
         * :type ingress_if: int
         * :param src_isd: ISD identifier of the requester.
         * :type src_isd: int
         * :param src_ad: AD identifier of the requester.
         * :type src_ad: int
         * :param isd_id: Target TRC's ISD identifier.
         * :type isd_id: int
         * :param version: Target TRC's version.
         * :type version: int
         * :returns: the newly created TRCRequest instance.
         * :rtype: :class:`TRCRequest`
         */
        SCIONAddr dst(isd_id, src_ad, req_type);
        hdr = SCIONHeader(src, dst, PathBase(), std::vector<ExtensionHeader>());
        this->ingress_if = ingress_if;
        this->src_isd = src_isd;
        this->src_ad = src_ad;
        this->isd_id = isd_id;
        this->version = version;
        BitArray bits;
        bits.append(ingress_if, 16);
        bits.append(src_isd, 16);
        bits.append(src_ad, 64);
        bits.append(isd_id, 16);
        bits.append(version, 32);
        payload = bits.to_string();
    }
};

class TRCReply : public SCIONPacket {
    /**
     * TRC Reply packet.
     * :cvar MIN_LEN: minimum length of the packet.
     * :type MIN_LEN: int
     * :ivar isd_id: Target TRC's ISD identifier.
     * :type isd_id: int
     * :ivar version: Target TRC's version.
     * :type version: int
     * :ivar trc: requested TRC's content.
     * :type trc: bytes
     */
public:
    static const int MIN_LEN = 6;
    uint16_t isd_id;
    uint32_t version;
    std::string trc;

    TRCReply(const std::string &raw) : SCIONPacket() {
        /**
         * Initialize an instance of the class TRCReply.
         * :param raw: packed packet.
         * :type raw: bytes
         * :returns: the newly created TRCReply instance.
         * :rtype: :class:`TRCReply`
         */
        isd_id = 0;
        version = 0;
        trc = "";
        if (raw.length())
            parse(raw);
    }

    void parse(const std::string &raw) {
        /**
         * Parse a string of bytes and populate the instance variables.
         * :param raw: packed packet.
         * :type raw: bytes
         */
        SCIONPacket::parse(raw);
        BitArray bits(payload);
        isd_id = bits.get_subarray(0, 16);
        version = bits.get_subarray(16, 32);
        trc = payload.substr(TRCReply::MIN_LEN);
    }

    TRCReply(SCIONAddr dst, uint16_t isd_id, uint32_t version, 
             std::string trc) : SCIONPacket() {
        /**
         * Return a TRC Reply with the values specified.
         * :param dst: Destination address.
         * :type dst: :class:`SCIONAddr`
         * :param isd_id: Target TRC's ISD identifier.
         * :type isd_id: int
         * :param version: Target TRC's version.
         * :type version: int
         * :param trc: requested TRC's content.
         * :type trc: bytes
         * :returns: the newly created TRCReply instance.
         * :rtype: :class:`TRCReply`
         */
        // TODO: revise TRC/Cert request/replies
        SCIONAddr src(dst.isd_id, dst.ad_id, &PacketType::TRC_REP);
        hdr = SCIONHeader(src, dst, PathBase(), std::vector<ExtensionHeader>());
        this->isd_id = isd_id;
        this->version = version;
        this->trc = trc;
        BitArray bits;
        bits.append(isd_id, 16);
        bits.append(version, 32);
        payload = bits.to_string() + trc;
    }
};

IPv4Address get_type(SCIONPacket pkt) {
    /* Return the packet type; used for dispatching.
     *
     * :param pkt: the packet.
     * :type pkt: SCIONPacket
     * :returns: the packet type.
     * :rtype: IPv4Address
     */
    IPv4Address src_addr = *((IPv4Address *)(pkt.hdr.src_addr.host_addr));
    for(auto it = PacketType::SRC.begin(); it != PacketType::SRC.end(); it++) {
        if (*it == src_addr) 
            return src_addr;
    }

    IPv4Address dst_addr = *((IPv4Address *)(pkt.hdr.dst_addr.host_addr));
    for(auto it = PacketType::DST.begin(); it != PacketType::DST.end(); it++) {
        if (*it == dst_addr) 
            return dst_addr;
    }
    return IPv4Address("0.0.0.0");
}

#endif // SCION_CPP
