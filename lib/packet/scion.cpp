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
    int curr_iof_p; // Pointer inside the packet to the current IOF.
    int curr_of_p; // Pointer to the current opaque field.
    int next_hdr; // Type of the next hdr field (IP protocol numbers).
    
public:
    static const int LEN = 8;
    uint32_t src_addr_len; // Length of the src address.
    uint32_t dst_addr_len; // Length of the dst address.
    uint32_t hdr_len; // Header length including the path.
    uint32_t total_len; // Total length of the packet.

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

    void parse(const std::string &raw) {
        /**
         * Parses the raw data and populates the fields accordingly.
         */
        int dlen = raw.length();
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

    std::string __str__() {
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
    SCIONHeader(const std::string &raw) : HeaderBase() {
        if (raw.length())
            parse(raw);
    }

    SCIONHeader(SCIONAddr src, SCIONAddr dst, PathBase path, 
                vector<ExtensionHeader> ext_hdrs, int next_hdr=0) {
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
            // logging.warning("Data too short to parse SCION header: "
                            // "data len %u", dlen)
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
            info = InfoOpaqueField(raw.substr(offset, 
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
            BitArray bits(raw.substr(offset, 2));
            next_hdr_type = bits.get_subarray(0, 8);
            hdr_len = bits.get_subarray(8, 8);
            // logging.info("Found extension hdr of type %u with len %u",
                         // cur_hdr_type, hdr_len)
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

    std::string __str__() {
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

#endif