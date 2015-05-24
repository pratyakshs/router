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

// Stdlib
// import logging
// import struct
// from ipaddress import IPv4Address

// // External packages
// import bitstring
// from bitstring import BitArray

// // SCION
// from lib.packet.ext_hdr import ExtensionHeader, ICNExtHdr
// from lib.packet.opaque_field import (
//     InfoOpaqueField,
//     OpaqueField,
//     OpaqueFieldType as OFT,
// )
// from lib.packet.packet_base import HeaderBase, PacketBase
// from lib.packet.path import (
//     CorePath,
//     CrossOverPath,
//     EmptyPath,
//     PathBase,
//     PeerPath,
// )
// from lib.packet.scion_addr import SCIONAddr

#include <vector>
#include <cstdlib>
#include "IPAddress.h"
#include "BitArray.h"
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


IPv4Address get_type(SCIONPacket pkt) {
    /* Return the packet type; used for dispatching.
     *
     * :param pkt: the packet.
     * :type pkt: SCIONPacket
     * :returns: the packet type.
     * :rtype: IPv4Address
     */
    IPv4Address src_addr = *(pkt.get_hdr().src_addr.host_addr);
    for(auto it = PacketType::SRC.begin(); it != PacketType::SRC.end(); it++) {
        if (*it == src_addr) 
            return src_addr;
    }


    IPv4Address dst_addr = *(pkt.get_hdr().dst_addr.host_addr);
    for(auto it = PacketType::DST.begin(); it != PacketType::DST.end(); it++) {
        if (*it == dst_addr) 
            return dst_addr;
    }
    return IPv4Address("0.0.0.0");
}


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
        this->hdr_len = SCIONCommonHdr.LEN + src_addr_len + dst_addr_len;
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

    BitArray pack(self) {
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
        //            self.version, self.src_addr_len, self.dst_addr_len,
        //            self.total_len, self.curr_iof_p, self.curr_of_p,
        //            self.next_hdr, self.hdr_len)
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
    vector<type> extension_hdrs;
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
            int path_len = path.pack().length();
            common_hdr.hdr_len -= path_len;
            common_hdr.total_len -= path_len;
        }
        this->path = path;
        if path is not None:
            path_len = len(path.pack());
            common_hdr.hdr_len += path_len;
            common_hdr.total_len += path_len;
    }

    vector<> get_extension_hdrs() {
        /**
         * Returns the extension headers.
         */
        return extension_hdrs;
    }

    @extension_hdrs.setter
    def extension_hdrs(self, ext_hdrs):
        """
        Sets extension headers.
        """
        self.set_ext_hdrs(ext_hdrs)

    def set_ext_hdrs(self, ext_hdrs):
        """
        Sets extension headers and updates necessary fields.
        """
        assert isinstance(ext_hdrs, list)
        while self._extension_hdrs:
            self.pop_ext_hdr()
        for ext_hdr in ext_hdrs:
            self.append_ext_hdr(ext_hdr)

    def append_ext_hdr(self, ext_hdr):
        """
        Appends an extension header and updates necessary fields.
        """
        assert isinstance(ext_hdr, ExtensionHeader)
        self._extension_hdrs.append(ext_hdr)
        self.common_hdr.total_len += len(ext_hdr)

    def pop_ext_hdr(self):
        """
        Pops and returns the last extension header and updates necessary fields.
        """
        if not self._extension_hdrs:
            return
        ext_hdr = self._extension_hdrs.pop()
        self.common_hdr.total_len -= len(ext_hdr)
        return ext_hdr

    def parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < SCIONHeader.MIN_LEN:
            logging.warning("Data too short to parse SCION header: "
                            "data len %u", dlen)
            return
        offset = 0
        self.common_hdr = \
            SCIONCommonHdr(raw[offset:offset + SCIONCommonHdr.LEN])
        offset += SCIONCommonHdr.LEN
        assert self.common_hdr.parsed
        // Create appropriate SCIONAddr objects.
        src_addr_len = self.common_hdr.src_addr_len
        self.src_addr = SCIONAddr(raw[offset:offset + src_addr_len])
        offset += src_addr_len
        dst_addr_len = self.common_hdr.dst_addr_len
        self.dst_addr = SCIONAddr(raw[offset:offset + dst_addr_len])
        offset += dst_addr_len
        // Parse opaque fields.
        // PSz: UpPath-only case missing, quick fix:
        if offset == self.common_hdr.hdr_len:
            self._path = EmptyPath()
        else:
            info = InfoOpaqueField(raw[offset:offset + InfoOpaqueField.LEN])
            if info.info == OFT.TDC_XOVR:
                self._path = CorePath(raw[offset:self.common_hdr.hdr_len])
            elif info.info == OFT.NON_TDC_XOVR:
                self._path = CrossOverPath(raw[offset:self.common_hdr.hdr_len])
            elif info.info == OFT.INTRATD_PEER or info.info == OFT.INTERTD_PEER:
                self._path = PeerPath(raw[offset:self.common_hdr.hdr_len])
            else:
                logging.info("Can not parse path in packet: Unknown type %x",
                             info.info)
        offset = self.common_hdr.hdr_len
        // Parse extensions headers.
        // FIXME: The last extension header should be a layer 4 protocol header.
        // At the moment this is not support and we just indicate the end of the
        // extension headers by a 0 in the type field.
        cur_hdr_type = self.common_hdr.next_hdr
        while cur_hdr_type != 0:
            bits = BitArray(raw[offset: offset + 2])
            (next_hdr_type, hdr_len) = bits.unpack("uintbe:8, uintbe:8")
            logging.info("Found extension hdr of type %u with len %u",
                         cur_hdr_type, hdr_len)
            if cur_hdr_type == ICNExtHdr.TYPE:
                self.extension_hdrs.append(
                    ICNExtHdr(raw[offset:offset + hdr_len]))
            else:
                self.extension_hdrs.append(
                    ExtensionHeader(raw[offset:offset + hdr_len]))
            cur_hdr_type = next_hdr_type
            offset += hdr_len
        self.parsed = True

    def pack(self):
        """
        Packs the header and returns a byte array.
        """
        data = []
        data.append(self.common_hdr.pack())
        data.append(self.src_addr.pack())
        data.append(self.dst_addr.pack())
        if self.path is not None:
            data.append(self.path.pack())
        for ext_hdr in self.extension_hdrs:
            data.append(ext_hdr.pack())
        return b"".join(data)

    def get_current_of(self):
        """
        Returns the current opaque field as pointed by the current_of field in
        the common_hdr.
        """
        if self.path is None:
            return None
        offset = (self.common_hdr.curr_of_p - (self.common_hdr.src_addr_len +
                  self.common_hdr.dst_addr_len))
        return self.path.get_of(offset // OpaqueField.LEN)

    def get_current_iof(self):
        """
        Returns the Info Opaque Field as pointed by the current_iof_p field in
        the common_hdr.
        """
        if self.path is None:
            return None
        offset = (self.common_hdr.curr_iof_p -
                  (self.common_hdr.src_addr_len + self.common_hdr.dst_addr_len))
        return self.path.get_of(offset // OpaqueField.LEN)

    def get_relative_of(self, n):
        """
        Returns (number_of_current_of + n)th opaque field. n may be negative.
        """
        if self.path is None:
            return None
        offset = (self.common_hdr.curr_of_p - (self.common_hdr.src_addr_len +
                  self.common_hdr.dst_addr_len))
        return self.path.get_of(offset // OpaqueField.LEN + n)

    def get_next_of(self):
        """
        Returns the opaque field after the one pointed by the current_of field
        in the common hdr or 'None' if there exists no next opaque field.
        """
        if self.path is None:
            return None
        offset = (self.common_hdr.curr_of_p - (self.common_hdr.src_addr_len +
                  self.common_hdr.dst_addr_len))
        return self.path.get_of(offset // OpaqueField.LEN + 1)

    def increase_of(self, number):
        """
        Increases pointer of current opaque field by number of opaque fields.
        """
        self.common_hdr.curr_of_p += number * OpaqueField.LEN

    def set_downpath(self):  // FIXME probably not needed
        """
        Sets down path flag.
        """
        iof = self.get_current_iof()
        if iof is not None:
            iof.up_flag = False

    def is_on_up_path(self):
        """
        Returns 'True' if the current opaque field should be interpreted as an
        up-path opaque field and 'False' otherwise.

        Currently this is indicated by a bit in the LSB of the 'type' field in
        the common header.
        """
        iof = self.get_current_iof()
        if iof is not None:
            return iof.up_flag
        else:
            True  // FIXME for now True for EmptyPath.

    def is_last_path_of(self):
        """
        Returs 'True' if the current opaque field is the last opaque field,
        'False' otherwise.
        """
        offset = (SCIONCommonHdr.LEN + OpaqueField.LEN)
        return self.common_hdr.curr_of_p + offset == self.common_hdr.hdr_len

    def reverse(self):
        """
        Reverses the header.
        """
        (self.src_addr, self.dst_addr) = (self.dst_addr, self.src_addr)
        self.path.reverse()
        self.common_hdr.curr_of_p = (self.common_hdr.src_addr_len +
                                     self.common_hdr.dst_addr_len)
        self.common_hdr.curr_iof_p = self.common_hdr.curr_of_p

    def __len__(self):
        length = self.common_hdr.hdr_len
        for ext_hdr in self.extension_hdrs:
            length += len(ext_hdr)
        return length

    def __str__(self):
        sh_list = []
        sh_list.append(str(self.common_hdr) + "\n")
        sh_list.append(str(self.src_addr) + " >> " + str(self.dst_addr) + "\n")
        sh_list.append(str(self.path) + "\n")
        for ext_hdr in self.extension_hdrs:
            sh_list.append(str(ext_hdr) + "\n")
        return "".join(sh_list)
};
