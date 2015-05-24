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
/* :mod:`opaque_field` --- SCION Opaque fields
 * ===========================================
 */

#include <stdint.h>
#include <bitset>
#include <cstring>
#include "BitArray.h"
using namespace std;

class OpaqueFieldType {
    /* 
     * Defines constants for the types of the opaque field (first byte of every
     * opaque field, i.e. field).
     * TODO describe here layout of Opaque Fields
     */
 public:
    // Types for HopOpaqueFields (7 MSB bits).
    static const uint32_t NORMAL_OF = 0b0000000;
    static const uint32_t LAST_OF = 0b0010000;  // indicates last hop OF on the half-path (TODO revise)
    static const uint32_t PEER_XOVR = 0b0001000;
    // Types for Info Opaque Fields (7 MSB bits).
    static const uint32_t TDC_XOVR = 0b1000000;
    static const uint32_t NON_TDC_XOVR = 0b1100000;
    static const uint32_t INPATH_XOVR = 0b1110000;
    static const uint32_t INTRATD_PEER = 0b1111000;
    static const uint32_t INTERTD_PEER = 0b1111100;
    static const uint32_t TRC_OF = 0b11111111;
};

class OpaqueField {
    /* 
     * Base class for the different kinds of opaque fields in SCION.
     */
protected:
    static const int LEN = 8;
    int info;
    int type;
    bool parsed;
    char *raw;

public:
    OpaqueField() {
        info = 0;  // TODO verify path.PathType in that context
        type = 0;
        parsed = false;
        raw = NULL;
    }

    void parse(char *raw) {
        /* Populates fields from a raw byte block.
         */
    }

    void pack() {
        /* Returns opaque field as 8 byte binary string.
         */
    }

    bool is_regular() {
        /* Returns true if opaque field is regular, false otherwise.
         */
        return !bitset<8>(info)[6];
    }

    bool is_continue() {
        /* Returns true if continue bit is set, false otherwise.
         */
        return !bitset<8>(info)[5];
    }

    bool is_xovr() {
        /* Returns true if crossover point bit is set, false otherwise.
         */
        return !bitset<8>(info)[4];
    }

    string __str__() {
        return "";
    }

    string __repr__() {
        return __str__();
    }

    // TODO test: one __eq__ breaks router when two SOFs in a path are identical
    bool operator==(OpaqueField &other) {
        return (strcmp(other.raw, raw) == 0);
    }

    bool operator!=(OpaqueField &other) {
        return !(*this == other);
    }
};

class CommonOpaqueField : public OpaqueField {
public:
    int exp_time;
    int ingress_if;
    int egress_if;
    int mac;
    int timestamp;
    int isd_id;
    int hops;
    bool up_flag;
    CommonOpaqueField() : OpaqueField() {}
};

class HopOpaqueField : public CommonOpaqueField {
    /**
     * Opaque field for a hop in a path of the SCION packet header.
     * 
     * Each hop opaque field has a info (8 bits), expiration time (8 bits)
     * ingress/egress interfaces (2 * 12 bits) and a MAC (24 bits) authenticating
     * the opaque field.
     */
public:
    HopOpaqueField(char *raw) : CommonOpaqueField() {
        exp_time = 0;
        ingress_if = 0;
        egress_if = 0;
        mac = 0;
        if (raw)
            parse(raw);
    }

    void parse(char *raw) {
        /**
         * Populates fields from a raw byte block.
         */ 
        strcpy(this->raw, raw);
        int dlen = strlen(raw);
        if (dlen < HopOpaqueField::LEN) {
            // logging.warning("HOF: Data too short for parsing, len: %u", dlen)
            return;
        }
        BitArray bits(raw);
        info = bits.get_subarray(0, 8);
        exp_time = bits.get_subarray(8, 8);
        int ifs = bits.get_subarray(16, 24);
        mac = bits.get_subarray(40, 24);
        ingress_if = (ifs & 0xFFF000) >> 12;
        egress_if = ifs & 0x000FFF;
        parsed = true;
    }

    HopOpaqueField(int exp_time, int ingress_if=0, int egress_if=0, int mac=0) {
        /**
         * Returns HopOpaqueField with fields populated from values.
         * 
         * @param ingress_if: Ingress interface.
         * @param egress_if: Egress interface.
         * @param mac: MAC of ingress/egress interfaces' ID and timestamp.
         */
        exp_time = exp_time;
        ingress_if = ingress_if;
        egress_if = egress_if;
        mac = mac;
    }

    BitArray pack() {
        /**
         * Returns HopOpaqueField as 8 byte binary string.
         */
        int ifs = (ingress_if << 12) | egress_if;
        BitArray res;
        res.append(info, 8);
        res.append(exp_time, 8);
        res.append(ifs, 24);
        res.append(mac, 24);
        return res;
    }

    bool operator==(HopOpaqueField &other) {
        return (exp_time == other.exp_time &&
                ingress_if == other.ingress_if &&
                egress_if == other.egress_if &&
                mac == other.mac);
    }

    string __str__() {
        return "[Hop OF info: " + to_string(info) + ", exp_time: " 
               + to_string(exp_time) + ", ingress if: " 
               + to_string(ingress_if) + ", egress if: " 
               + to_string(egress_if) + ", mac: " 
               + to_string(mac) + "]"; 
    }
};


class InfoOpaqueField : public CommonOpaqueField {
    /**
     * Class for the info opaque field.
     * 
     * The info opaque field contains type info of the path-segment (1 byte),
     * a creation timestamp (4 bytes), the ISD ID (2 byte) and # hops for this
     * segment (1 byte).
     */
public:  
    InfoOpaqueField(char *raw) : CommonOpaqueField() {
        timestamp = 0;
        isd_id = 0;
        hops = 0;
        up_flag = false;
        if (raw)
            parse(raw);
    }

    void parse(char *raw) {
        /**
         * Populates fields from a raw byte block.
         */
        int dlen = strlen(raw);        
        this->raw = new char[dlen];
        strcpy(this->raw, raw);

        if (dlen < InfoOpaqueField::LEN) {
            // logging.warning("IOF: Data too short for parsing, len: %u", dlen)
            return;
        }
        BitArray bits(raw);
        info = bits.get_subarray(0, 8);
        timestamp = bits.get_subarray(8, 32);
        isd_id = bits.get_subarray(40, 16);
        hops = bits.get_subarray(56, 8);
        up_flag = bool(info & 0b00000001);
        info >>= 1;
        parsed = true;
    }

    InfoOpaqueField(int info=0, bool up_flag=false, int timestamp=0, 
                    int isd_id=0, int hops=0) {
        /**
         * Constructor with fields populated from values.
         * 
         * @param info: Opaque field type.
         * @param up_flag: up/down-flag.
         * @param timestamp: Beacon's timestamp.
         * @param isd_id: Isolation Domanin's ID.
         * @param hops: Number of hops in the segment.
         */        
        this->info = info;
        this->up_flag = up_flag;
        this->timestamp = timestamp;
        this->isd_id = isd_id;
        this->hops = hops;
    }

    BitArray pack() {
        /**
         * Returns InfoOpaqueFIeld as 8 byte binary string.
         */
        int info_ = (info << 1) + up_flag;
        BitArray res;
        res.append(info_, 8);
        res.append(timestamp, 32);
        res.append(isd_id, 16);
        res.append(hops, 8);
        return res;
    }

    string __str__() {
        // iof_str = ("[Info OF info: %x, up: %r, TS: %u, ISD ID: %u, hops: %u]" %
        //            (self.info, self.up_flag, self.timestamp, self.isd_id,
        //             self.hops))
        // stringstream stream;
        // stream << std::hex << info;
        // string result( stream.str() );
        // return "[Info OF info: " + result + ", up: %r, TS: %u, ISD ID: %u, hops: %u]"
        cerr << "***UNIMPLEMENTED***" << endl;
        exit(-1);
        return "";
    }

    bool operator==(InfoOpaqueField &other) {
        return (this->info == other.info &&
                this->up_flag == other.up_flag &&
                this->timestamp == other.timestamp &&
                this->isd_id == other.isd_id &&
                this->hops == other.hops);
    }
};

class TRCField : public OpaqueField {
    /**
     * Class for the TRC field.
     * 
     * The TRC field contains type info of the path-segment (1 byte),
     * the TRC version (4 bytes), the IF ID (2 bytes),
     * and a reserved section (1 byte).
     */    
    int trc_version;
    int if_id;
    int reserved;
public:
    TRCField(char *raw) : OpaqueField() {
        info = OpaqueFieldType::TRC_OF;
        trc_version = 0;
        if_id = 0;
        reserved = 0;
        if (raw)
            parse(raw);
    }

    void parse(char *raw) {
        /**
         * Populates fields from a raw byte block.
         */
        int dlen = strlen(raw);
        this->raw = new char[dlen];
        strcpy(this->raw, raw);
        
        if (dlen < TRCField::LEN) {
            // logging.warning("TRCF: Data too short for parsing, len: %u", dlen)
            return;
        }
        BitArray bits(raw);
        info = bits.get_subarray(0, 8);
        trc_version = bits.get_subarray(8, 32);
        if_id = bits.get_subarray(40, 16);
        reserved = bits.get_subarray(56, 8);
        parsed = true;
    }

    TRCField(int trc_version=0, int if_id=0, int reserved=0) : OpaqueField() {
        /**
         * Returns TRCField with fields populated from values.
         * 
         * @param trc_version: Version of the Isolation Domanin's TRC file.
         * @param if_id: Interface ID.
         * @param reserved: Reserved section.
         */
        this->trc_version = trc_version;
        this->if_id = if_id;
        this->reserved = reserved;
    }

    BitArray pack() {
        /**
         * Returns TRCField as 8 byte binary string.
         */
        BitArray res;
        res.append(info, 8);
        res.append(trc_version, 32);
        res.append(if_id, 16);
        res.append(reserved, 8);
        return res;
    }

    string __str__() {
        // trcf_str = ("[TRC OF info: %x, TRCv: %u, IF ID: %u]\n" %
                    // (self.info, self.trc_version, self.if_id))
        // return trcf_str
        cerr << "***UNIMPLEMENTED***" << endl;
        exit(-1);
        return "";
    }

    bool operator==(TRCField &other) {
        return (this->info == other.info &&
                this->trc_version == other.trc_version &&
                this->if_id == other.if_id);
    }
};

class SupportSignatureField : public OpaqueField {
    /**
     * Class for the support signature field.
     * 
     * The support signature field contains a certificate version (4 bytes), the
     * signature length (2 bytes), and the block size (2 bytes).
     */
    int cert_chain_version;
    int sig_len;
    int block_size;
public:
    SupportSignatureField() : OpaqueField() {
        cert_chain_version = 0;
        sig_len = 0;
        block_size = 0;
        if (raw) 
            parse(raw);
    }

    void parse(char *raw) {
        /**
         * Populates fields from a raw byte block.
         */
        int dlen = strlen(raw);
        this->raw = new char[dlen];
        strcpy(this->raw, raw);
        if (dlen < SupportSignatureField::LEN) {
            // logging.warning("SSF: Data too short for parsing, len: %u", dlen)
            return;
        }

        BitArray bits(raw);
        cert_chain_version = bits.get_subarray(0, 32);
        sig_len = bits.get_subarray(32, 16);
        block_size = bits.get_subarray(48, 16);
        parsed = true;
    }

    SupportSignatureField(int block_size, int cert_chain_version=0, 
                          int sig_len=0) : OpaqueField() {
        /**        
         * Returns SupportSignatureField with fields populated from values.
         * 
         * :param block_size: Total marking size for an AD block (peering links
         *                    included.)
         * :param cert_chain_version: Version of the Autonomous Domain's
         *                            certificate.
         * :param sig_len: Length of the beacon's signature.
         */
        this->cert_chain_version = cert_chain_version;
        this->sig_len = sig_len;
        this->block_size = block_size;
    }

    BitArray pack() {
        /**
         * Returns SupportSignatureField as 8 byte binary string.
         */
        BitArray res;
        res.append(cert_chain_version, 32);
        res.append(sig_len, 16);
        res.append(block_size, 16);
        return res;
    }

    string __str__() {
        // ssf_str = ("[Support Signature OF cert_chain_version: %x, "
        //            "sig_len: %u, block_size: %u]\n" % (
        //                self.cert_chain_version, self.sig_len, self.block_size))
        // return ssf_str
        cerr << "***UNIMPLEMENTED***" << endl;
        exit(-1);
        return "";
    }

    bool operator==(SupportSignatureField &other) {
        return (cert_chain_version == other.cert_chain_version &&
                sig_len == other.sig_len &&
                block_size == other.block_size);
    }
};

class SupportPeerField: public OpaqueField {
    /**
     * Class for the support peer field.
     * 
     * The support peer field contains the trusted domain id (2 bytes),
     * bandwidth allocation left (1 byte), bandwith allocation right (1 byte),
     * the bandwidth class (1 bit), and a reserved section (31 bits).
     */
    int isd_id;
    int bwalloc_f;
    int bwalloc_r;
    int bw_class;
    int reserved;
public:
    SupportPeerField(char *raw) : OpaqueField() {
        isd_id = 0;
        bwalloc_f = 0;
        bwalloc_r = 0;
        bw_class = 0;
        reserved = 0;
        if (raw)
            parse(raw);
    }

    void parse(char *raw) {
        /**
         * Populates fields from a raw byte block.
         */
        int dlen = strlen(raw);
        this->raw = new char[dlen];
        strcpy(this->raw, raw);
        
        if (dlen < SupportPeerField::LEN) {
            // logging.warning("SPF: Data too short for parsing, len: %u", dlen)
            return;
        }

        BitArray bits(raw);
        isd_id = bits.get_subarray(0, 16);
        bwalloc_f = bits.get_subarray(16, 8);
        bwalloc_r = bits.get_subarray(24, 8);
        bw_class = bits.get_subarray(32, 1);
        reserved = bits.get_subarray(33, 31);
        parsed = true;
    }

    SupportPeerField(int isd_id=0, int bwalloc_f=0, int bwalloc_r=0,
                    int bw_class=0, int reserved=0) : OpaqueField() {
        /**
         * Returns SupportPeerField with fields populated from values.
         * 
         * @param isd_id: Isolation Domanin's ID.
         * @param bwalloc_f: Allocated bandwidth left.
         * @param bwalloc_r: Allocated bandwidth right.
         * @param bw_class: Bandwidth class.
         * @param reserved: Reserved section.
         */        
        this->isd_id = isd_id;
        this->bwalloc_f = bwalloc_f;
        this->bwalloc_r = bwalloc_r;
        this->bw_class = bw_class;
        this->reserved = reserved;
    }

    BitArray pack() {
        /**
         * Returns SupportPeerField as 8 byte binary string.
         */
        BitArray res;
        res.append(isd_id, 16);
        res.append(bwalloc_f, 8);
        res.append(bwalloc_r, 8);
        res.append(bw_class, 1);
        res.append(reserved, 31);
        return res;
    }

    string __str__() {
        // spf_str = ("[Support Peer OF TD ID: %x, bwalloc_f: %u, "
        //            "bwalloc_r: %u, bw_class: %u]\n" % (
        //                self.isd_id, self.bwalloc_f, self.bwalloc_r,
        //                self.bw_class))
        // return spf_str
        cerr << "***UNIMPLEMENTED***" << endl;
        exit(-1);
        return "";
    }

    bool operator==(SupportPeerField &other) {
        return (isd_id == other.isd_id &&
                bwalloc_f == other.bwalloc_f &&
                bwalloc_r == other.bwalloc_r &&
                bw_class == other.bw_class);
    }
};

class SupportPCBField : public OpaqueField {
    /**
     * Class for the support PCB field.
     * 
     * The support PCB field contains the trusted domain id (2 bytes),
     * bandwidth allocation left (1 byte), bandwith allocation right (1 byte),
     * dynamic bandwidth allocation left (1 byte), dynamic bandwidth allocation
     * right (1 byte), best effort bandwidth left (1 byte), and best effort
     * bandwidth right (1 byte).
    */
    int isd_id;
    int bwalloc_f;
    int bwalloc_r;
    int dyn_bwalloc_f;
    int dyn_bwalloc_r;
    int bebw_f;
    int bebw_r;
public:
    SupportPCBField(char *raw) : OpaqueField() {
        isd_id = 0;
        bwalloc_f = 0;
        bwalloc_r = 0;
        dyn_bwalloc_f = 0;
        dyn_bwalloc_r = 0;
        bebw_f = 0;
        bebw_r = 0;
        if (raw)
            parse(raw);
    }

    void parse(char *raw) {
        /**
         * Populates fields from a raw byte block.
         */
        int dlen = strlen(raw);
        this->raw = new char[dlen];
        strcpy(this->raw, raw);

        if (dlen < SupportPCBField::LEN) {
            // logging.warning("SPCBF: Data too short for parsing, len: %u", dlen)
            return;
        }

        BitArray bits(raw);
        isd_id = bits.get_subarray(0, 16);
        bwalloc_f = bits.get_subarray(16, 8);
        bwalloc_r = bits.get_subarray(24, 8);
        dyn_bwalloc_f = bits.get_subarray(32, 8);
        dyn_bwalloc_r = bits.get_subarray(40, 8);
        bebw_f = bits.get_subarray(48, 8);
        bebw_r = bits.get_subarray(56, 8);
        parsed = true;
    }

    SupportPCBField(int isd_id=0, int bwalloc_f=0, int bwalloc_r=0,
                    int dyn_bwalloc_f=0, int dyn_bwalloc_r=0, int bebw_f=0,
                    int bebw_r=0) : OpaqueField() {
        /**
         * Returns SupportPCBField with fields populated from values.
         * 
         * @param isd_id: Isolation Domanin's ID.
         * @param bwalloc_f: Allocated bandwidth left.
         * @param bwalloc_r: Allocated bandwidth right.
         * @param dyn_bwalloc_f: Dynamic allocated bandwidth left.
         * @param dyn_bwalloc_r: Dynamic allocated bandwidth right.
         * @param bebw_f: Best effort bandwidth left.
         * @param bebw_r: Best effort bandwidth right.
         */
        this->isd_id = isd_id;
        this->bwalloc_f = bwalloc_f;
        this->bwalloc_r = bwalloc_r;
        this->dyn_bwalloc_f = dyn_bwalloc_f;
        this->dyn_bwalloc_r = dyn_bwalloc_r;
        this->bebw_f = bebw_f;
        this->bebw_r = bebw_r;
    }

    BitArray pack() {
        /**
         * Returns SupportPCBField as 8 byte binary string.
         */
        BitArray res;
        res.append(isd_id, 16);
        res.append(bwalloc_f, 8);
        res.append(bwalloc_r, 8);
        res.append(dyn_bwalloc_f, 8);
        res.append(dyn_bwalloc_r, 8);
        res.append(bebw_f, 8);
        res.append(bebw_r, 8);
        return res;
    }

    string __str__() {
        // spcbf_str = ("[Info OF TD ID: %x, bwalloc_f: %u, bwalloc_r: %u]\n" %
        //              (self.isd_id, self.bwalloc_f, self.bwalloc_r))
        // return spcbf_str
        cerr << "***UNIMPLEMENTED***" << endl;
        exit(-1);
        return "";
    }

    bool operator==(SupportPCBField &other) {
        return (isd_id == other.isd_id &&
                bwalloc_f == other.bwalloc_f &&
                bwalloc_r == other.bwalloc_r &&
                dyn_bwalloc_f == other.dyn_bwalloc_f &&
                dyn_bwalloc_r == other.dyn_bwalloc_f &&
                bebw_f == other.bebw_f &&
                bebw_r == other.bebw_r);
    }
};