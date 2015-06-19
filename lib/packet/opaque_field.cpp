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
#ifndef OPAQUE_FIELD_CPP
#define OPAQUE_FIELD_CPP

#include <stdint.h>
#include <bitset>
#include "BitArray.h"
#include "easylogging++.h"

class OpaqueFieldType {
    /* 
     * Defines constants for the types of the opaque field (first byte of every
     * opaque field, i.e. field).
     * TODO describe here layout of Opaque Fields
     */
public:
    // Types for HopOpaqueFields (7 MSB bits).
    static const uint32_t NORMAL_OF = 0b0000000;

    // indicates last hop OF on the half-path (TODO revise)
    static const uint32_t LAST_OF = 0b0010000;  
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
    int type;
    bool parsed;
    std::string raw;

public:
    uint32_t info;
    static const int LEN = 8;
    
    OpaqueField() {
        info = 0;  // TODO verify path.PathType in that context
        type = 0;
        parsed = false;
        raw = "";
    }

    void parse(const std::string &raw) {
        /* Populates fields from a raw byte block.
         */
    }

    void pack() const {
        /* Returns opaque field as 8 byte binary string.
         */
    }

    bool is_regular() {
        /* Returns true if opaque field is regular, false otherwise.
         */
        return !std::bitset<8>(info)[6];
    }

    bool is_continue() {
        /* Returns true if continue bit is set, false otherwise.
         */
        return !std::bitset<8>(info)[5];
    }

    bool is_xovr() {
        /* Returns true if crossover point bit is set, false otherwise.
         */
        return !std::bitset<8>(info)[4];
    }

    std::string to_string() {
        return "";
    }

    // TODO test: one __eq__ breaks router when two SOFs in a path are identical
    bool operator==(const OpaqueField &other) const {
        return raw == other.raw;
    }

    bool operator!=(const OpaqueField &other) {
        return !(*this == other);
    }
};

class CommonOpaqueField : public OpaqueField {
public:
    int exp_time;
    int ingress_if;
    int egress_if;
    std::string mac;
    uint32_t timestamp;
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
     * ingress/egress interfaces (2 * 12 bits) and a MAC (24 bits) 
     * authenticating the opaque field.
     */
public:
    static const int MAC_LEN = 3;

    HopOpaqueField() {
        HopOpaqueField("");
    }

    HopOpaqueField(const std::string &raw) : CommonOpaqueField() {
        exp_time = 0;
        ingress_if = 0;
        egress_if = 0;
        for (int i = 0; i < MAC_LEN; i++)
            mac.push_back(0x00);
        if (raw.length())
            parse(raw);
    }

    void parse(const std::string &raw) {
        /**
         * Populates fields from a raw byte block.
         */ 
        this->raw = raw;
        int dlen = raw.length();
        if (dlen < HopOpaqueField::LEN) {
            LOG(WARNING) << "HOF: Data too short for parsing, len: " << dlen;
            return;
        }
        BitArray bits(raw);
        info = bits.get_subarray(0, 8);
        exp_time = bits.get_subarray(8, 8);
        int ifs = bits.get_subarray(16, 40); // ifs is 3 bytes
        // mac = bits.get_subarray(56, 24);
        mac = raw.substr(5, 3);
        ingress_if = (ifs & 0xFFF000) >> 12;
        egress_if = ifs & 0x000FFF;
        parsed = true;
    }

    HopOpaqueField(int exp_time, int ingress_if=0, int egress_if=0, 
                   std::string mac="") : CommonOpaqueField() {
        /**
         * Returns HopOpaqueField with fields populated from values.
         * 
         * @param ingress_if: Ingress interface.
         * @param egress_if: Egress interface.
         * @param mac: MAC of ingress/egress interfaces' ID and timestamp.
         */
        this->exp_time = exp_time;
        this->ingress_if = ingress_if;
        this->egress_if = egress_if;
        if (mac == "")
            for (int i = 0; i < MAC_LEN; i++)
                mac.push_back(0x00);
        this->mac = mac;
    }

    std::string pack() const {
        /**
         * Returns HopOpaqueField as 8 byte binary string.
         */
        int ifs = (ingress_if << 12) | egress_if;
        BitArray res;
        res.append(info, 8);
        res.append(exp_time, 8);
        res.append(ifs, 24);
        return res.to_string() + mac;
    }

    bool operator==(const HopOpaqueField &other) const {
        return (exp_time == other.exp_time &&
                ingress_if == other.ingress_if &&
                egress_if == other.egress_if &&
                mac == other.mac);
    }

    std::string to_string() {
        return "[Hop OF info: " + std::to_string(info) + ", exp_time: " 
               + std::to_string(exp_time) + ", ingress if: " 
               + std::to_string(ingress_if) + ", egress if: " 
               + std::to_string(egress_if) + ", mac: " 
               + mac + "]"; 
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
    InfoOpaqueField(const std::string &raw) : CommonOpaqueField() {
        timestamp = 0;
        isd_id = 0;
        hops = 0;
        up_flag = false;
        if (raw.length())
            parse(raw);
    }

    void parse(const std::string &raw) {
        /**
         * Populates fields from a raw byte block.
         */
        int dlen = raw.length();        
        this->raw = raw;

        if (dlen < this->LEN) {
            LOG(WARNING) << "IOF: Data too short for parsing, len: " << dlen;
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

    std::string pack() const {
        /**
         * Returns InfoOpaqueFIeld as 8 byte binary string.
         */
        int info_ = (info << 1) + up_flag;
        BitArray res;
        res.append(info_, 8);
        res.append(timestamp, 32);
        res.append(isd_id, 16);
        res.append(hops, 8);
        return res.to_string();
    }

    std::string to_string() {
        // iof_str = ("[Info OF info: %x, up: %r, TS: %u, ISD ID: %u, hops: %u]" %
        //            (self.info, self.up_flag, self.timestamp, self.isd_id,
        //             self.hops))
        // stringstream stream;
        // stream << std::hex << info;
        // string result( stream.str() );
        // return "[Info OF info: " + result + ", up: %r, TS: %u, ISD ID: %u, hops: %u]"
        std::cerr << "***UNIMPLEMENTED***" << std::endl;
        exit(-1);
        return "";
    }

    bool operator==(const InfoOpaqueField &other) const {
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
    int reserved;
public:
    int if_id;

    TRCField(const std::string &raw) : OpaqueField() {
        info = OpaqueFieldType::TRC_OF;
        trc_version = 0;
        if_id = 0;
        reserved = 0;
        if (raw.length())
            parse(raw);
    }

    void parse(const std::string &raw) {
        /**
         * Populates fields from a raw byte block.
         */
        int dlen = raw.length();
        this->raw = raw;

        if (dlen < TRCField::LEN) {
            LOG(WARNING) << "TRCF: Data too short for parsing, len: " << dlen;
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

    std::string pack() const {
        /**
         * Returns TRCField as 8 byte binary string.
         */
        BitArray res;
        res.append(info, 8);
        res.append(trc_version, 32);
        res.append(if_id, 16);
        res.append(reserved, 8);
        return res.to_string();
    }

    std::string to_string() {
        // trcf_str = ("[TRC OF info: %x, TRCv: %u, IF ID: %u]\n" %
                    // (self.info, self.trc_version, self.if_id))
        // return trcf_str
        std::cerr << "***UNIMPLEMENTED***" << std::endl;
        exit(-1);
        return "";
    }

    bool operator==(const TRCField &other) const {
        return (this->info == other.info &&
                this->trc_version == other.trc_version &&
                this->if_id == other.if_id);
    }
};

#endif