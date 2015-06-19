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
 * :mod:`scion_addr` --- SCION host address specifications
 * =======================================================
 * 
 * Module docstring here.
 * 
 * .. note::
 *     Fill in the docstring.
 */

#ifndef SCION_ADDR_CPP
#define SCION_ADDR_CPP

#include <stdint.h>
#include "IPAddress.h"
#include "easylogging++.h"

class ISD_AD {
public:
    static const int LEN = 4;

    uint16_t isd;
    uint32_t ad;

    ISD_AD() {
        /**
         * Default constructor.
         */
        isd = 0;
        ad = 0;
    }

    ISD_AD(const uint16_t isd, const uint32_t ad) {
        /**
         * Constructor from ISD, AD values.
         */
        this->isd = isd;
        this->ad = ad;
    }
    
    ISD_AD(const std::string &raw) {
        /**
         * Constructor from raw data.
         */
        BitArray bits(raw);
        isd = bits.get_subarray(0, 12);
        ad = bits.get_subarray(12, 20);
    }

    std::string pack() const {
        /**
         * Pack the class variables into a byte string.
         * returns a 4B long byte string containing ISD ID (first 12 bits),
                  AD ID (remaining 20 bits).
         */
        uint32_t res = isd << 20;
        res |= ad;
        BitArray bits;
        bits.append(res, 32);
        return bits.to_string();
    }
};

class SCIONAddr {
    /* Class for complete SCION addresses.
     */
public:
    uint16_t isd_id;
    uint32_t ad_id;
    int addr_len;
    IPAddress *host_addr;

    SCIONAddr() {
        isd_id = 0;
        ad_id = 0;
        host_addr = NULL;
        addr_len = 0;
    }

    SCIONAddr(const std::string &raw) {
        isd_id = 0;
        ad_id = 0;
        host_addr = NULL;
        addr_len = 0;
        if (raw.length())
            parse(raw);
    }

    // def from_values(cls, isd_id, ad_id, host_addr):
    SCIONAddr(uint16_t isd_id, uint32_t ad_id, const IPAddress * host_addr) {
        this->isd_id = isd_id;
        this->ad_id = ad_id;
        this->host_addr = new IPAddress;
        *(this->host_addr) = *(IPAddress*)host_addr; ///? hacky
        int host_addr_len;
        if (this->host_addr->version == 4)
            host_addr_len = IPV4LENGTH; // 8
        else if (this->host_addr->version == 6)
            host_addr_len = IPV6LENGTH; // 8
        addr_len = ISD_AD::LEN + host_addr_len;
    }

    void parse(const std::string &raw) {
        // assert isinstance(raw, bytes)
        addr_len = raw.length();
        if (addr_len < ISD_AD::LEN) {
            LOG(WARNING) << "SCIONAddr: Data too short for parsing, len: " 
                         << addr_len;
            return;
        }
        /****UNIMPLEMENTED****/
        std::cerr << "parse function unimplemented" << std::endl;
        exit(-1);
        // bits = BitArray(bytes=raw[:SCIONAddr.ISD_AD_LEN])
        // (self.isd_id, self.ad_id) = bits.unpack("uintbe:16, uintbe:64")
        // host_addr_len = addr_len - SCIONAddr.ISD_AD_LEN
        // if host_addr_len == IPV4LENGTH // 8: 
        //     self.host_addr = IPv4Address(raw[SCIONAddr.ISD_AD_LEN:])
        // elif host_addr_len == IPV6LENGTH // 8: 
        //     self.host_addr = IPv6Address(raw[SCIONAddr.ISD_AD_LEN:])
        // else:
        //     logging.warning("SCIONAddr: host address unsupported, len: %u",
        //                     host_addr_len)
        //     return
        // addr_len = ISD_AD_LEN + host_addr_len;

    }

    std::string pack() const {
        /**
         * Pack the class variables into a byte string.
         * 
         * returns a byte string containing ISD ID, AD ID, and host address.
         */
        return ISD_AD(isd_id, ad_id).pack() + host_addr->pack();
    }

    std::string to_string() {
        return "(" + std::to_string(isd_id) + ", " + std::to_string(ad_id) 
                   + ", " + host_addr->to_string() + ")";
    }

    ISD_AD get_isd_ad() {
        return ISD_AD(isd_id, ad_id);
    }
};

#endif
