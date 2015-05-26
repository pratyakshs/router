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

// ISD_AD = namedtuple('ISD_AD', ['isd', 'ad'])
// figure out an alternative

class SCIONAddr {
    /* Class for complete SCION addresses.
     */
public:
    uint16_t isd_id;
    uint64_t ad_id;
    int addr_len;
    IPAddress *host_addr;
    static const int ISD_AD_LEN = 10;  // Size of (isd_id, ad_id) pair in bytes.

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
    SCIONAddr(uint16_t isd_id, uint64_t ad_id, IPv4Address * host_addr) {
        this->isd_id = isd_id;
        this->ad_id = ad_id;
        this->host_addr = host_addr;
        int host_addr_len;
        if (this->host_addr->version == 4)
            host_addr_len = IPV4LENGTH; // 8
        else if (this->host_addr->version == 6)
            host_addr_len = IPV6LENGTH; // 8
        addr_len = ISD_AD_LEN + host_addr_len;
    }

    void parse(const std::string &raw) {
        // assert isinstance(raw, bytes)
        addr_len = raw.length();
        if (addr_len < ISD_AD_LEN) {
            // logging.warning("SCIONAddr: Data too short for parsing, len: %u",
            //                  addr_len)
            // add logging warning.
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

    int pack(){
        /****UNIMPLEMENTED****/
        std::cerr << "pack function unimplemented" << std::endl;
        exit(-1);
        return 0;
        // return (bitstring.pack("uintbe:16, uintbe:64", self.isd_id,
        //                        self.ad_id).bytes + self.host_addr.packed)
    }

    std::string to_string(){
        std::cerr << "to_string function unimplemented" << std::endl;
        exit(-1);
        return "";
        // return "(%u, %u, %s)" % (self.isd_id, self.ad_id, self.host_addr)
    }

    // int isn't the correct type
    int get_isd_ad(){
        std::cerr << "get_isd_ad function unimplemented" << std::endl;
        exit(-1);
        return 0;
        // return ISD_AD(self.isd_id, self.ad_id)
    }

};

#endif