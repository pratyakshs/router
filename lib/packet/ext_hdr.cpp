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
/* :mod:`ext_hdr` --- Extension header classes
 * ===========================================
 */
#ifndef EXT_HDR_CPP
#define EXT_HDR_CPP

#include "packet_base.cpp"
#include "easylogging++.h"

class ExtensionHeader : public HeaderBase {
    /**
     * Base class for extension headers.
     * 
     * For each extension header there should be a subclass of this class (e.g
     * StrideExtensionHeader).
     */
public:
    static const int MIN_LEN = 2;
    int next_ext;
    uint32_t hdr_len;
    
    ExtensionHeader() {
        ExtensionHeader("");
    }

    ExtensionHeader(const std::string &raw) : HeaderBase() {
        next_ext = 0;
        hdr_len = 0;
        if (raw.length())
            parse(raw);
    }

    void parse(const std::string &raw) {
        int dlen = raw.length();
        if (dlen < this->MIN_LEN) {
            LOG(WARNING) << "Data too short to parse extension hdr: "
                         << "data len " << dlen;
            return;
        }
        BitArray bits(raw);
        next_ext = bits.get_subarray(0, 8);
        hdr_len = bits.get_subarray(8, 8);
        parsed = true;
    }

    std::string pack() const {
        BitArray res;
        res.append(next_ext, 8);
        res.append(hdr_len, 8);
        return res.to_string();
    }

    int length() {
        return 8;
    }

    std::string to_string() {
        return "[EH next hdr: " + std::to_string(next_ext) 
               + ", len: " + std::to_string(hdr_len) + "]";
    }
};


class ICNExtHdr : public ExtensionHeader {
    /**
     * The extension header for the SCION ICN extension.
     * 
     * 0          8         16      24                                           64
     * | next hdr | hdr len |  type  |                reserved                    |
     */
public:
    static const int MIN_LEN = 8;
    static const int TYPE = 220;  // Extension header type
    int fwd_flag;

    ICNExtHdr(const std::string &raw) : ExtensionHeader() {
        /**
         * Initialize an instance of the class ICNExtHdr.
         * Tells the edge router whether to forward this pkt to the local Content
         * Cache or to the next AD.
         */
        fwd_flag = 0;
        if (raw.length())
            parse(raw);
    }

    void parse(const std::string &raw) {
        int dlen = raw.length();
        if (dlen < ExtensionHeader::MIN_LEN) {
            LOG(WARNING) << "Data too short to parse ICN extension hdr: "
                         << "data len " << dlen;
            return;
        }
        BitArray bits(raw);
        next_ext = bits.get_subarray(0, 8);
        hdr_len = bits.get_subarray(8, 8);
        fwd_flag = bits.get_subarray(16, 8);
        long long rsvd = bits.get_subarray(24, 40);
        parsed = true;
    }

    std::string pack() const {
        BitArray res;
        res.append(next_ext, 8);
        res.append(hdr_len, 8);
        res.append(fwd_flag, 8);
        res.append(0, 40);
        return res.to_string();
    }

    int length() {
        return ICNExtHdr::MIN_LEN;
    }

    std::string to_string() {
        return "[ICN EH next hdr: " + std::to_string(next_ext) + ", len: " 
               + std::to_string(hdr_len) + ", fwd_flag: " 
               + std::to_string(fwd_flag) + "]";
    }
};

#endif 