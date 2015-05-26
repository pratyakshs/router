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
/* :mod:`packet_base` --- Packet base class
 * ===========================================
 */
#ifndef PACKET_BASE_CPP
#define PACKET_BASE_CPP

#include <string>
#include "BitArray.h"

class HeaderBase {
    /* Base class for headers.
     * 
     * Each header class must implement parse, pack and __str__.
     * 
     * :ivar parsed: whether or not the header has been parsed.
     * :vartype parsed: bool
     */
 public:
    bool parsed;
    HeaderBase() {
        parsed = false;
    }

    void parse(const std::string &raw){
        return;
    }
    
    virtual BitArray pack() const {}

public:
    virtual int length() {}

    virtual std::string __str__() {}

    virtual std::string __repr__() {
        return __str__();
    }
};

class PacketBase {
    /* Base class for packets.
     * 
     * :ivar parsed: whether or not the packet has been parsed.
     * :vartype parsed: bool
     * :ivar raw: the raw bytes of the packet contents.
     * :vartype raw: bytes
     * :ivar hdr: the packet header.
     * :vartype hdr: :class:`HeaderBase`
     * :ivar payload: the packet payload
     * :vartype payload: std::string
     */
    HeaderBase *hdr;
    std::string payload;
public:
    bool parsed;
    std::string raw;
    PacketBase() {
        parsed = false;
        raw = "";
    }

    std::string get_payload() {
        /* Returns the packet payload.
         */
        return payload;
    }

    void set_payload(const std::string &new_payload) {
        /* Set the packet payload.  Expects bytes or a Packet subclass.
         */
        // if (not isinstance(new_payload, PacketBase) and
        //         not isinstance(new_payload, PayloadBase) and
        //         not isinstance(new_payload, bytes)):
        //     raise TypeError("payload must be bytes or packet/payload subclass.")
        // else:
        payload = new_payload;
    }

    HeaderBase get_hdr() {
        /* Returns the packet header.
         */
        return *hdr;
    }

    void set_hdr(HeaderBase *new_hdr) {
        /* Sets the packet header. Expects a Header subclass.
         */
        hdr = new_hdr;
    }

    void parse(const std::string &raw) {
        // pass
    }

    void pack() const {
        // pass
    }

    int length() {
        return hdr->length() + payload.length();
    }

    std::string __str__() {
        return hdr->__str__() + "\n" + "Payload:\n" + payload;
    }

    std::string __repr__() {
        return __str__();
    }

    long long __hash__() {
        // return hash(self.pack())
        return 0;
    }

    bool operator==(PacketBase &other) {
        return raw == other.raw;
    }
};

class PayloadBase {
    /* Interface that payloads of packets must implement.
     */
public:
    std::string raw;
    bool parsed;

    PayloadBase() {
        raw = "";
        parsed = false;
    }

    void parse(const std::string &raw) {
        this->raw = raw;
    }

    std::string pack() const {
        return raw;
    }

    int length() {
        return raw.length();
    }

    long long __hash__() {
        // return hash(raw);
        return 0;
    }

    bool operator==(PayloadBase &other) {
        return raw == other.raw;
    }
};

#endif