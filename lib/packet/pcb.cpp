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
/* :mod:`pcb` --- SCION Beacon
 * ===========================================
 */
#ifndef PCB_CPP
#define PCB_CPP

#include "BitArray.h"
#include "base64.h"
#include "opaque_field.cpp"
#include "path.cpp"
#include "scion_addr.cpp"
#include "scion.cpp"

#define MAX_SEGMENT_TTL 86400 // 26 * 60 * 60
#define EXP_TIME_UNIT 337.5 // MAX_SEGMENT_TTL / 2 ** 8

class Marking {
    /**
     * Base class for all marking objects.
     */
protected:
    bool parsed;

public:
    std::string raw;

    Marking() {
        parsed = false;
        raw = "";
    }

    void parse(const std::string &raw) {
        /**
         * Populates fields from a raw bytes block.
         */
     }

    BitArray pack() const {
        /**
         * Returns object as a binary string.
         */
    }

    bool operator==(const Marking &other) const {
        return raw == other.raw;
    }

    bool operator!=(const Marking &other) {
        return !(*this == other);
    }

    int64_t __hash__() {
        ///? TODO
        return 0;
    }
};


class PCBMarking : public Marking {
    /**
     * Packs all fields for a specific PCB marking, which includes: the Autonomous
     * Domain's ID, the SupportSignatureField, the HopOpaqueField, the
     * SupportPCBField, and the revocation tokens for the interfaces
     * included in the HOF.
     */
public:
    uint64_t ad_id;
    SupportSignatureField ssf;
    HopOpaqueField hof;
    SupportPCBField spcbf;
    std::string ig_rev_token;
    std::string eg_rev_token;
    static const int LEN = 32 + 2 * 32;

    PCBMarking() {
        PCBMarking("");
    }

    PCBMarking(const std::string &raw) : Marking() {
        ad_id = 0;
        ig_rev_token = std::string(32, 0);
        eg_rev_token = std::string(32, 0);
        if (raw.length()) 
            parse(raw);
    }

    void parse(const std::string &raw) {
        /**
         * Populates fields from a raw bytes block.
         */
        this->raw = raw;
        int dlen = raw.length();
        if (dlen < PCBMarking::LEN) {
            // logging.warning("PCBM: Data too short for parsing, len: %u", dlen)
            return;
        }
        BitArray bits(raw.substr(0, 8));
        ad_id = bits.get_subarray(0, 64);
        ssf = SupportSignatureField(raw.substr(8, 8));
        hof = HopOpaqueField(raw.substr(16, 8));
        spcbf = SupportPCBField(raw.substr(24, 8));
        ig_rev_token = raw.substr(32, 32);
        eg_rev_token = raw.substr(64, 32);
        parsed = true;
    }

    PCBMarking(int ad_id, SupportSignatureField ssf, HopOpaqueField hof, 
               SupportPCBField spcbf, std::string ig_rev_token, 
               std::string eg_rev_token) : Marking() {
        /**
         * Returns PCBMarking with fields populated from values.
         * 
         * :param ad_id: Autonomous Domain's ID.
         * :param ssf: SupportSignatureField object.
         * :param hof: HopOpaqueField object.
         * :param spcbf: SupportPCBField object.
         * :param ig_rev_token: Revocation token for the ingress if
         *                      in the HopOpaqueField.
         * :param eg_rev_token: Revocation token for the egress if
         *                      in the HopOpaqueField.
         */
        this->ad_id = ad_id;
        this->ssf = ssf;
        this->hof = hof;
        this->spcbf = spcbf;
        this->ig_rev_token = ig_rev_token;
        this->eg_rev_token = eg_rev_token;
    }

    BitArray pack() const {
        /**
         * Returns PCBMarking as a binary string.
         */
        BitArray res;
        res.append(ad_id, 64);
        res += ssf.pack() + hof.pack() + spcbf.pack();
        res += BitArray(ig_rev_token) + BitArray(eg_rev_token);
        return res;
    }

    std::string to_string() {
        std::string pcbm_str = "[PCB Marking ad_id: " + std::to_string(ad_id) 
                                                      + "]\n";
        pcbm_str += "ig_rev_token: " + ig_rev_token + "\neg_rev_token:" 
                                     + eg_rev_token + "\n";
        pcbm_str += ssf.to_string();
        pcbm_str += hof.to_string() + "\n";
        pcbm_str += spcbf.to_string();
        return pcbm_str;
    }

    bool operator==(const PCBMarking &other) const {
        return (ad_id == other.ad_id &&
                ssf == other.ssf &&
                hof == other.hof &&
                spcbf == other.spcbf &&
                ig_rev_token == other.ig_rev_token &&
                eg_rev_token == other.eg_rev_token);
    }
};


class PeerMarking : public Marking {
    /**
     * Packs all fields for a specific peer marking.
     */
public:
    static const int LEN = 24 + 2 * 32;
    uint64_t ad_id;
    std::string ig_rev_token;
    std::string eg_rev_token;
    HopOpaqueField hof;
    SupportPeerField spf;

    PeerMarking() {
        PeerMarking("");
    }

    PeerMarking(const std::string &raw) : Marking() {
        ad_id = 0;
        ig_rev_token = "";
        eg_rev_token = "";
        if (raw.length()) 
            parse(raw);
    }

    void parse(const std::string &raw) {
        /**
         * Populates fields from a raw bytes block.
         */
        this->raw = raw;
        int dlen = raw.length();
        if (dlen < PeerMarking::LEN) {
            // logging.warning("PM: Data too short for parsing, len: %u", dlen)
            return;
        }
        BitArray bits(raw.substr(0, 8));
        ad_id = bits.get_subarray(0, 64);
        hof = HopOpaqueField(raw.substr(8, 8));
        spf = SupportPeerField(raw.substr(16, 8));
        ig_rev_token = raw.substr(24, 32);
        eg_rev_token = raw.substr(56);
        parsed = true;
    }

    PeerMarking(int ad_id, HopOpaqueField hof, SupportPeerField spf,
                std::string ingress_hash, std::string egress_hash) : Marking() {
        /**
         * Returns PeerMarking with fields populated from values.
         * 
         * :param ad_id: Autonomous Domain's ID.
         * :param hof: HopOpaqueField object.
         * :param spf: SupportPeerField object.
         * :param ig_rev_token: Revocation token for the ingress if
         *                      in the HopOpaqueField.
         * :param eg_rev_token: Revocation token for the egress if
         *                      in the HopOpaqueField.
         */
        this->ad_id = ad_id;
        this->hof = hof;
        this->spf = spf;
        if (ingress_hash.length() == 0) ig_rev_token = std::string(0, 32);
        else ig_rev_token = ingress_hash;
        if (egress_hash.length() == 0) eg_rev_token = std::string(0, 32);
        else eg_rev_token = egress_hash;
    }

    BitArray pack() const {
        /**
         * Returns PeerMarking as a binary string.
         */
        BitArray res;
        res.append(ad_id, 64);
        res += hof.pack() + spf.pack();
        res += BitArray(ig_rev_token) + BitArray(eg_rev_token);
        return res;
    }

    std::string to_string() {
        std::string pm_str = "[Peer Marking ad_id: " + std::to_string(ad_id) 
                                                     + "]\n";
        pm_str += "ig_rev_token: " + ig_rev_token + "\neg_rev_token:" 
                                   + eg_rev_token + "\n";
        pm_str += hof.to_string() + "\n";
        pm_str += spf.to_string();
        return pm_str;
    }

    bool operator==(const PeerMarking &other) const {
        return (ad_id == other.ad_id &&
                hof == other.hof &&
                spf == other.spf &&
                ig_rev_token == other.ig_rev_token &&
                eg_rev_token == other.eg_rev_token);
    }
};

class ADMarking : public Marking {
    /**
     * Packs all fields for a specific Autonomous Domain.
     */
 public:
    PCBMarking pcbm;
    std::string sig;
    std::vector<PeerMarking> pms;

    static const int LEN = PCBMarking::LEN;

    ADMarking() {
        ADMarking("");
    }

    ADMarking(const std::string &raw) : Marking() {
        sig = "";
        if (raw.length()) 
            parse(raw);
    }

    void parse(const std::string &raw) {
        /**
         * Populates fields from a raw bytes block.
         */
        this->raw = raw;
        int dlen = raw.length();
        if (dlen < ADMarking::LEN) {
            // logging.warning("AD: Data too short for parsing, len: %u", dlen)
            return;
        }
        pcbm = PCBMarking(raw.substr(0, PCBMarking::LEN));
        std::string raw_ = raw.substr(PCBMarking::LEN);
        while (raw_.length() > pcbm.ssf.sig_len) {
            pms.push_back(PeerMarking(raw_.substr(0, PeerMarking::LEN)));
            raw_ = raw_.substr(PeerMarking::LEN);
        }
        sig = raw_;
        parsed = true;
    }

    ADMarking(PCBMarking &pcbm, std::vector<PeerMarking> &pms, 
              std::string &sig) : Marking() {
        /**
         * Returns ADMarking with fields populated from values.
         * 
         * @param pcbm: PCBMarking object.
         * @param pms: List of PeerMarking objects.
         * @param sig: Beacon's signature.
         */
        pcbm.ssf.sig_len = sig.length();
        pcbm.ssf.block_size = PCBMarking::LEN + PeerMarking::LEN * pms.size();
        this->pcbm = pcbm;
        this->pms = pms;
        this->sig = sig;
    };

    BitArray pack() const {
        /**
         * Returns ADMarking as a binary string.
         */
        BitArray res = pcbm.pack();
        for (int i = 0; i < pms.size(); i++) 
            res += pms[i].pack();
        res += BitArray(sig);
        return res;
    }

    void remove_signature() {
        /**
         * Removes the signature from the AD block.
         */
        sig = "";
        pcbm.ssf.sig_len = 0;
    }

    std::string to_string() {
        std::string ad_str = "[Autonomous Domain]\n";
        ad_str += pcbm.to_string();
        for (int i = 0; i < pms.size(); i++)
            ad_str += pms[i].to_string();
        std::string encoded = base64_encode(
            reinterpret_cast<const unsigned char*>(sig.c_str()), sig.length());
        ///? decode to utf-8 required?
        ad_str += "[Signature: " + encoded + "]\n";
        return ad_str;
    }

    bool operator==(const ADMarking &other) const {
        return (pcbm == other.pcbm &&
                pms == other.pms &&
                sig == other.sig);
    }
};


class PathSegment : public Marking {
    /**
     * Packs all PathSegment fields for a specific beacon.
     */
 public:
    InfoOpaqueField iof;
    TRCField trcf;
    std::string segment_id;
    std::vector<ADMarking> ads;
    uint32_t min_exp_time;
    uint32_t size;
    static const int LEN = 16 + 32;

    PathSegment() {
        PathSegment("");
    }

    PathSegment(const std::string &raw) : Marking() {
        segment_id = std::string(0, 32);
        min_exp_time = (1 << 8 ) - 1;
        if (raw.length()) 
            parse(raw);
    }

    void parse(const std::string &raw) {
        /**
        * Populates fields from a raw bytes block.
         */        
        this->raw = raw;
        size = raw.length();
        int dlen = raw.length();
        if (dlen < PathSegment::LEN) {
            // logging.warning("PathSegment: Data too short for parsing, " +
                            // "len: %u", dlen)
            return;
        }
        // Populate the info and ROT OFs from the first and second 8-byte blocks
        // of the segment, respectively.
        iof = InfoOpaqueField(raw.substr(0, 8));
        trcf = TRCField(raw.substr(8, 8));
        segment_id = raw.substr(16, 32);
        std::string raw_ = raw.substr(48);
        for (int i = 0; i < iof.hops; i++) {
            PCBMarking pcbm(raw_.substr(0, PCBMarking::LEN));
            ADMarking ad_marking(raw_.substr(0, 
                                 pcbm.ssf.sig_len + pcbm.ssf.block_size));
            add_ad(ad_marking);
            raw_ = raw_.substr(pcbm.ssf.sig_len + pcbm.ssf.block_size);
        }
        parsed = true;
    }

    BitArray pack() const {
        /**
         * Returns PathSegment as a binary string.
         */
        BitArray res = iof.pack() + trcf.pack();
        res += BitArray(segment_id);
        for (int i = 0; i < ads.size(); i++) 
            res += ads[i].pack();
        return res;
    }

    void add_ad(const ADMarking &ad_marking) {
        /**
         * Appends a new AD block.
         */
        if (ad_marking.pcbm.hof.exp_time < min_exp_time) 
            min_exp_time = ad_marking.pcbm.hof.exp_time;
        ads.push_back(ad_marking);
        iof.hops = ads.size();
    }

    void remove_signatures() {
        /**
         * Removes the signature from each AD block.
         */
        for (int i = 0; i < ads.size(); i++) 
            ads[i].remove_signature();
    }

    CorePath get_path(bool reverse_direction = false) {
        /**
         * Returns the list of HopOpaqueFields in the path.
         */
        std::vector<HopOpaqueField> hofs;
        InfoOpaqueField iof = this->iof;
        std::vector<ADMarking> ads;
        ads.resize(this->ads.size());

        if (reverse_direction) {
            std::reverse_copy(this->ads.begin(), this->ads.end(), ads.begin());
            iof.up_flag = this->iof.up_flag ^ true;
        }
        else
            ads = this->ads;
        for (int i = 0; i < ads.size(); i++) 
            hofs.push_back(ads[i].pcbm.hof);
        return CorePath(iof, hofs, InfoOpaqueField(),
                        std::vector<HopOpaqueField>(), 
                        InfoOpaqueField(), std::vector<HopOpaqueField>());
    }

    int get_isd() {
        /**
         * Returns the ISD ID.
         */ 
        return iof.isd_id;
    }

    PCBMarking get_last_pcbm() {
        /**
         * Returns the PCBMarking belonging to the last AD on the path.
         */
        if (ads.size()) 
            return ads[ads.size() - 1].pcbm;
        else
            return PCBMarking();
        ///? should actually return a null pointer?
    }

    PCBMarking get_first_pcbm() {
        /**
         * Returns the PCBMarking belonging to the first AD on the path.
         */
        if (ads.size()) 
            return ads[0].pcbm;
        else
            return PCBMarking();
    }

    bool compare_hops(const PathSegment &other) {
        /**
         * Compares the (AD-level) hops of two half-paths. Returns true if 
         * all hops are identical and false otherwise.
         */
        std::vector<uint64_t> self_hops, other_hops;
        for (int i = 0; i < ads.size(); i++)
            self_hops.push_back(ads[i].pcbm.ad_id);
        for (int i = 0; i < other.ads.size(); i++)
            other_hops.push_back(other.ads[i].pcbm.ad_id);
        return self_hops == other_hops;
    }

    std::string get_hops_hash(bool hex = false) {
        /**
         * Returns the hash over all the interface revocation tokens included in
         * the path segment.
         */
        // h = SHA256.new()
        // for ad in ads:
        //     h.update(ad.pcbm.ig_rev_token)
        //     h.update(ad.pcbm.eg_rev_token)
        //     for pm in ad.pms:
        //         h.update(pm.ig_rev_token)
        //         h.update(pm.eg_rev_token)
        // if (hex) 
        //     return h.hexdigest()
        // return h.digest()
        std::cerr << "***UNIMPLEMENTED***" << std::endl;
        exit(-1);
        return "";
    }

    uint32_t get_n_peer_links() {
        /**
         * Return the total number of peer links in the PathSegment.
         */
        uint32_t n_peer_links = 0;
        for (int i = 0; i < ads.size(); i++) 
            n_peer_links += ads[i].pms.size();
        return n_peer_links;
    }

    uint32_t get_n_hops() {
        /**
         * Return the number of hops in the PathSegment.
         */
        return ads.size();
    }

    int get_timestamp() {
        /**
         * Returns the creation timestamp of this PathSegment.
         */
        return iof.timestamp;
    }

    void set_timestamp(uint32_t timestamp) {
        /**
         * Updates the timestamp in the IOF.
         */
        assert(timestamp < (1ULL << 32) - 1);
        iof.timestamp = timestamp;
    }

    int get_expiration_time() {
        /**
         * Returns the expiration time of the path segment in real time.
         */
        return (iof.timestamp + int(min_exp_time * EXP_TIME_UNIT));
    }

    std::vector<std::string> get_all_iftokens() {
        /**
         * Returns all interface revocation tokens included in the path segment.
         */
        std::vector<std::string> tokens;
        for (int i = 0; i < ads.size(); i++) {
            tokens.push_back(ads[i].pcbm.ig_rev_token);
            tokens.push_back(ads[i].pcbm.eg_rev_token);
            for (int j = 0; j < ads[i].pms.size(); i++) {
                tokens.push_back(ads[i].pms[j].ig_rev_token);
                tokens.push_back(ads[i].pms[j].eg_rev_token);
            }
        }
        return tokens;
    }

    static std::vector<PathSegment> deserialize(std::string raw) {
        /**
         * Deserializes a bytes string into a list of PathSegments.
         */
        int dlen = raw.length();
        if (dlen < PathSegment::LEN) {
            // logging.warning("HPB: Data too short for parsing, len: %u", dlen)
            return std::vector<PathSegment>();
        }
        std::vector<PathSegment> pcbs;
        while (raw.length() > 0) {
            PathSegment pcb;
            pcb.iof = InfoOpaqueField(raw.substr(0, 8));
            pcb.trcf = TRCField(raw.substr(8, 8));
            pcb.segment_id = raw.substr(16, 32);
            raw = raw.substr(48);
            for (int i = 0; i < pcb.iof.hops; i++) {
                PCBMarking pcbm(raw.substr(0, PCBMarking::LEN));
                ADMarking ad_marking(raw.substr(0, pcbm.ssf.sig_len +
                                           pcbm.ssf.block_size));
                pcb.add_ad(ad_marking);
                raw = raw.substr(pcbm.ssf.sig_len + pcbm.ssf.block_size);
            }
            pcbs.push_back(pcb);
        }
        return pcbs;
    }

    static std::string serialize(const std::vector<PathSegment> &pcbs) {
        /**
         * Serializes a list of PathSegments into a bytes string.
         */
        std::string pcbs_list;
        for (int i = 0; i < pcbs.size(); i++) 
            pcbs_list += pcbs[i].pack().get_string();
        return pcbs_list;
    }

    std::string to_string() {
        std::string pcb_str = "[PathSegment]\n";
        pcb_str += "Segment ID: " + segment_id + "\n";
        pcb_str += iof.to_string() + "\n" + trcf.to_string() + "\n";
        for (int i = 0; i < ads.size(); i++) 
            pcb_str += ads[i].to_string();
        return pcb_str;
    }

    bool operator==(const PathSegment &other) const {
        return (iof == other.iof &&
                trcf == other.trcf &&
                ads == other.ads);
    }
};

class PathConstructionBeacon : public SCIONPacket {
    /**
     * PathConstructionBeacon packet, used for path propagation.
     */
public:
    PathSegment pcb;
    PathConstructionBeacon(const std::string &raw) : SCIONPacket() {
        if (raw.length()) 
            parse(raw);
    }

    void parse(const std::string &raw) {
        SCIONPacket::parse(raw);
        pcb = PathSegment(payload);
    }

    PathConstructionBeacon(std::pair<uint16_t, uint64_t> src_isd_ad, 
                        SCIONAddr &dst, PathSegment &pcb) : SCIONPacket() {
        /**
         * Returns a PathConstructionBeacon packet with the values specified.
         * 
         * :param src_isd_ad: Source's 'ISD_AD' namedtuple.
         * :param dst: Destination address (must be a 'SCIONAddr' object)
         * :param pcb: Path Construction PathConstructionBeacon ('PathSegment'
         *             class)
         */
        this->pcb = pcb;
        SCIONAddr src(src_isd_ad.first, src_isd_ad.second, &PacketType::BEACON);
        hdr = SCIONHeader(src, dst);
    }

    BitArray pack() {
        payload = pcb.pack().get_string();
        return SCIONPacket::pack();
    }
};

#endif // PCB_CPP
