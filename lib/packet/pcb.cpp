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
#define REV_TOKEN_LEN 32

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

    std::string pack() const {
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
	uint16_t isd_id:12;
    uint32_t ad_id:20;
    HopOpaqueField hof;
    std::string ig_rev_token;
    static const int LEN = 12 + REV_TOKEN_LEN;

    PCBMarking() {
        PCBMarking("");
    }

    PCBMarking(const std::string &raw) : Marking() {
    	isd_id = 0;
        ad_id = 0;
        ig_rev_token = std::string(REV_TOKEN_LEN, 0);
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
            LOG(WARNING) << "PCBM: Data too short for parsing, len: " << dlen;
            return;
        }
        ISD_AD isd_ad(raw.substr(0, ISD_AD::LEN));
        isd_id = isd_ad.isd;
        ad_id = isd_ad.ad;
        int offset = ISD_AD::LEN;
        hof = HopOpaqueField(raw.substr(offset, HopOpaqueField::LEN));
        offset += HopOpaqueField::LEN;
        ig_rev_token = raw.substr(offset, REV_TOKEN_LEN);
        parsed = true;
    }

    PCBMarking(int16_t isd_id, int32_t ad_id, HopOpaqueField hof, 
    	std::string ig_rev_token=std::string(REV_TOKEN_LEN, 0)) : Marking() {
        /**
         * Returns PCBMarking with fields populated from values.
         * 
         * :param ad_id: Autonomous Domain's ID.
         * :param hof: HopOpaqueField object.
         * :param ig_rev_token: Revocation token for the ingress if
         *                      in the HopOpaqueField.
         */
        this->isd_id = isd_id;
        this->ad_id = ad_id;
        this->hof = hof;
        this->ig_rev_token = ig_rev_token;
    }

    std::string pack() const {
        /**
         * Returns PCBMarking as a binary string.
         */
        return ISD_AD(isd_id, ad_id).pack() + hof.pack() + ig_rev_token;
    }

    std::string to_string() {
        std::string pcbm_str = "[PCB Marking isd,ad (" + std::to_string(isd_id) 
                               + ", " + std::to_string(ad_id) + ")]\n";
        pcbm_str += "ig_rev_token: " + ig_rev_token + "\n";
        pcbm_str += hof.to_string() + "\n";
        return pcbm_str;
    }

    bool operator==(const PCBMarking &other) const {
        return (isd_id == other.isd_id && 
                ad_id == other.ad_id &&
                hof == other.hof &&
                ig_rev_token == other.ig_rev_token);
    }
};


class ADMarking : public Marking {
    /**
     * Packs all fields for a specific Autonomous Domain.
     */
 public:
    static const int METADATA_LEN = 8;
    PCBMarking pcbm;
    std::vector<PCBMarking> pms;
    std::string sig;
    std::string asd;
    std::string eg_rev_token;
    int cert_ver;
    int sig_len;
    int asd_len;
    int block_len;

    ADMarking() {
        ADMarking("");
    }

    ADMarking(const std::string &raw) : Marking() {
        sig = "";
        asd = "";
        eg_rev_token = std::string(REV_TOKEN_LEN, 0);
        cert_ver = 0;
        sig_len = 0;
        asd_len = 0;
        block_len = 0;
        if (raw.length())
            parse(raw);
    }

    void parse(const std::string &raw) {
        /**
         * Populates fields from a raw bytes block.
         */
        this->raw = raw;
        int dlen = raw.length();
        if (dlen < PCBMarking::LEN + METADATA_LEN + REV_TOKEN_LEN) {
            LOG(WARNING) << "AD: Data too short for parsing, len: " << dlen; 
            return;
        }
        std::cerr << "***UNIMPLEMENTED***" << std::endl;
        // pcbm = PCBMarking(raw.substr(0, PCBMarking::LEN));
        // std::string raw_ = raw.substr(PCBMarking::LEN);
        // while (raw_.length() > pcbm.ssf.sig_len) {
        //     pms.push_back(PeerMarking(raw_.substr(0, PeerMarking::LEN)));
        //     raw_ = raw_.substr(PeerMarking::LEN);
        // }
        // sig = raw_;
        parsed = true;
    }

    ADMarking(PCBMarking &pcbm, std::vector<PCBMarking> &pms,
              const std::string &eg_rev_token=std::string(REV_TOKEN_LEN, 0),
              const std::string &sig="", const std::string &asd="") : Marking() {
        /**
         * Returns ADMarking with fields populated from values.
         * 
         * @param pcbm: PCBMarking object.
         * @param pms: List of PeerMarking objects.
         * @param sig: Beacon's signature.
         */
        this->pcbm = pcbm;
        this->pms = pms;
        this->block_len = (1 + pms.size()) * PCBMarking::LEN;
        this->sig = sig;
        this->sig_len = sig.length();
        this->asd = asd;
        this->asd_len = asd.length();
        this->eg_rev_token = eg_rev_token;
    };

    std::string pack() const {
        /**
         * Returns ADMarking as a binary string.
         */
        std::cerr << "***UNIMPLEMENTED***" << std::endl;
        std::string res = pcbm.pack();
        // for (int i = 0; i < pms.size(); i++) 
        //     res += pms[i].pack();
        //     res += BitArray(sig);
        return res;
    }

    void remove_signature() {
        /**
         * Removes the signature from the AD block.
         */
        sig = "";
        sig_len = 0;
    }

    void remove_asd() {
        /**
         * Removes the Additional Signed Data (ASD) from the AD block.
         * Note that after ASD is removed, a corresponding signature is invalid.
         */
        asd = "";
        asd_len = 0;
    }

    std::string to_string() {
        std::string ad_str = "[Autonomous Domain]\n";
        // ad_str += pcbm.to_string();
        // for (int i = 0; i < pms.size(); i++)
        //     ad_str += pms[i].to_string();
        // std::string encoded = base64_encode(
        //     reinterpret_cast<const unsigned char*>(sig.c_str()), sig.length());
        // ///? decode to utf-8 required?
        // ad_str += "[Signature: " + encoded + "]\n";
        return ad_str;
    }

    bool operator==(const ADMarking &other) const {
        return (pcbm == other.pcbm &&
                pms == other.pms &&
                asd == other.asd &&
                eg_rev_token == other.eg_rev_token &&
                sig == other.sig);
    }
};


class PathSegment : public Marking {
    /**
     * Packs all PathSegment fields for a specific beacon.
     */
 public:
    InfoOpaqueField iof;
    int trc_ver;
    int if_id;
    std::string segment_id;
    std::vector<ADMarking> ads;
    uint32_t min_exp_time;
    static const int MIN_LEN = 14 + REV_TOKEN_LEN;

    PathSegment() {
        PathSegment("");
    }

    PathSegment(const std::string &raw) : Marking() {
        trc_ver = 0;
        if_id = 0;
        segment_id = std::string(REV_TOKEN_LEN, 0);
        min_exp_time = (1 << 8) - 1;        
        if (raw.length()) 
            parse(raw);
    }

    void parse(const std::string &raw) {
        /**
        * Populates fields from a raw bytes block.
         */        
        this->raw = raw;
        int dlen = raw.length();
        if (dlen < PathSegment::MIN_LEN) {
            LOG(WARNING) << "PathSegment: Data too short for parsing, len: "
                         << dlen;
            return;
        }
        // Populate the info and ROT OFs from the first and second 8-byte blocks
        // of the segment, respectively.
        iof = InfoOpaqueField(raw.substr(0, InfoOpaqueField::LEN));
        int offset = InfoOpaqueField::LEN;
        BitArray bits(raw.substr(offset, 6));
        trc_ver = bits.get_subarray(0, 32);
        if_id = bits.get_subarray(32, 16);
        offset += 6;
        segment_id = raw.substr(offset, REV_TOKEN_LEN);
        offset += REV_TOKEN_LEN;
        std::string raw_ = raw.substr(offset);
        for (int i = 0; i < iof.hops; i++) {
            BitArray bits(raw_.substr(0, ADMarking::METADATA_LEN));
            int asd_len = bits.get_subarray(16, 16);
            int sig_len = bits.get_subarray(32, 16);
            int block_len = bits.get_subarray(48, 16);
            int ad_len = sig_len + asd_len + block_len + ADMarking::METADATA_LEN 
                        + REV_TOKEN_LEN;
            ADMarking ad_marking = ADMarking(raw_.substr(0, ad_len));
            add_ad(ad_marking);
            raw_ = raw_.substr(ad_len);
        }
        parsed = true;
    }

    std::string pack() const {
        /**
         * Returns PathSegment as a binary string.
         */
        std::string res = iof.pack();
        BitArray bits;
        bits.append(trc_ver, 32);
        bits.append(if_id, 16);
        res += bits.to_string();
        res += segment_id;
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

    ADMarking get_last_adm() {
        /**
         * Returns the last ADMarking on the path.
         */
        if (ads.size())
            return ads[ads.size()-1];
        else
            return ADMarking();
            ///? should return a null pointer?
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
            tokens.push_back(ads[i].eg_rev_token);
            for (int j = 0; j < ads[i].pms.size(); i++) {
                tokens.push_back(ads[i].pms[j].ig_rev_token);
            }
        }
        return tokens;
    }

    static std::vector<PathSegment> deserialize(std::string raw) {
        /**
         * Deserializes a bytes string into a list of PathSegments.
         */
        // int dlen = raw.length();
        // if (dlen < PathSegment::LEN) {
        //     LOG(WARNING) << "HPB: Data too short for parsing, len: " << dlen; 
        //     return std::vector<PathSegment>();
        // }
        std::vector<PathSegment> pcbs;
        // while (raw.length() > 0) {
        //     PathSegment pcb;
        //     pcb.iof = InfoOpaqueField(raw.substr(0, 8));
        //     pcb.trcf = TRCField(raw.substr(8, 8));
        //     pcb.segment_id = raw.substr(16, 32);
        //     raw = raw.substr(48);
        //     for (int i = 0; i < pcb.iof.hops; i++) {
        //         PCBMarking pcbm(raw.substr(0, PCBMarking::LEN));
        //         ADMarking ad_marking(raw.substr(0, pcbm.ssf.sig_len +
        //                                    pcbm.ssf.block_size));
        //         pcb.add_ad(ad_marking);
        //         raw = raw.substr(pcbm.ssf.sig_len + pcbm.ssf.block_size);
        //     }
        //     pcbs.push_back(pcb);
        // }
        std::cerr << "***UNIMPLEMENTED***" << std::endl;
        return pcbs;
    }

    static std::string serialize(const std::vector<PathSegment> &pcbs) {
        /**
         * Serializes a list of PathSegments into a bytes string.
         */
        std::string pcbs_list;
        for (int i = 0; i < pcbs.size(); i++) 
            pcbs_list += pcbs[i].pack();
        return pcbs_list;
    }

    std::string to_string() {
        std::string pcb_str = "[PathSegment]\n";
        // pcb_str += "Segment ID: " + segment_id + "\n";
        // pcb_str += iof.to_string() + "\n" + trcf.to_string() + "\n";
        // for (int i = 0; i < ads.size(); i++) 
        //     pcb_str += ads[i].to_string();
        std::cerr << "***UNIMPLEMENTED***" << std::endl;
        return pcb_str;
    }

    bool operator==(const PathSegment &other) const {
        return (iof == other.iof &&
                trc_ver == other.trc_ver &&
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

    PathConstructionBeacon(ISD_AD src_isd_ad, SCIONAddr &dst, 
        PathSegment &pcb) : SCIONPacket() {
        /**
         * Returns a PathConstructionBeacon packet with the values specified.
         * 
         * :param src_isd_ad: Source's 'ISD_AD' namedtuple.
         * :param dst: Destination address (must be a 'SCIONAddr' object)
         * :param pcb: Path Construction PathConstructionBeacon ('PathSegment'
         *             class)
         */
        this->pcb = pcb;
        SCIONAddr src(src_isd_ad.isd, src_isd_ad.ad, &PacketType::BEACON);
        hdr = SCIONHeader(src, dst);
    }

    std::string pack() {
        payload = pcb.pack();
        return SCIONPacket::pack();
    }
};

#endif // PCB_CPP
