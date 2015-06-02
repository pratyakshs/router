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
/* :mod:`path` --- SCION Path packets
 * ===========================================
 */
#ifndef PATH_CPP
#define PATH_CPP

#include "opaque_field.cpp"
#include <algorithm>

class PathBase {
    /**
     * Base class for paths in SCION.
     *
     * A path is a sequence of path segments dependent on the type of path. Path
     * segments themselves are a sequence of opaque fields containing routing
     * information for each AD-level hop.
     */
protected:
    InfoOpaqueField up_segment_info;
    std::vector<HopOpaqueField> up_segment_hops;
    InfoOpaqueField down_segment_info;
    std::vector<HopOpaqueField> down_segment_hops;
    bool parsed;
public:
    PathBase() {
        parsed = false;
    }

    void parse(const std::string &raw) {}

    BitArray pack() const {}

    void reverse() {
        /**
         * Reverses the segment.
         */
        // Swap down segment and up segment.
        std::vector<HopOpaqueField> temp_hops = up_segment_hops;
        up_segment_hops = down_segment_hops;
        down_segment_hops = temp_hops;

        InfoOpaqueField temp_info = up_segment_info;
        up_segment_info = down_segment_info;
        down_segment_info = temp_info;

        // Reverse flags.
        //? not checking here if up_segment_info
        //? and down_segment_info were initialized.
        up_segment_info.up_flag ^= true;
        down_segment_info.up_flag ^= true;
        // Reverse hops.
        std::reverse(up_segment_hops.begin(), up_segment_hops.end());
        std::reverse(down_segment_hops.begin(), down_segment_hops.end());
    }

    bool is_last_hop(HopOpaqueField hop) {
        /**
         * Returns true if 'hop' equals to the last down-segment hop.
         */
        return (hop == down_segment_hops[down_segment_hops.size()-1]);
    }

    bool is_first_hop(HopOpaqueField hop) {
        /**
         * Returns true if 'hop' equals to the first up-segment hop.
         */
        return (hop == up_segment_hops[0]);
    }

    HopOpaqueField * get_first_hop_of() {
        /**
         * Depending on up_segment flag returns the first up- or down-segment hop.
         */
        if (up_segment_hops.size())
            return &up_segment_hops[0];
        else if (down_segment_hops.size()) 
            return &down_segment_hops[0];
        else return NULL;
    }

    CommonOpaqueField* get_of(int index) {
        /**
         * Returns the opaque field for the given index.
         */
        if (index == 0)
            return &up_segment_info;
        if (index <= up_segment_hops.size())
            return &up_segment_hops[index-1];
        if (index == up_segment_hops.size() + 1)
            return &down_segment_info;
        if (index <= up_segment_hops.size() + 1 + down_segment_hops.size())
            return &down_segment_hops[index - 2 - up_segment_hops.size()];
        return NULL;
    }

    std::string to_string() { return ""; }

    std::string __repr__() {
        return to_string();
    }
};


class CorePath : public PathBase {
    /**
     * A (non-shortcut) path through the ISD core.
     * 
     * The sequence of opaque fields for such a path is:
     * | info OF up-segment | hop OF 1 | ... | hop OF N | info OF core-segment |
     * | hop OF 1 \ ... | hop OF N | info OF down-segment |
     * | hop OF 1 | ... | hop OF N |
     */
    InfoOpaqueField core_segment_info;
    std::vector<HopOpaqueField> core_segment_hops;
 public:
    CorePath(const std::string &raw) : PathBase() {
        if (raw.length())
            parse(raw);
    }

    // TODO PSz: a flag is needed to distinguish downPath-only case. I.e. if
    // SCIONPacket.up_path is false and path has only one special OF, then it
    // should parse only DownPath. It would be easier to put down/up flag to SOF.
    void parse(const std::string &raw) {
        /**
         * Parses the raw data and populates the fields accordingly.
         */
        // Parse up-segment
        up_segment_info = InfoOpaqueField(raw.substr(0, InfoOpaqueField::LEN));
        int offset = InfoOpaqueField::LEN;
        for (int i = 0; i < up_segment_info.hops; i++) {
            up_segment_hops.push_back(
                HopOpaqueField(raw.substr(offset, HopOpaqueField::LEN)));
            offset += HopOpaqueField::LEN;
        }
        // Parse core-segment
        if (raw.length() != offset) {
            core_segment_info = InfoOpaqueField(raw.substr(offset, 
                                                InfoOpaqueField::LEN));
            offset += InfoOpaqueField::LEN; 

            for (int i = 0; i < core_segment_info.hops; i++) {
                core_segment_hops.push_back(HopOpaqueField(
                    raw.substr(offset, HopOpaqueField::LEN)));
                offset += HopOpaqueField::LEN;
            }
        }
        // Parse down-segment
        if (raw.length() != offset) {
            down_segment_info = InfoOpaqueField(
                raw.substr(offset, InfoOpaqueField::LEN));
            offset += InfoOpaqueField::LEN;
            for (int i = 0; i < down_segment_info.hops; i++) {
                down_segment_hops.push_back(HopOpaqueField(raw.substr(
                                    offset, HopOpaqueField::LEN)));
                offset += HopOpaqueField::LEN;
            }
        }
        parsed = true;
    }

    BitArray pack() const {
        /**
         * Packs the opaque fields and returns a byte array.
         */
        BitArray bits;
        if (true) {///? check if up_segment_info is set 
            bits += up_segment_info.pack();
            for (int i = 0; i < up_segment_hops.size(); i++) 
                bits += up_segment_hops[i].pack();
        }
        if (true) {///? check if core_segment_info is set 
            bits += core_segment_info.pack();
            for (int i = 0; i < core_segment_hops.size(); i++) 
                bits += core_segment_hops[i].pack();
        }
        if (true) {///? check if down_segment_info is set 
            bits += down_segment_info.pack();
            for (int i = 0; i < down_segment_hops.size(); i++) 
                bits += down_segment_hops[i].pack(); 
        }
        return bits;
    }

    void reverse() {
        PathBase::reverse();
        std::reverse(core_segment_hops.begin(), core_segment_hops.end());
        if (true) ///? check if core_segment_info is not None
            core_segment_info.up_flag ^= true;
    }

    CommonOpaqueField* get_of(int index) {
        /**
         * Returns the opaque field for the given index.
         */
        ///? check is up_segment_info, core_segment_info are not NULL.
        if (index == 0)
            return &up_segment_info;
        if (index <= up_segment_hops.size()) 
            return &up_segment_hops[index - 1];
        if (index == up_segment_hops.size() + 1)
            return &core_segment_info;
        if (index <= up_segment_hops.size() + 1 + core_segment_hops.size())
            return &core_segment_hops[index - 2 - up_segment_hops.size()];
        if (index == up_segment_hops.size() + 2 + core_segment_hops.size())
            return &down_segment_info;
        if (index <= up_segment_hops.size() + 2 + core_segment_hops.size() 
                                            + down_segment_hops.size())
            return &down_segment_hops[index - 3 - core_segment_hops.size()
                                            - down_segment_hops.size()];
        return NULL;
    }

    CorePath(InfoOpaqueField up_inf, std::vector<HopOpaqueField> up_hops,
             InfoOpaqueField core_inf, std::vector<HopOpaqueField> core_hops,
             InfoOpaqueField dw_inf, std::vector<HopOpaqueField> dw_hops) {
        /**
         * Returns CorePath with the values specified.
         * @param up_inf: InfoOpaqueField of up_segment
         * @param up_hops: list of HopOpaqueField of up_segment
         * @param core_inf: InfoOpaqueField for core_segment
         * @param core_hops: list of HopOpaqueFields of core_segment
         * @param dw_inf: InfoOpaqueField of down_segment
         * @param dw_hops: list of HopOpaqueField of down_segment
         */
        up_segment_info = up_inf;
        up_segment_hops = up_hops;
        core_segment_info = core_inf;
        core_segment_hops = core_hops;
        down_segment_info = dw_inf;
        down_segment_hops = dw_hops;
    }

    std::string to_string() {
        // s = []
        // s.push_back("<Core-Path>:\n")

        // if self.up_segment_info:
        //     s.push_back("<Up-Segment>:\n")
        //     s.push_back(str(self.up_segment_info) + "\n")
        //     for of in self.up_segment_hops:
        //         s.push_back(str(of) + "\n")
        //     s.push_back("</Up-Segment>\n")

        // if self.core_segment_info:
        //     s.push_back("<Core-Segment>\n")
        //     s.push_back(str(self.core_segment_info) + "\n")
        //     for of in self.core_segment_hops:
        //         s.push_back(str(of) + "\n")
        //     s.push_back("</Core-Segment>\n")

        // if self.down_segment_info:
        //     s.push_back("<Down-Segment>\n")
        //     s.push_back(str(self.down_segment_info) + "\n")
        //     for of in self.down_segment_hops:
        //         s.push_back(str(of) + "\n")
        //     s.push_back("</Down-Segment>\n")

        // s.push_back("</Core-Path>")
        // return "".join(s)
        std::cerr << "***UNIMPLEMENTED***" << std::endl;
        return "";
    }
};


class CrossOverPath : public PathBase {
    /**
     * A shortcut path using a cross-over link.
     * 
     * The sequence of opaque fields for such a path is:
     * | info OF up-segment |  hop OF 1 | ... | hop OF N | upstream AD OF |
     * | info OF down-segment | upstream AD OF | hop OF 1 | ... | hop OF N |
     * The upstream AD OF is needed to verify the last hop of the up-segment /
     * first hop of the down-segment respectively.
     */
    HopOpaqueField up_segment_upstream_ad;
    HopOpaqueField down_segment_upstream_ad;
public:
    CrossOverPath(const std::string &raw) : PathBase() {
        // up_segment_upstream_ad = HopOpaqueField("");
        // down_segment_upstream_ad = HopOpaqueField("");
        if (raw.length())
            parse(raw);
    }

    void parse(const std::string &raw) {
        /**
         * Parses the raw data and populates the fields accordingly.
         */
        // Parse up-segment
        up_segment_info = InfoOpaqueField(raw.substr(0, InfoOpaqueField::LEN));
        int offset = InfoOpaqueField::LEN;
        for (int i = 0; i < up_segment_info.hops; i++) {
            up_segment_hops.push_back(HopOpaqueField(raw.substr(offset, 
                                                     HopOpaqueField::LEN)));
            offset += HopOpaqueField::LEN;
        }
        up_segment_upstream_ad = HopOpaqueField(raw.substr(offset, 
                                                HopOpaqueField::LEN));
        offset += HopOpaqueField::LEN;

        // Parse down-segment
        down_segment_info = InfoOpaqueField(raw.substr(offset, 
                                            InfoOpaqueField::LEN));
        offset += InfoOpaqueField::LEN;
        down_segment_upstream_ad = HopOpaqueField(raw.substr(offset, 
                                                  HopOpaqueField::LEN));
        offset += HopOpaqueField::LEN;
        for (int i = 0; i < down_segment_info.hops; i++) {
            down_segment_hops.push_back(
                HopOpaqueField(raw.substr(offset, HopOpaqueField::LEN)));
            offset += HopOpaqueField::LEN;
        }
        parsed = true;
    }

    BitArray pack() const {
        /**
         * Packs the opaque fields and returns a byte array.
         */
        BitArray res;
        res += up_segment_info.pack();
        for (int i = 0; i < up_segment_hops.size(); i++) 
            res += up_segment_hops[i].pack();
        
        res += up_segment_upstream_ad.pack();
        res += down_segment_info.pack();
        res += down_segment_upstream_ad.pack();
        for (int i = 0; i < down_segment_hops.size(); i++) 
            res += down_segment_hops[i].pack();
        return res;
    }

    void reverse() {
        // Reverse hops and info fields.
        PathBase::reverse();
        // Reverse upstream AD fields.
        HopOpaqueField temp = up_segment_upstream_ad;
        up_segment_upstream_ad = down_segment_upstream_ad;
        down_segment_upstream_ad = temp;
    }

    CommonOpaqueField* get_of(int index) {
        // Build temporary flat list of opaque fields.
        if (index == 0)
            return &up_segment_info;
        if (index <= up_segment_hops.size()) 
            return &up_segment_hops[index - 1];
        if (index == up_segment_hops.size() + 1)
            return &up_segment_upstream_ad;
        if (index == up_segment_hops.size() + 2)
            return &down_segment_info;
        if (index == up_segment_hops.size() + 3)
            return &down_segment_upstream_ad;
        if (index <= up_segment_hops.size() + 3 + down_segment_hops.size())
            return &down_segment_hops[index - 4 + up_segment_hops.size()];
        return NULL;
    }

    std::string to_string() {
        // s = []
        // s.push_back("<CrossOver-Path>:\n<Up-Segment>:\n")
        // s.push_back(str(self.up_segment_info) + "\n")
        // for of in self.up_segment_hops:
        //     s.push_back(str(of) + "\n")
        // s.push_back("Upstream AD: " + str(self.up_segment_upstream_ad) + "\n")
        // s.push_back("</Up-Segment>\n<Down-Segment>\n")
        // s.push_back(str(self.down_segment_info) + "\n")
        // s.push_back("Upstream AD: " + str(self.down_segment_upstream_ad) + "\n")
        // for of in self.down_segment_hops:
        //     s.push_back(str(of) + "\n")
        // s.push_back("</Down-Segment>\n</CrossOver-Path>")

        // return "".join(s)
        std::cerr << "***UNIMPLEMENTED***" << std::endl;
        exit(-1);
        return "";
    }
};


class PeerPath : public PathBase {
    /**
     * A shortcut path using a crossover link.
     * 
     * The sequence of opaque fields for such a path is:
     * | info OF up-segment |  hop OF 1 | ... | hop OF N | peering link OF |
     * | upstream AD OF | info OF down-segment | upstream AD OF | peering link OF |
     * | hop OF 1 | ... | hop OF N |
     * The upstream AD OF is needed to verify the last hop of the up-segment /
     * first hop of the down-segment respectively.
     */
    HopOpaqueField up_segment_peering_link;
    HopOpaqueField up_segment_upstream_ad;
    HopOpaqueField down_segment_peering_link;
    HopOpaqueField down_segment_upstream_ad;
public:
    PeerPath(const std::string &raw) : PathBase() {
        if (raw.length())
            parse(raw);
    }

    void parse(const std::string &raw) {
        /**
         * Parses the raw data and populates the fields accordingly.
         */
        // Parse up-segment
        up_segment_info = InfoOpaqueField(raw.substr(0, InfoOpaqueField::LEN));
        int offset = InfoOpaqueField::LEN;
        for (int i = 0; i < up_segment_info.hops; i++) {
            up_segment_hops.push_back(
                HopOpaqueField(raw.substr(offset, HopOpaqueField::LEN)));
            offset += HopOpaqueField::LEN;
        }
        up_segment_peering_link = HopOpaqueField(raw.substr(offset, 
                                                 HopOpaqueField::LEN));
        offset += HopOpaqueField::LEN;
        up_segment_upstream_ad = HopOpaqueField(raw.substr(offset, 
                                                HopOpaqueField::LEN));
        offset += HopOpaqueField::LEN;

        // Parse down-segment
        down_segment_info = InfoOpaqueField(raw.substr(offset, 
                                            InfoOpaqueField::LEN));
        offset += InfoOpaqueField::LEN;
        down_segment_upstream_ad = HopOpaqueField(raw.substr(offset, 
                                                  HopOpaqueField::LEN));
        offset += HopOpaqueField::LEN;
        down_segment_peering_link = HopOpaqueField(raw.substr(offset, 
                                                   HopOpaqueField::LEN));
        offset += HopOpaqueField::LEN;
        for (int i = 0; i < down_segment_info.hops; i++) {
            down_segment_hops.push_back(HopOpaqueField(raw.substr(offset, 
                                        HopOpaqueField::LEN)));
            offset += HopOpaqueField::LEN;
        }
        parsed = true;
    }

    BitArray pack() const {
        /**
         * Packs the opaque fields and returns a byte array.
         */
        BitArray res;
        res += up_segment_info.pack();
        for (int i = 0; i < up_segment_hops.size(); i++) 
            res += up_segment_hops[i].pack();
        res += up_segment_peering_link.pack();
        res += up_segment_upstream_ad.pack();
        res += down_segment_info.pack();
        res += down_segment_upstream_ad.pack();
        res += down_segment_peering_link.pack();
        for (int i = 0; i < down_segment_hops.size(); i++) 
            res += down_segment_hops[i].pack();
        return res;
    }

    void reverse() {
        // Reverse hop and info fields.
        PathBase::reverse();
        // Reverse upstream AD and peering link fields.
        HopOpaqueField temp = up_segment_upstream_ad;
        up_segment_upstream_ad = down_segment_upstream_ad;
        down_segment_upstream_ad = temp;

        temp = up_segment_peering_link; 
        up_segment_peering_link = down_segment_peering_link;
        down_segment_peering_link = temp;
    }

    CommonOpaqueField* get_of(int index) {
        // Build temporary flat list of opaque fields.
        if (index == 0)
            return &up_segment_info;
        if (index <= up_segment_hops.size())
            return &up_segment_hops[index - 1];
        if (index == up_segment_hops.size() + 1)
            return &up_segment_peering_link;
        if (index == up_segment_hops.size() + 2)
            return &up_segment_upstream_ad;
        if (index == up_segment_hops.size() + 3)
            return &up_segment_upstream_ad;
        if (index == up_segment_hops.size() + 4)
            return &down_segment_upstream_ad;
        if (index == up_segment_hops.size() + 5)
            return &down_segment_peering_link;
        if (index <= up_segment_hops.size() + 5 + down_segment_hops.size())
            return &down_segment_hops[index - up_segment_hops.size() - 6];
        return NULL;
    }

    std::string to_string() {
        // s = []
        // s.push_back("<Peer-Path>:\n<Up-Segment>:\n")
        // s.push_back(str(self.up_segment_info) + "\n")
        // for of in self.up_segment_hops:
        //     s.push_back(str(of) + "\n")
        // s.push_back("Upstream AD: " + str(self.up_segment_upstream_ad) + "\n")
        // s.push_back("Peering link: " + str(self.up_segment_peering_link) + "\n")
        // s.push_back("</Up-Segment>\n<Down-Segment>\n")
        // s.push_back(str(self.down_segment_info) + "\n")
        // s.push_back("Peering link: " + str(self.down_segment_peering_link) + "\n")
        // s.push_back("Upstream AD: " + str(self.down_segment_upstream_ad) + "\n")
        // for of in self.down_segment_hops:
        //     s.push_back(str(of) + "\n")
        // s.push_back("</Down-Segment>\n</Peer-Path>")

        // return "".join(s)
        std::cerr << "***UNIMPLEMENTED***" << std::endl;
        exit(-1);
        return "";
    }
};

class EmptyPath : public PathBase {
    /**
     * Represents an empty path.
     * 
     * This is currently needed for intra AD communication, which doesn't need a
     * SCION path but still uses SCION packets for communication.
     */
public:
    EmptyPath() : PathBase() {}

    EmptyPath(const std::string &raw) : PathBase() {
        if (raw.length())
            parse(raw);
    }

    void parse(const std::string &raw) {
        up_segment_info = InfoOpaqueField(raw.substr(0, InfoOpaqueField::LEN));
        // We do this so we can still reverse the segment.
        down_segment_info = up_segment_info;
        parsed = true;
    }

    BitArray pack(){
        return BitArray();
    }

    bool is_first_hop(HopOpaqueField hop) {
        return true;
    }

    bool is_last_hop(HopOpaqueField hop) {
        return true;
    }

    HopOpaqueField* get_first_hop_of() {
        return NULL;
    }

    CommonOpaqueField* get_of(int index) {
        return &up_segment_info;
    }

    std::string to_string() {
        return "<Empty-Path></Empty-Path>";
    }
};


class PathCombinator {
    /**
     * Class that contains functions required to build end-to-end SCION paths.
     */

    // static CorePath _build_core_path(up_segment, core_segment, down_segment) {
    //     /**
    //      * Joins up_, core_ and down_segment into core fullpath. core_segment can
    //      * be 'None' in case of a intra-ISD core_segment of length 0.
    //      * Returns object of CorePath class. core_segment (if exists) has to have
    //      * down-segment orientation.
    //      */
    //     if (not up_segment or not down_segment or
    //             not up_segment.ads or not down_segment.ads):
    //         return None

    //     // If we have a core segment, check that the core_segment connects the
    //     // up_ and down_segment. Otherwise, check that up- and down-segment meet
    //     // at a single core AD.
    //     if ((core_segment and
    //             (core_segment.get_last_pcbm().ad_id !=
    //              up_segment.get_first_pcbm().ad_id) or
    //             (core_segment.get_first_pcbm().ad_id !=
    //              down_segment.get_first_pcbm().ad_id)) or
    //             (not core_segment and
    //              (up_segment.get_first_pcbm().ad_id !=
    //               down_segment.get_first_pcbm().ad_id))):
    //         return None

    //     full_path = CorePath()
    //     full_path.up_segment_info = up_segment.iof
    //     full_path.up_segment_info.up_flag = True
    //     for block in reversed(up_segment.ads):
    //         full_path.up_segment_hops.push_back(copy.deepcopy(block.pcbm.hof))
    //     full_path.up_segment_hops[-1].info = OpaqueFieldType.LAST_OF

    //     if core_segment:
    //         full_path.core_segment_info = core_segment.iof
    //         full_path.core_segment_info.up_flag = True
    //         for block in reversed(core_segment.ads):
    //             full_path.core_segment_hops.push_back(
    //                 copy.deepcopy(block.pcbm.hof))
    //         full_path.core_segment_hops[0].info = OpaqueFieldType.LAST_OF

    //     full_path.down_segment_info = down_segment.iof
    //     full_path.down_segment_info.up_flag = False
    //     for block in down_segment.ads:
    //         full_path.down_segment_hops.push_back(copy.deepcopy(block.pcbm.hof))
    //     full_path.down_segment_hops[0].info = OpaqueFieldType.LAST_OF
    //     return full_path

    // @staticmethod
    // def _join_shortcuts(up_segment, down_segment, point, peer=True) {
    //     *
    //     Joins up_ and down_segment (objects of PCB class) into a shortcut
    //     fullpath.
    //     Depending on the scenario returns an object of type PeerPath or
    //     CrossOverPath class.
    //     point: tuple (up_segment_index, down_segment_index) position of
    //            peer/xovr link
    //     peer:  true for peer, false for xovr path
    //     *
    //     up_segment = copy.deepcopy(up_segment)
    //     down_segment = copy.deepcopy(down_segment)
    //     (up_index, dw_index) = point

    //     if peer:
    //         path = PeerPath()
    //         if up_segment.get_isd() == down_segment.get_isd():
    //             info = OpaqueFieldType.INTRATD_PEER
    //         else:
    //             info = OpaqueFieldType.INTERTD_PEER
    //     else:
    //         path = CrossOverPath()
    //         info = OpaqueFieldType.NON_TDC_XOVR

    //     path.up_segment_info = up_segment.iof
    //     path.up_segment_info.info = info
    //     path.up_segment_info.hops -= up_index
    //     path.up_segment_info.up_flag = True
    //     for i in reversed(range(up_index, len(up_segment.ads))):
    //         path.up_segment_hops.push_back(up_segment.ads[i].pcbm.hof)
    //     path.up_segment_hops[-1].info = OpaqueFieldType.LAST_OF
    //     path.up_segment_upstream_ad = up_segment.ads[up_index - 1].pcbm.hof

    //     if peer:
    //         up_ad = up_segment.ads[up_index]
    //         down_ad = down_segment.ads[dw_index]
    //         for up_peer in up_ad.pms:
    //             for down_peer in down_ad.pms:
    //                 if (up_peer.ad_id == down_ad.pcbm.ad_id and
    //                         down_peer.ad_id == up_ad.pcbm.ad_id):
    //                     path.up_segment_peering_link = up_peer.hof
    //                     path.down_segment_peering_link = down_peer.hof

    //     path.down_segment_info = down_segment.iof
    //     path.down_segment_info.info = info
    //     path.down_segment_info.hops -= dw_index
    //     path.down_segment_info.up_flag = False
    //     path.down_segment_upstream_ad = down_segment.ads[dw_index - 1].pcbm.hof
    //     for i in range(dw_index, len(down_segment.ads)):
    //         path.down_segment_hops.push_back(down_segment.ads[i].pcbm.hof)
    //     path.down_segment_hops[0].info = OpaqueFieldType.LAST_OF

    //     return path

    // @staticmethod
    // def _build_shortcut_path(up_segment, down_segment) {
    //     *
    //     Takes PCB objects (up/down_segment) and tries to combine
    //     them as short path
    //     *
    //     // TODO check if stub ADs are the same...
    //     if (not up_segment or not down_segment or
    //             not up_segment.ads or not down_segment.ads):
    //         return None
    //     // looking for xovr and peer points
    //     xovrs = []
    //     peers = []
    //     for up_i in range(1, len(up_segment.ads)):
    //         for down_i in range(1, len(down_segment.ads)):
    //             up_ad = up_segment.ads[up_i]
    //             down_ad = down_segment.ads[down_i]
    //             if up_ad.pcbm.ad_id == down_ad.pcbm.ad_id:
    //                 xovrs.push_back((up_i, down_i))
    //             else:
    //                 for up_peer in up_ad.pms:
    //                     for down_peer in down_ad.pms:
    //                         if (up_peer.ad_id == down_ad.pcbm.ad_id and
    //                                 down_peer.ad_id == up_ad.pcbm.ad_id):
    //                             peers.push_back((up_i, down_i))
    //     // select shortest path xovrs (preferred) or peers
    //     xovrs.sort(key=lambda tup: sum(tup))
    //     peers.sort(key=lambda tup: sum(tup))
    //     if not xovrs and not peers:
    //         return None
    //     elif xovrs and peers:
    //         if sum(peers[-1]) > sum(xovrs[-1]):
    //             return PathCombinator._join_shortcuts(up_segment, down_segment,
    //                                                   peers[-1], True)
    //         else:
    //             return PathCombinator._join_shortcuts(up_segment, down_segment,
    //                                                   xovrs[-1], False)
    //     elif xovrs:
    //         return PathCombinator._join_shortcuts(up_segment, down_segment,
    //                                               xovrs[-1],
    //                                               False)
    //     else:  // peers only
    //         return PathCombinator._join_shortcuts(up_segment, down_segment,
    //                                               peers[-1],
    //                                               True)

    // @staticmethod
    // def build_shortcut_paths(up_segments, down_segments) {
    //     *
    //     Returns a list of all shortcut paths (peering and crossover paths) that
    //     can be built using the provided up- and down-segments.
    //     *
    //     paths = []
    //     for up in up_segments:
    //         for down in down_segments:
    //             path = PathCombinator._build_shortcut_path(up, down)
    //             if path and path not in paths:
    //                 paths.push_back(path)

    //     return paths

    // @staticmethod
    // def build_core_paths(up_segment, down_segment, core_segments) {
    //     *
    //     Returns list of all paths that can be built as combination of segments
    //     from up_segments, core_segments and down_segments.
    //     *
    //     paths = []
    //     if not core_segments:
    //         path = PathCombinator._build_core_path(up_segment, [], down_segment)
    //         if path:
    //             paths.push_back(path)
    //     else:
    //         for core_segment in core_segments:
    //             path = PathCombinator._build_core_path(up_segment,
    //                                                    core_segment,
    //                                                    down_segment)
    //             if path and path not in paths:
    //                 paths.push_back(path)
    //     return paths
};

#endif // PATH_CPP