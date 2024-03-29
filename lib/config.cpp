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
 * :mod:`config` --- SCION configuration parser
 *  ============================================
 */

#include <string>
#include <map>
#include "rapidjson/document.h"
#include "rapidjson/filereadstream.h"

class Config {
    /* The Config class parses the configuration file of an AD and stores such
     * information for further use.
     * 
     * :ivar master_of_gen_key: the master opaque field generation key file.
     * :type master_of_gen_key: int
     * :ivar master_ad_key: AD certificate servers priv key.
     * :type master_ad_key: int
     * :ivar n_registered_paths: the number of registered paths.
     * :type n_registered_paths: int
     * :ivar n_shortest_up_paths: the number of shortest up-paths.
     * :type n_shortest_up_paths: int
     * :ivar propagation_time: the propagation time.
     * :type propagation_time: int
     * :ivar registration_time: the registration time.
     * :type registration_time: int
     * :ivar reset_time: the reset time.
     * :type reset_time: int
     * :ivar registers_paths: whether or not the AD registers paths.
     * :type registers_paths: int
     * :ivar pcb_queue_size: PCB queue size for the beacon servers.
     * :type pcb_queue_size: int
     * :ivar path_server_queue_size: path queue size for the path servers.
     * :type path_server_queue_size: int
     * :ivar cert_chain_version: initial version of the certificate chain.
     * :ivar cert_chain_version: int
     */
public:
    uint64_t master_of_gen_key;
    uint64_t master_ad_key; 
    int n_registered_paths; 
    int n_shortest_up_paths;
    int propagation_time;
    int registration_time;
    int reset_time;
    int registers_paths;
    int pcb_queue_size;
    int path_server_queue_size;
    int cert_chain_version;

    Config() {
        Config("");
    }

    Config(const std::string &config_file) {
        /**
         * Initialize an instance of the class Config.

         * :param config_file: the name of the configuration file.
         * :type config_file: str
         * :returns: the newly created Config instance.
         * :rtype: :class:`Config`
         */
        master_of_gen_key = 0;
        master_ad_key = 0;
        n_registered_paths = 0;
        n_shortest_up_paths = 0;
        propagation_time = 0;
        registration_time = 0;
        reset_time = 0;
        registers_paths = 0;
        pcb_queue_size = 0;
        path_server_queue_size = 0;
        cert_chain_version = 0;
        if (config_file.length())
            parse_file(config_file);
    }

    void parse_file(const std::string &config_file) {
        /* Parse a configuration file and populate the instance's attributes.
         * 
         * :param config_file: the name of the configuration file.
         * :type config_file: str
         */
        rapidjson::Document d;
        try {
            FILE* fp = fopen(config_file.c_str(), "r");
            char readBuffer[65536];
            rapidjson::FileReadStream is(fp, readBuffer, sizeof(readBuffer));
            d.ParseStream(is);
            fclose(fp);
        }
        catch(int e) {
            // logging.error("Config: JSON format error.")
            return;
        }
        master_of_gen_key = d["MasterOFGKey"].GetUint64();
        master_ad_key = d["MasterADKey"].GetUint64();
        n_registered_paths = d["NumRegisteredPaths"].GetInt();
        n_shortest_up_paths = d["NumShortestUPs"].GetInt();
        propagation_time = d["PropagateTime"].GetInt();
        registration_time = d["RegisterTime"].GetInt();
        reset_time = d["ResetTime"].GetInt();
        registers_paths = d["RegisterPath"].GetInt();
        pcb_queue_size = d["PCBQueueSize"].GetInt();
        path_server_queue_size = d["PSQueueSize"].GetInt();
        cert_chain_version = d["CertChainVersion"].GetInt();
    }

    Config(std::map<std::string, int> &config_dict) {
        /**
         * Create a Config instance from the dictionary.
         * :param config_dict: dictionary representation of configuration
         * :type config_dict: dict
         */
        Config("");
        parse_dict(config_dict);
    }

    void parse_dict(std::map<std::string, int> &config) {
        /**
         * Parse a configuration file and populate the instance's attributes.
         * :param config: the name of the configuration file.
         * :type config: dict
         */
        master_of_gen_key = config["MasterOFGKey"];
        master_ad_key = config["MasterADKey"];
        n_registered_paths = config["NumRegisteredPaths"];
        n_shortest_up_paths = config["NumShortestUPs"];
        propagation_time = config["PropagateTime"];
        registration_time = config["RegisterTime"];
        reset_time = config["ResetTime"];
        registers_paths = config["RegisterPath"];
        pcb_queue_size = config["PCBQueueSize"];
        path_server_queue_size = config["PSQueueSize"];
        cert_chain_version = config["CertChainVersion"];
    }
};