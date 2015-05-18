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
 * :mod:`IPv4Address` --- Data structure to represent an IP Address
 * ================================================================
 * 
 * Module docstring here.
 * 
 * .. note::
 *     Fill in the docstring.
 */
#pragma once

#include <bitset>
#include <iostream>
#include <stdint.h>
#include <assert.h>

using namespace std;

#define IPV4LENGTH 32
#define IPV6LENGTH 128

class IPAddress {

public:
	int version;
	int length;

	IPAddress() {
		version = 0;
		length = 0;
	}
	virtual string to_string() {}
};

class IPv4Address : public IPAddress {
	bitset<8> address[4];

	bool checked_parse(string addr) {
		uint32_t dots = 0, dig[4] = {0};
		uint32_t mask = ~(0xFF);
		for(int i = 0; i < addr.length(); i++) {
			if (addr[i] == '.'){ 
				dots++;
				if (dots > 3)
					return false;
			}
			else if (addr[i] >= '0' && addr[i] <= '9') {
				dig[dots] *= 10;
				dig[dots] += (addr[i] - '0');
			}
			else return false;
		}
		if (dots == 3 && !((dig[0] & mask) || (dig[1] & mask)
			|| (dig[2] & mask) || (dig[3] & mask))){
			for(int i = 0; i < 4; i++)
				address[i] = bitset<8>(dig[i]);
			return true;
		}
		return false;
	}

public:
	IPv4Address(string addr) {
		if (!checked_parse(addr))
			cerr << "Invalid IP address" << endl;
	}

	string to_string() {
		/***UNIMPLEMENTED***/
		cerr << "UNIMPLEMENTED" << endl;
		exit(-1);
		return "";
	}

};

class IPv6Address : public IPAddress {
	bitset<16> address[8];

	string gen_zeros(int num) {
		/* Returns a string of `num`
		 * zeros, separated by colons(':')
		 */
		assert(num > 0);
		string res = "0";
		if (num == 1) {
			return res;
		}
		num--;
		while(num--) {
			res += ":0";
		}
		return res;
	}

	void convert_to_canonical(string &addr) {
		/* Converts collapsed 0's in the 
		 * IPv6 address to a string of 
		 * eight colon separated numbers.
		 */ 
		string res = "";
		int colons = 0, pos = -1;
		for(int i = 0; i < addr.length() - 1; i++) {
			if (addr[i] == ':') {
				colons++;
				if (addr[i] == addr[i+1]) {
					/* shouldn't have consecutive
					 * colons multiple times
					 */
					assert(pos == -1); 
					pos = i;
				}
			}
		}

		/* If there are no collapsed 0s */ 
		if (pos == -1) {
			if (colons == 7)
				return;
			else {
				cerr << "Invalid IPv6 address" << endl;
				exit(-1);
			}
		}

		/* If the consecutive colons are
		 * right at the start of the string 
		 */
		if (pos == 0) {
			res = addr.substr(1);
			res = gen_zeros(9-colons) + res;
		}

		/* If the consecutive colons
		 * are right at the end. 
		 */
		else if (pos == addr.length() - 2) {
			res = addr.substr(0, addr.length()-1);
			res = res + gen_zeros(8-colons);
		}

		/* In the middle */
		else {
			res = addr.substr(0, pos+1)
				+ gen_zeros(8-colons) + addr.substr(pos+1);
		}
		addr = res;
	}

	bool checked_parse(string addr) {
		/* Returns true if addr is a well formed
		 * IPv6 address. Initializes the private data
		 * member `Address` with contents from addr.
		 */
		convert_to_canonical(addr);
		
		uint32_t colons = 0, dig[8] = {0};
		uint32_t mask = ~(0xFFFF);
		string current = "";

		for(int i = 0; i < addr.length(); i++) {
			if (addr[i] == ':') {
				if (colons > 7)
					return false; 
				dig[colons] = strtoul(current.c_str(), NULL, 16);
				colons++;
				current = "";
			}
			else if ((addr[i] >= '0' && addr[i] <= '9')
				|| (tolower(addr[i]) >= 'a' && tolower(addr[i]) <= 'f'))
				current.push_back(addr[i]);
			else return false;
		}
		dig[colons] = strtoul(current.c_str(), NULL, 16);

		bool correct = (colons == 7);
		for(int i = 0; i < 8; i++) {
			address[i] = bitset<16>(dig[i]);
			correct &= !(dig[i] & mask);
			cout << address[i] << endl;
		}
		return correct;
	}

public:
	IPv6Address(string addr) {
		if (!checked_parse(addr))
			cerr << "Invalid IP address" << endl;
	}

	string to_string() {
		/***UNIMPLEMENTED***/
		cerr << "UNIMPLEMENTED" << endl;
		exit(-1);
		return "";
	}

};
