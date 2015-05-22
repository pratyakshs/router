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

/**
 * :mod:`BitArray` --- Data structure to represent array of bits
 * ================================================================
 * 
 * Module docstring here.
 * 
 * .. note::
 *     Fill in the docstring.
 */
#pragma once

#include <cstring>
#include <vector>
#include <stdint.h>
#include <cstdlib>
#include <iostream>
#include <bitset>

using namespace std;

class BitArray {
	vector<bool> array;
	int length;

public:
	BitArray(char *raw) {
		/**
		 * Constructor - from char array
		 */
		int len = strlen(raw);
		bitset<8> c;
		for(int i = 0; i < len; i++) {
			c = bitset<8>(raw[i]);
			for(int j = 0; j < 8; j++) 
				array.push_back(c[j]);
		}
		length = 8 * len;
	}

	BitArray() {
		/**
		 * Default constructor.
		 */
		length = 0;
		array.clear();
	}

	unsigned long long get_subarray(int pos, uint32_t len) {
		/**
		 * Converts `len` bits starting from `pos` to decimal
		 * param pos: start index in the bitarray
		 * param len: number of bits to return
		 * return type: unsigned long long
		 */
		if (len > 64) {
			cerr << "Cannot return more than 64 bits" << endl;
			exit(-1);
		}

		bitset<64> res;
		for(int i = 0; i < len; i++) {
			res[63-i] = array[pos+i]; 
		}
		return res.to_ullong();
	}

	void append(unsigned long long val, uint32_t len) {
		/**
		 * Append lowest `len` bits from `val` to `array`
		 */
		if (len > 64) {
			cerr << "Cannot append more than 64 bits" << endl;
			exit(-1);
		}

		bitset<64> _val(val);
		for(int i = len-1; i >= 0; i++) 
			array.push_back(_val[i]);
	}
};