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
	/**
	 * A hacky version of a data structure representing an
	 * array of bits. Ideally params `array` and `_length`
	 * should be private.
	 */
public:
	uint32_t _length;
	vector<bool> array;
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
		_length = 8 * len;
	}

	BitArray() {
		/**
		 * Default constructor.
		 */
		_length = 0;
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
		_length += len;
	}

	vector<bool> get_vector() {
		return array;
	}

	uint32_t length() {
		return _length;
	}

	BitArray operator+(BitArray &other) {
		/**
		 * The underlying vectors get merged.
		 */
		BitArray res;
		res.array.reserve(this->length() + other.length());
		res.array.insert(res.array.end(), array.begin(), array.end());
		res.array.insert(res.array.end(), 
						 other.array.begin(), other.array.end());
		res._length = res.array.size();
		return res;
	}

	string get_string() {
		string s;
		assert(!(array.size() & 0x8)); // number of bits must be multiple of 8
		int len = array.size() >> 3;
		for(int i = 0; i < len; i++) {
			bitset<8> bits;
			for(int j = 0; j < 8; j++) 
				bits[j] = array[i*8+j];
			s.push_back((char)bits.to_ulong());
		}
		return s; 
	}
};

