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
#ifndef BITARRAY_H
#define BITARRAY_H

#include <cstring>
#include <vector>
#include <stdint.h>
#include <cstdlib>
#include <iostream>
#include <bitset>
#include <assert.h>

class BitArray {
	/**
	 * A hacky version of a data structure representing an
	 * array of bits. Ideally param `array` should be private.
	 */
public:
	std::vector<bool> array;
	BitArray(const std::string &raw) {
		/**
		 * Constructor - from std::string
		 */
		int len = raw.length();
		std::bitset<8> c;
		for(int i = 0; i < len; i++) {
			c = std::bitset<8>(raw[i]);
			for(int j = 0; j < 8; j++) 
				array.push_back(c[j]);
		}
	}

	BitArray() {
		/**
		 * Default constructor.
		 */
		array.clear();
	}

	~BitArray() {
		array.clear();
	}
	
	unsigned long long get_subarray(int pos, uint32_t len) const {
		/**
		 * Converts `len` bits starting from `pos` to decimal
		 * param pos: start index in the bitarray
		 * param len: number of bits to return
		 * return type: unsigned long long
		 */
		if (len > 64) {
			std::cerr << "Cannot return more than 64 bits" << std::endl;
			exit(-1);
		}

		std::bitset<64> res;
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
			std::cerr << "Cannot append more than 64 bits" << std::endl;
			exit(-1);
		}

		std::bitset<64> _val(val);
		for(int i = len-1; i >= 0; i--) 
			array.push_back(_val[i]);
	}

	std::vector<bool> get_vector() const {
		return array;
	}

	uint32_t length() const {
		/** 
		 * Returns the length in bits
		 */
		return array.size();
	}

	BitArray operator+(const BitArray &other) const {
		/**
		 * The underlying vectors get merged.
		 */
		BitArray res;
		res.array.reserve(length() + other.length());
		res.array.insert(res.array.end(), array.begin(), array.end());
		res.array.insert(res.array.end(), 
						 other.array.begin(), other.array.end());
		return res;
	}

	BitArray operator+=(const BitArray &other) {
		/**
		 * Similar to operator+
		 */
		array.reserve(other.array.size() + array.size());
		array.insert(array.end(), other.array.begin(), other.array.end());
		return *this;
	}

	std::string get_string() const {
		std::string s;
		assert(!(array.size() & 0x8)); // number of bits must be multiple of 8
		int len = array.size() >> 3;
		for(int i = 0; i < len; i++) {
			std::bitset<8> bits;
			for(int j = 0; j < 8; j++) 
				bits[j] = array[i*8+j];
			s.push_back((char)bits.to_ulong());
		}
		return s; 
	}
};

#endif