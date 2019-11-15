/********************************************************************************
* Name: Sathya Ramanathan
* Date: 12/03/2017
* Description: Implementing the TOTP algorithm
* Refferences: https://github.com/fmount/c_otp
               https://tools.ietf.org/html/rfc6238
*********************************************************************************/

#ifndef A3_H
#define A3_H

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <time.h>
#include <math.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include <stdlib.h>

using namespace std;

static const int8_t base32_vals[256] = {
	//	  This map cheats and interprets:
	//		 - the numeral zero as the letter "O" as in oscar
	//		 - the numeral one as the letter "L" as in lima
	//		 - the numeral eight as the letter "B" as in bravo
	// 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x00
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x10
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x20
	14, 11, 26, 27, 28, 29, 30, 31,  1, -1, -1, -1, -1,  0, -1, -1, // 0x30
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x40
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, // 0x50
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 0x60
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, -1, -1, -1, -1, // 0x70
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x80
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0x90
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xA0
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xB0
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xC0
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xD0
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xE0
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0xF0
};

size_t decode_b32key(uint8_t **k, size_t len){
	size_t keylen;
	size_t pos;
	//decodes base32 secret key
	keylen = 0;
	for (pos = 0; pos <= (len - 8); pos += 8) {
	//MSB is Most Significant Bits  (0x80 == 10000000 ~= MSB)
	//MB is middle bits			 (0x7E == 01111110 ~= MB)
	//LSB is Least Significant Bits (0x01 == 00000001 ~= LSB)

	//byte 0
	(*k)[keylen+0]	= (base32_vals[(*k)[pos+0]] << 3) & 0xF8; // 5 MSB
	(*k)[keylen+0] |= (base32_vals[(*k)[pos+1]] >> 2) & 0x07; // 3 LSB
	if ((*k)[pos+2] == '=') {
		keylen += 1;
		break;
	}

	//byte 1
	(*k)[keylen+1]	= (base32_vals[(*k)[pos+1]] << 6) & 0xC0; // 2 MSB
	(*k)[keylen+1] |= (base32_vals[(*k)[pos+2]] << 1) & 0x3E; // 5	MB
	(*k)[keylen+1] |= (base32_vals[(*k)[pos+3]] >> 4) & 0x01; // 1 LSB
	if ((*k)[pos+4] == '=') {
		keylen += 2;
		break;
	}

	//byte 2
	(*k)[keylen+2]	= (base32_vals[(*k)[pos+3]] << 4) & 0xF0; // 4 MSB
	(*k)[keylen+2] |= (base32_vals[(*k)[pos+4]] >> 1) & 0x0F; // 4 LSB
	if ((*k)[pos+5] == '=') {
		keylen += 3;
		break;
	}

	//byte 3
	(*k)[keylen+3]	= (base32_vals[(*k)[pos+4]] << 7) & 0x80; // 1 MSB
	(*k)[keylen+3] |= (base32_vals[(*k)[pos+5]] << 2) & 0x7C; // 5	MB
	(*k)[keylen+3] |= (base32_vals[(*k)[pos+6]] >> 3) & 0x03; // 2 LSB
	if ((*k)[pos+7] == '=') {
		keylen += 4;
		break;
	}

	//byte 4
	(*k)[keylen+4]	= (base32_vals[(*k)[pos+6]] << 5) & 0xE0; // 3 MSB
	(*k)[keylen+4] |= (base32_vals[(*k)[pos+7]] >> 0) & 0x1F; // 5 LSB
	keylen += 5;
	}
	(*k)[keylen] = 0;

	return keylen;
}

time_t getTime(){
	//Get unix time to match
  time_t utime = (floor((unsigned long)time(NULL) / 30));
  uint32_t endian;

  endian = 0xdeadbeef;
  if ((*(const uint8_t *)&endian) == 0xef) {
    utime = ((utime & 0x00000000ffffffff) << 32) | ((utime & 0xffffffff00000000) >> 32);
    utime = ((utime & 0x0000ffff0000ffff) << 16) | ((utime & 0xffff0000ffff0000) >> 16);
    utime = ((utime & 0x00ff00ff00ff00ff) <<  8) | ((utime & 0xff00ff00ff00ff00) >>  8);
  };

  return utime;
}

#endif
