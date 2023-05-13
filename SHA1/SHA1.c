
//
//  SHA1.c
//  SHA1
//
//  Created by Wael Youssef on 1/31/17.
//  Copyright © 2017 DigitalEgypt. All rights reserved.
//

#include "SHA1.h"
#include <stdlib.h>
#include <string.h>

int K(uint32_t t) {
	if(0  <= t && t <= 19) return 0x5A827999;
	if(20 <= t && t <= 39) return 0x6ED9EBA1;
	if(40 <= t && t <= 59) return 0x8F1BBCDC;
	if(60 <= t && t <= 79) return 0xCA62C1D6;

	printf("\nERR");
	return 0;
}

uint32_t requiredExtraBitsForByteSize(uint32_t size) {
	uint32_t sizeInBits = size * 8;
	sizeInBits += 1;

	uint32_t remainder = sizeInBits % 512;
	uint32_t padding;
	if (remainder < 448) {
		padding = 448 - remainder;
	} else {
		padding = 512 - (remainder - 448);
	}
	
	// Safe variation
	//	padding = 0;
	//	while ((sizeInBits % 512) != 448) {
	//		padding++;
	//		sizeInBits++;
	//	}
	
	return padding + 65;
}

uint32_t f (uint32_t t, uint32_t B, uint32_t C, uint32_t D) {
	if(0  <= t && t <= 19) return (B & C) | ((~B) & D);
	if(20 <= t && t <= 39) return B ^ C ^ D;
	if(40 <= t && t <= 59) return (B & C) | (B & D) | (C & D);
	if(60 <= t && t <= 79) return B ^ C ^ D;
	printf("\nERR");
	return 0;
}

int Spn(uint32_t n, uint32_t X) {
	return (X << n) | (X >> (32-n));
}

uint32_t paddedDataSizeFromSize(uint32_t size) {
	uint32_t bitPadding = requiredExtraBitsForByteSize(size);
	uint32_t bytePadding = bitPadding / 8;
	
	uint32_t totalSize = size + bytePadding;
	return totalSize;
}

uint64_t swapInt64(uint64_t int64) {
	uint64_t swapped =
	((int64>>56)&0x00000000000000ff) | // byte 7 to byte 0
	((int64>>40)&0x000000000000ff00) | // byte 6 to byte 1
	((int64>>24)&0x0000000000ff0000) | // byte 5 to byte 2
	((int64>>8) &0x00000000ff000000) | // byte 4 to byte 3
	((int64<<8) &0x000000ff00000000) | // byte 3 to byte 4
	((int64<<24)&0x0000ff0000000000) | // byte 2 to byte 5
	((int64<<40)&0x00ff000000000000) | // byte 1 to byte 6
	((int64<<56)&0xff00000000000000);  // byte 0 to byte 7
	return swapped;
}

uint32_t swapInt32(uint32_t int32) {
	uint32_t swapped =
	((int32>>24)&0x000000ff) | // byte 3 to byte 0
	((int32>>8) &0x0000ff00) | // byte 2 to byte 1
	((int32<<8) &0x00ff0000) | // byte 1 to byte 2
	((int32<<24)&0xff000000); // byte 0 to byte 3
	return swapped;
}

uint8_t* paddedDataFromData(uint8_t* data, uint32_t size) {
	uint32_t totalSize = paddedDataSizeFromSize(size);
	
//	uint8_t arr[8] = {0};
//	arr[0] = size;
////	uint32_t buff = 0;
//	memcpy(&buff, arr, sizeof(uint32_t));
	
	uint8_t* paddedData = malloc(totalSize);
	memset(paddedData, 0, totalSize);
	paddedData[size] = 0x80;
	memcpy(paddedData, data, size);
//	memset(&paddedData[size], 128, 1);
//	memset(&paddedData[size+1], 0, totalSize - (size +1));

	uint64_t sizeInBits = (uint64_t)size * 8;
	uint64_t swapped = swapInt64(sizeInBits);
//	swapped = 'L';
	memcpy(&paddedData[totalSize - sizeof(uint64_t)], &swapped, sizeof(uint64_t));
	
	return paddedData;
}

char* sha1KeyFromData(uint8_t* data, uint32_t size) {
	uint8_t* paddedData = paddedDataFromData(data, size);
	
	uint32_t H[5] = {
		0x67452301,
		0xEFCDAB89,
		0x98BADCFE,
		0x10325476,
		0xC3D2E1F0
	};
	
	uint32_t totalSize = paddedDataSizeFromSize(size);
	uint32_t N = totalSize / 64;
	uint8_t* blockPtr = NULL;
	for (uint32_t k = 0; k < N; k++) {
		blockPtr = &paddedData[k * 64];
		uint32_t words[80] = {0};
		for (uint32_t t = 0; t < 16; t++) {
			uint32_t temp;
			memcpy(&temp, &blockPtr[t * 4], sizeof(uint32_t));
			words[t] = swapInt32(temp);
		}
		
		for (uint32_t t = 16; t < 80; t++) {
			words[t] = Spn(1, words[t-3] ^ words[t-8] ^ words[t-14] ^ words[t-16]);
		}
		
		uint32_t A = H[0], B = H[1], C = H[2], D = H[3], E = H[4];

	
		for (uint32_t t = 0; t < 80; t++) {
			uint32_t TEMP = Spn(5, A) + f(t, B, C, D) + E + words[t] + K(t);
			E = D;
			D = C;
			C = Spn(30, B);
			B = A;
			A = TEMP;

		}
		
		H[0] = H[0] + A;
		H[1] = H[1] + B;
		H[2] = H[2] + C;
		H[3] = H[3] + D;
		H[4] = H[4] + E;
	}
	
	free(paddedData);

	int hexCharPerHash = 8;
	int hashCount = 5;
	int nullTermenatorSize = 1;
	char* key = malloc((hexCharPerHash * hashCount) + nullTermenatorSize);
	
	sprintf(&key[0], "%x%x%x%x%x", H[0], H[1], H[2] ,H[3], H[4]);

	return key;
}
