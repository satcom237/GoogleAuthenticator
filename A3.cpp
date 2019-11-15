/********************************************************************************
* Name: Sathya Ramanathan
* Date: 12/03/2017
* Description: Implementing the TOTP algorithm
* Refferences: https://github.com/fmount/c_otp
							 https://tools.ietf.org/html/rfc6238
*********************************************************************************/

#include "A3.h"

int main(){

	char key[] = "TESTZZZZTESTZZZZ"; //Get key to hash
	printf("Secret Key: %s\n", key);
	size_t len = strlen(key); //Length of key
	uint8_t *key32 = (uint8_t *)key; //Converts char to uint8_t
	size_t key32len = decode_b32key(&key32, len); //Decodes key to base32
	int set = 1; //While-loop flag
	int x = 1; //While-loop flag

	while(2 > set){
    //Get unix time
		time_t utime = getTime();

		uint8_t *hash;
		uint32_t result;
		uint64_t offset;
		uint32_t truncH;

		//Get the hash of key and time
		hash = (uint8_t *)HMAC(EVP_sha1(), key32, key32len, (const unsigned char *)&utime,
		sizeof(utime), NULL, 0);

		//Get offset position
		offset = hash[19] & 0x0f;

		//Truncate hash
		truncH =
			(hash[offset] & 0x7f) << 24 |
			(hash[offset + 1] & 0xff) << 16 |
			(hash[offset + 2] & 0xff) << 8 |
			(hash[offset + 3] & 0xff);

		//Mod truncated hash to get the 6 digit OTP
		result = truncH % 1000000;

		if(x != result){
			printf("OTP: %06u\n", result);
			x = result;
		}
	}

  return 0;
}
