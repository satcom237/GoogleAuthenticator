# Google Authenticator

To compile and run, type: ``` make ``` 

This will run the command ``` g++ A3.cpp -lm -lcrypto -o A3 ./A3 ``` 

Output will be the Secret Key, which is "TESTZZZZTESTZZZZ" and an OTP in the subsequent lines for the 30 second period corresponding to that of the Google Authenticator. TOTP stands for "Time-based one-time password", which is a variant of HOTP, where time is used as the message instead of a counter. This algorithm is commonly used for two-factor authentication, where a user enters their password and afterwards a TOTP to gain access. A important property of TOTP is that each password generated will be unique, since it is based off the current time of day. There are various methods in which TOTP's can be generated; such as hardware security tokens, text messages, and mobile apps such as the one in this assignment, Google Authenticator. 

*The prover and verifier must have the same time value and secret key for TOTP to work. 

Implemented in C++, I could not however find a library to decode the secret key into base32, so I decided to use a function for that instance from online (https://github.com/fmount/c_otp). Apart from that, my code follows the algorithm layed out in (https://en.wikipedia.org/wiki/Google_Authenticator). First, I take the secret key (16 characters) and decode it to base32, which is the required format for TOTP. The message (time), is calculated by flooring the current unix time divided by 30. Next, I pass these two values to HMAC-SHA1, which is included in the openssl/hmac.h library in C++. TOTP implementations may use HMAC-SHA-512 or HMAC-SHA-256 functions as well. Then, I calculate the offset by getting the last part of the hash value we just obtained form HMAC-SHA1. This outputs a 20 character hash (160 bits), so the offset was set to hash[19]. After that, I truncate the hash so that the value can be easy for a user to enter. The truncated hash is finally modded by 1000000, so it can be entered as a 6 digit number - matching the output of Google Authenticator.
