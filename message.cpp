#include "message.hpp"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <iostream>

void User::sign(const secp256k1_context* ctx, Message* msg) {
	//allocate new signature
	secp256k1_ecdsa_signature* sig = new secp256k1_ecdsa_signature;
	//sign using secret key, default nonce, no extra entropy
	int success = secp256k1_ecdsa_sign(ctx, sig, msg->sha, privateKey, NULL, NULL);
	if (!success) {
		printf("Warning: User %d was unable to sign message \"%s\"\n", id, msg->data);
	}
	else {
		msg->addSignature(sig, id);
	}

	//delete the temporary
	delete sig;
}

User::User(const secp256k1_context* ctx, int nid) {
	id = nid;
	unsigned char* tempPrivateKey = new unsigned char [KEY_LENGTH_IN_CHARS];
	publicKey = new secp256k1_pubkey;
	int validPrivate = 0;
	int nTries = 0;
	//keep generating random private keys until one is valid or we hit max tries
	while (!validPrivate && nTries < MAX_PRIVATE_GEN_TRIES ) {
		nTries++;
		//randomly initialize bytes to create key
		//should only be invalid if all bytes are 0 or if key is greater than 
		//FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364140
		//(less than 1e-36 chance)
		for (int i = 0; i < KEY_LENGTH_IN_CHARS; i++) {
			tempPrivateKey[i] = rand() % (UCHAR_MAX + 1);
		}
		//check if key is valid
		validPrivate = secp256k1_ec_seckey_verify(ctx, tempPrivateKey);
	}
	if (!validPrivate) {
		printf("Warning: User %d was unable to generate a private key\n", nid);
	}
	else { //key is valid, generate public key from it
		privateKey = tempPrivateKey;
		//In reality, we would NEVER want to print private keys. I did this for debugging purposes.
		printf("User %d has private key \n\"", id);
		for (int i = 0; i < KEY_LENGTH_IN_CHARS; i++) {
			printf("%02X", tempPrivateKey[i]);
			if (i%4 == 3) {
				printf(" ");
			}
		}
		printf("\"\n");
		//try to generate a public key
		int success = secp256k1_ec_pubkey_create(ctx, publicKey, privateKey);
		if (!success) {
			printf("Warning: User %d was unable to generate a public key\n", nid);
		}
		printf("User %d has public key \n\"", id);
		for (int i = 0; i < KEY_LENGTH_IN_CHARS; i++) {
			printf("%02X", publicKey->data[i]);
			if (i%4 == 3) {
				printf(" ");
			}
		}
		printf("\"\n");
	}
}

Message::Message(char* indata, int nMaxSignatures) {
	maxSignatures = nMaxSignatures;

	//make a local copy of the data passed in that can be deleted later
	unsigned char* tempData = new unsigned char[len];
	len = strlen(indata);
	memcpy(tempData, indata, len);
	data = tempData;

	//allocate and set sha256
	sha = new unsigned char[SHA256::DIGEST_SIZE];
	sha256_bytes(indata, sha);

	//allocate signatures array and set signature counter to 0
	signatures = new Signature[maxSignatures];
	numSignatures = 0;
}

void Message::addSignature(secp256k1_ecdsa_signature* signature, int id) {
	//copy signature into array and increment signature counter
	signatures[numSignatures] = Signature(*signature, id); 
	numSignatures++;
}

int Message::getMaxSignatures() {
	return maxSignatures;
}

int Message::getNumSignatures() {
	return numSignatures;
}

int Message::getLen() {
	return len;
}

Message::~Message() {
	delete[] data;
	delete[] sha;
	delete[] signatures;
}

Signature::Signature(secp256k1_ecdsa_signature sig, int id) {
	userid = id;
	signature = sig;
}

Signature::Signature() {

}

void printError(const char* message, void* data) {
	std::cout << message;
}
