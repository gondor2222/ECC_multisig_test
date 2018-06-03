#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include "include/secp256k1.h"
#define KEY_LENGTH_IN_CHARS 32
#define MAX_PRIVATE_GEN_TRIES 10

//wrapper for a signature that additionally allows us to store a user id
//without storing the user id, verifification would require on average N*s / 2 verifications,
//where N is the number of users in the pool and s is the number of signatures on this document.
//This is because we would need to test random combinations of signatures and public keys
class Signature {
	public:
		secp256k1_ecdsa_signature signature;
		int userid;
		Signature(secp256k1_ecdsa_signature sig, int id);
		Signature();
};

//A wrapper for a message to be hashed, signed, verified etc.
class Message {
	public:
		const unsigned char* data; //the message itself
		unsigned char* sha; //message hash. currently sha256 in implementation
		Message(char* indata, int nMaxSignatures);
		~Message();
		Signature* signatures; //array of signature pointers (type defined in secp256k1 library)
		void addSignature(secp256k1_ecdsa_signature* signature, int id); //add a signature to the signature array
		int getNumSignatures();	//prevent change to underlying signature counter
		int getMaxSignatures(); //prevent change to underlying signature cap
		int getLen();	//prevent change to underlying message length counter
	private:
		int numSignatures;
		int maxSignatures;
		int len; 

};


class User {
	private:
		const unsigned char* privateKey;
	public:
		int id;
		secp256k1_pubkey* publicKey;
		User(const secp256k1_context* ctx, int nid);
		void sign(const secp256k1_context* ctx, Message* msg); //sign a message
};

void printError(const char* message, void* data);
