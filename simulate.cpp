#include "message.hpp"
#include "sha256.h"
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define MAX_ERROR_DATA_LENGTH 1024


int main(int argc, char* argv[]) {
	//srand currently commented out for replicability purposes.
	//srand(time(NULL));


	//check for argument validity
	if (argc != 5) {
		std::cout << "Usage: simulate <message> <num_users> <num_required_signatures> <runs>";
		return -1;
	}
	int numUsers = atoi(argv[2]);
	int numRequired = atoi(argv[3]);
	int numRuns = atoi(argv[4]);
	if (numUsers < 1) {
		std::cout << "number of users must be at least 1.";
		return -2;
	}
	//I decided to allow M > N for completeness. It will run fine but will never successfully validate a multisig
	if (numRequired < 0) {
		std::cout << "Number of required signatures must be nonnegative";
		return -3;
	}
	if (numRuns < 0) {
		std::cout << "Number of runs must be nonnegative";
	}
	//create secp256k1 contexts for signing and verifying
	secp256k1_context* context = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
	const void* errorData = (const void*) new char[MAX_ERROR_DATA_LENGTH];

	//if anything goes wrong with API calls, just print the error
	secp256k1_context_set_illegal_callback(context, printError, errorData);
	secp256k1_context_set_error_callback(context, printError, errorData);
	
	//needs to be a double pointer because we have no default constructor
	User** users = new User*[numUsers];

	for (int i = 0; i < numUsers; i++) { //initialize users
		users[i] = new User(context, i);	
	}


	Message* message;
	//number of valid messages
	int numSuccess = 0;
	//initial timestamp, used for calculation of total runtime
	clock_t timeStamp = clock();
	//initial timestamp for verification, used to calculate total verification runtime
	clock_t verifyStamp;
	//running total of time spend verifying
	float timeToVerify = 0;
	//simulate
	for (int runIndex = 0 ; runIndex < numRuns; runIndex++) {
		if (runIndex % 10000 == 0) {
			printf("Run %d\n", runIndex);
		}
		//continuously regenerate message to simulate messages being distinct
		message = new Message(argv[1], numUsers);


		//add random signatures
		for (int userIndex = 0; userIndex < numUsers; userIndex++) {
			//50% chance of signing
			if (rand() % 2 == 0) {
				users[userIndex]->sign(context, message);
			}
			else {
			}
		}

		int numSignatures = message->getNumSignatures();
		//number of valid signatures
		int numValid = 0;
		//check for validity ONCE
		//skip if there aren't enough signatures to reach the requirement threshold;
		//no point running costly verification if we definitely won't reach threshold
		verifyStamp = clock();
		if (numSignatures >= numRequired) {
			//for each signature:
			for (int signatureIndex = 0; signatureIndex < numSignatures; signatureIndex++) {
				//get the signature data and associated public key
				secp256k1_ecdsa_signature* sig = &(message->signatures[signatureIndex].signature);
				int id = message->signatures[signatureIndex].userid;
				secp256k1_pubkey* publicKey = users[id]->publicKey;

				//if valid, increment counter.
				if (secp256k1_ecdsa_verify(context, sig, message->sha, publicKey)) {
					numValid++;
				}
				else {
					//should never happen, we don't simulate forged or corrupted signatures
					printf("Invalid signature\n");
				}
			}
			//if we pass the requirement threshold M, this run was a success.
			if (numValid >= numRequired) {
				numSuccess++;
			}
		}
		//add this run's verification time to running verification time total
		timeToVerify += ((float)(clock() - verifyStamp)) / CLOCKS_PER_SEC;



		//print text and SHA256 on first run for debug purposes
		if (runIndex == 0) {
			printf("Message \"%s\" has SHA256 \"", message->data);
			for (int i = 0 ; i < SHA256::DIGEST_SIZE; i++) {
				printf("%02X", message->sha[i]);
			}
			printf("\"\n");
		}
		//delete message so it can be regenerated from scratch at the beginning of the loop
		delete message;
	}
	//final time taken
	timeStamp = clock() - timeStamp;
	printf("Done. Took %5.3fs, of which %5.3fs was spent verifying. Out of %d runs, %d succeeded.\n",
			((float)timeStamp) / CLOCKS_PER_SEC, timeToVerify, numRuns, numSuccess);
	return 0;
}
