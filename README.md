# ECC_multisig_test
Compile and test SECP256k1 library first:
$ cd secp256k1-master
$ ./autogen.sh
$ ./configure
$ make
$ ./tests

Then, back in the HEAD directory, compile the simulation program:
$ make

Then run the program with
$ ./simulate <message> <num_users> <num_required_signatures> <runs>

e.g.

$ ./simulate "hi" 20 11 1000000

will simulate 1 million runs of 20 users putting a signature on the message "hi", where at least 11 signatures are required for validity.

The program outputs the randomly generated public and private keys for debug purposes.
The main output is the final calculation time and number of successful validations at the end, along with the amount of time spent in the validation phase.
