

default:
	g++ -I./secp256k1-master/ secp256k1-master/src/.libs/*.o *.cpp -o simulate2
