all:
	gcc -c openssl.c
	gcc -o openssl openssl.c -lssl -lcrypto

clean:
	rm *.o openssl

run: 
	./openssl
