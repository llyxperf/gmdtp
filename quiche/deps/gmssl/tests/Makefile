VPATH = /home/lyx/projects/GmSSL/src: /home/lyx/projects/GmSSL/tests: /home/lyx/projects/GmSSL/include/gmssl
vpath %.c /home/lyx/projects/GmSSL/src
vpath %.h /home/lyx/projects/GmSSL/include/  
objects = sm4test.o sm4_avx.o sm4_setkey.o sm4_enc.o hex.o sm4_common.o rand.o sm4ni.o

sm4Test:$(objects)
	gcc $(objects) -o sm4Test

sm4test.o :sm4test.c
	cc -c sm4test.c -o sm4test.o -I /home/lyx/projects/GmSSL/include/gmssl

sm4_avx.o :sm4_avx.c
	cc -c /home/lyx/projects/GmSSL/src/sm4_avx.c -o sm4avx.o -I /home/lyx/projects/GmSSL/include


sm4_common.o :
	cc -c /home/lyx/projects/GmSSL/src/sm4_common.c -o sm4_common.o -I /home/lyx/projects/GmSSL/include
hex.o :
	cc -c /home/lyx/projects/GmSSL/src/hex.c -o hex.o -I /home/lyx/projects/GmSSL/include
sm4_enc.o :
	cc -c /home/lyx/projects/GmSSL/src/sm4_enc.c -o sm4_enc.o -I /home/lyx/projects/GmSSL/include
sm4_setkey.o :
	cc -c /home/lyx/projects/GmSSL/src/sm4_setkey.c -o sm4_setkey.o -I /home/lyx/projects/GmSSL/include
rand.o :
	cc -c /home/lyx/projects/GmSSL/src/rand.c -o rand.o -I /home/lyx/projects/GmSSL/include
sm4ni.o :
	cc -c /home/lyx/projects/GmSSL/src/sm4ni.c -o sm4ni.o -I /home/lyx/projects/GmSSL/include



.PHONY: clean
clean :
	rm sm4Test $(objects)
