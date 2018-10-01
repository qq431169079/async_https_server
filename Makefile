wserver : common.c server.c wserver.c
	$(CC) -o wserver common.c server.c wserver.c -lcrypto -lssl 

