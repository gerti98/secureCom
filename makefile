CC= g++
CFLAGS= -c 
LIB= -lcrypto

all: client server crypto

server.o: server.cpp 
	$(CC) $(CFLAGS) server.cpp

client.o: client.cpp
	$(CC) $(CFLAGS) client.cpp

crypto.o: crypto.cpp
	$(CC) $(CFLAGS) crypto.cpp

server: server.o
	$(CC) server.o -o server

client: client.o
	$(CC) client.o -o client 

crypto: crypto.o
	$(CC) crypto.o  $(LIB) -o crypto

clean:
	rm *.o client server crypto