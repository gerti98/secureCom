CC= g++
CFLAGS= -c -g
LIB= -lcrypto -lpthread -lrt

all: client server

server.o: server.cpp 
	$(CC) $(CFLAGS) server.cpp

client.o: client.cpp
	$(CC) $(CFLAGS) client.cpp

crypto.o: crypto.cpp
	$(CC) $(CFLAGS) crypto.cpp

util.o: util.cpp
	$(CC) $(CFLAGS) util.cpp

server: server.o
	$(CC) server.o util.o crypto.o $(LIB) -o server

client: client.o util.o crypto.o
	$(CC) client.o util.o crypto.o $(LIB) -o client 

clean:
	rm *.o client server