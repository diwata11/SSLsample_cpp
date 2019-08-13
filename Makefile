# $@ : ターゲットファイル名
# $< : 最初の依存するファイルの名前
# $^ : すべての依存するファイルの名前

SSL_INCLUDE = -L/usr/local/lib
SSL_LDFLAGS = -Wall -O2 -std=c++11 -lssl -lcrypto

files = client server

all: $(files)


clean:
		rm -rf *~ *.o
		rm -rf $(files)


%.o: %.cpp
		$(CXX) $(SSL_LDFLAGS) -c $<


client: SSLclient.o client.o
		$(CXX) -o $@ $^ $(SSL_INCLUDE) $(SSL_LDFLAGS)


server: SSLserver.o server.o
		$(CXX) -o $@ $^ $(SSL_INCLUDE) $(SSL_LDFLAGS)

