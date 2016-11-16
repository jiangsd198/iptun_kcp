# iptun_kcp
ip tunnel over kcp,golang

build and install
into the server directory,then...
make
make install

into the client directory,then...
make 
make install

test
sudo ./server --ifip=192.168.10.2 -l ":4000" -mode fast2
sudo ./client --ifip=192.168.10.3 -r "192.168.198.22:4000"  -mode fast2

in the client
ping 192.168.10.2

in the server
ping 192.168.10.3