# GolangSSHServer
A standalone SSH server written in Go

# Usage
1) Install Go (https://golang.org/doc/install) and setup your GOPATH

2) Get the code
```
go get github.com/leechristensen/GolangSSHServer
```
3) Generate keys
```
ssh-keygen -t ed25519 -f ./authkey
ssh-keygen -t ed25519 -f ./hostkey
```
4) Replace keys in the code
```
cat authkey.pub      Find "authPublicKeys" variable in the code and replace the example key that's already there. 
cat hostkey          Find "hostKeyBytes" variable in the code and replace the example key that's already there
```
5) Recompile
```
go install github.com/leechristensen/GolangSSHServer
```
6) Run the SSH server
```
GolangSSHServer 2222           Starts the SSH server on localhost:2222

or

GolangSSHServer 0.0.0.0 2222   Starts the SSH server on 0.0.0.0:2222
```
7) Connect to the SSH server with your SSH client + authentication key
```
ssh -i authkey user@localhost -p2222
```

# Thanks
The code in this repo is heavily borrowed from the following sources:
* https://github.com/Scalingo/go-ssh-examples/
* https://lukevers.com/2016/05/01/ssh-as-authentication-for-web-applications

