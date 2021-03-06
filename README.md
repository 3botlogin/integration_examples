# Integrations of 3botlogin 
Implementation examples in:
* php
* python


## PHP

#### Project Setup

`sudo apt install php`

#### Run

`php -S localhost:8000`

#### Login

the example working on 3bot login production, so make sure you have an account there.

when example it redirects you directly to 3botlogin, then you login 
and you will be redirected back to the server running on localhost
you should see something like `user logged in`

localhost will be running in http mode instead of https, but `3bot login` will redirect user to localhost server but it assumes `https` is used and you'll get error in browser, so you may need to change `https` to `http` and refresh
this is if you are running the flask example in http mode, otherwise if it is running in https mode, all will be OK, no need to do anything

## Python

#### Project Setup

`pip3 install flask pynacl`

#### Run

`python3 3botlogin.py`

#### Login

the example working on 3bot login production, so make sure you have an account there.

when example it redirects you directly to 3botlogin, then you login 
and you will be redirected back to the server running on localhost
you should see something like `user logged in`

localhost will be running in http mode instead of https, but `3bot login` will redirect user to localhost server but it assumes `https` is used and you'll get error in browser, so you may need to change `https` to `http` and refresh
this is if you are running the flask example in http mode, otherwise if it is running in https mode, all will be OK, no need to do anything

## Golang

- **Install Libsodium**
```
sudo apt install libsodium-dev
sudo ldconfig
sudo apt-get install pkg-config
go get -d github.com/GoKillers/libsodium-go
cd $GOPATH/src/github.com/GoKillers
./build.sh
```

- **Install Other golang requirements**
```
go get "github.com/google/uuid"
go get	"github.com/gorilla/mux"
go get	"github.com/kevinburke/nacl"
go get	"github.com/kevinburke/nacl/box"
go get	"github.com/kevinburke/nacl/sign"
```

- **Build & Run example
 ```
go build threebot.go
./threebot
 ```

## Rails

- [See here](ruby/README.md)
