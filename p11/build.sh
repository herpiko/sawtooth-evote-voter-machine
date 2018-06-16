#!/bin/bash

g++ -g -Wall -std=c++11 -I deps/include main.cpp deps/lib/liberpiko.a deps/lib/libssl.a deps/lib/libcrypto.a -ldl -o main
