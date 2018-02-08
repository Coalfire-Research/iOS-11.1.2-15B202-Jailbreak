#!/bin/bash
`xcrun -sdk iphoneos -find clang` -Os -isysroot `xcrun -sdk iphoneos -show-sdk-path` -F`xcrun -sdk iphoneos -show-sdk-path`/System/Library/Frameworks -arch arm64 helloworld.c -o helloworld
jtool --sign --inplace --ent ent.xml helloworld


`xcrun -sdk iphoneos -find clang` -Os -isysroot `xcrun -sdk iphoneos -show-sdk-path` -F`xcrun -sdk iphoneos -show-sdk-path`/System/Library/Frameworks -arch arm64 -I../async_wake_ios ../async_wake_ios/find_port.c ../async_wake_ios/symbols.c ../async_wake_ios/kmem.c ../async_wake_ios/kutils.c ../async_wake_ios/sha256.c ../async_wake_ios/code_hiding_for_sanity.c  tfp0.c -o tfp0
jtool --sign --inplace --ent ent.xml tfp0