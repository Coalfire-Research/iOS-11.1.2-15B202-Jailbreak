#!/bin/bash
`xcrun -sdk iphoneos -find clang` -Os -isysroot `xcrun -sdk iphoneos -show-sdk-path` -F`xcrun -sdk iphoneos -show-sdk-path`/System/Library/Frameworks -arch arm64 helloworld.c -o helloworld
jtool --sign --inplace --ent ent.xml helloworld
