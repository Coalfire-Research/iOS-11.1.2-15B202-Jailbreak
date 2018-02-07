# How to compile code for arm64 & iOS 11
Every binary must be signed. The signature can be total crap & absolutely made up, but given the requirements for iOS 11 and AMFID and how this jailbreak bypasses that, after compilation of code you HAVE to sign the binary.

Get jtool from here: http://www.newosxbook.com/tools/jtool.html
Direct link: http://www.newosxbook.com/tools/jtool.tar

Extract it, and then you can sign your code by running it like so:

`jtool --sign --inplace --ent ent.xml helloworld`

and now you can run your own code!

One more caveat, the sandbox will stop you from running code if the location of the binary on the file system is not allowed. SO KEEP ALL YOUR BINARIES in /jailbreak/, to bypass this.