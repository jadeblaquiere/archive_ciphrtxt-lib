# ciphrtxt-lib
Client libraries for interacting with primary ciphrtxt objects including:

1. Keys
1.1. Address Keys ("Keys") - Elliptic key set used for blind key exchange (based on ECDH) and anonymous message addressing
1.1. Topic-based Keys ("Topics") - Derivation algorithm to create a keypair from a topic (simple text string, by convention a #hashtag, but really any string can be used)
1.1. Network Access Keys ("NAKs") - Elliptic keys which are tied to cryptocurrency transactions and used to validate anonymous network access
1. Messages ("Messages") - Secure, signed messages
1. Network-based message services ("Network") - client-side protocol for communication with the ciphrtxt message stores

To install python library:

```
pip install git+https://github.com/jadeblaquiere/ciphrtxt-lib.git
```

CLI examples are provided to demonstrate usage. You'll need to clone the repository to get the examples. There is a tutorial in the README markdown for the cli-examples directory

Addtional Resources:

* ciphrtxt message server : https://github.com/jadeblaquiere/msgstore
* ciphrtxt crypto-token server : https://github.com/jadeblaquiere/ctcd
* ciphrtxt crypto-token client : https://github.com/jadeblaquiere/python-ctcoinlib
