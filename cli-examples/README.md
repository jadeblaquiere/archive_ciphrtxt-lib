# ciphrtxt-lib/clitools
Simple CLI tool example for using the ciphrtxt libraries

# Tutorial

## Creating Keys

1. Make some random keys

    In order to demonstrate encryption/decryption we create two keypairs. 

    ```
    python new-keypair.py > alice.keypair
    python new-keypair.py > bob.keypair
    cat alice.keypair
    cat bob.keypair
    ```
    
    You'll need these key values through the examples

## Manipulating Messages

1. Encode a message

    ```
    echo "Hello, Bob!" | python encode-message.py --sender [SENDER PRIVKEY] [RECIPIENT PUBKEY] > ctext
    ```

1. Decode the message

    ```
    cat ctext | python decode-message.py [RECIPIENT PRIVKEY]
    ```

1. (optional) Decode the message and also verify the recipient

    ```
    cat ctext | python decode-message.py [RECIPIENT PRIVKEY] --sender [SENDER PUBKEY]
    ```

    if you repeat that with a different pubkey (e.g. the recipient pubkey) then it will fail validation

1. (optional) Encode an anonymous message by leaving off the sender when encoding so that the sender key is generated at random

    ```
    echo "Hello, Bob!" | python encode-message.py [RECIPIENT PUBKEY] > ctext
    ```

    This message should not validate to any sender key (unless you happen to guess the specific key which should happen approximately once out of every 2**256 guesses)

## Interacting with the Network

1. Push your message to the network

    ```
    cat ctext | python post-message.py
    ```
    
    The message will propagate through all the servers in the network (typically within 10-20 seconds) and you can interact with the message store service via http://ciphrtxt.com:7754/ or any of the peers listed in the peer list ... 

1. (optional) Get fancy and create a message and post to a peer all in one command:

    ```
    python encode-message.py --sender [SENDER PRIVKEY] [RECIPIENT PUBKEY] | python post-message.py --host [PEER HOSTNAME] --port [PEER PORT NUMBER]
    ```
    
    This command will expect input from stdin. You can write multiple lines and then hit Ctrl+D to end input. The message will be encoded and the output piped into post-message which will push the message to the server. 

1. Check the network for messages

    ```
    python check-messages.py [RECIPIENT PRIVKEY]
    ```
    
    You'll see a list of messages listed by date with the message ID value
    
1. Fetch a message from the network

    ```
    python fetch-message.py [MESSAGE ID]
    ```
    
1. (optional) Get fancy and fetch the message and download it:
    
    ```
    python fetch-message.py [MESSAGE ID] | python decode-message.py [RECIPIENT PRIVKEY]
    ```
    
