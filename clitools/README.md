# ciphrtxt-lib/clitools
Simple CLI tool example for using the ciphrtxt libraries

# Tutorial
1. Make some random keys

    In order to demonstrate encryption/decryption we create two keypairs. 

    ```
    python new-keypair.py > alice.keypair
    python new-keypair.py > bob.keypair
    cat alice.keypair
    cat bob.keypair
    ```

    the results should looks something like (in fact you can use these keys, though obviously they aren't very private/secure anymore):

    alice.keypair:
    ```
    Privkey : p0100:k8399366dea5c6793a18ae8e64bf1c4cccf174fcdc60038962f7467489677cfda:m8d901d00:n01800500:z49771381:s00016a38:r0003:fbc96b3b6ccb3d64e2f9b801daacfff4d5a3238e12a6093d95f05a140c86d16c5:ta05d848f6175ad18b38e49ccdf99daca025d607385a022322a6f41afa3d65222:f0986f686d193b6720cb7b60b74e221c2595518ee9d04a0c62cbccf571c484cf9:t5dfeae4466f0fb2478d2a9bd1622a25ba466428a7a801a9b216de903422fa0c7:f659d956d81bf513f6150a51e2c8d44741ee98ee05821c6a28105f169a0307f55:t2d3b774e2a04da28de190e2ad8806de553e2b0906affee51b10dc299b5e42f7e:cbb42e9a3
    Pubkey  : P0100:K03224D886326DFC8BCDEBC6B95B4742EDEF7E16BCE7EA0F6CABAA7850483FE425D:M8D901D00:N01800500:Z49771381:S00016A38:R0003:FBC96B3B6CCB3D64E2F9B801DAACFFF4D5A3238E12A6093D95F05A140C86D16C5:T0214D033D9EE8EDB687C2B401DDB514ADA260AD945B8D40AC5718899FC1AB8546C:F0986F686D193B6720CB7B60B74E221C2595518EE9D04A0C62CBCCF571C484CF9:T02DF946293F23992D570227C7B2BC0BD5121D3A1BCF6BFAAD4D67C50F1A95F6B3C:F659D956D81BF513F6150A51E2C8D44741EE98EE05821C6A28105F169A0307F55:T03D2E05F6CEA2AAADBE07E96CF3C30E597EB6729389DF2099DE29CC1B05959C1E3:C0F06AD36
    ```

    bob.keypair:
    ```
    Privkey : p0100:ke0a7c35c3b763bce3c2207c70e3e9cc366961a4a12426dcd54f68d2c7d35f7b1:m60e41182:n40e01180:z4e27e5f9:s00013bda:r0003:ff46e6b23046b80ebf3a3c96713ef793567cd9e1cf1970b54fc45035f039a1c4e:t6bd73bc5153e578b3b2de1410959d16f30a035e1da7bd78bcef8dad861811a94:f2c1350b97e2b8c126a7dda8f2b05384663c24721a9ff165c9789b4886ad50b47:te8b6df0a9cf35fead321c444472f47ba7f0822a27b885d0303957a21f1b0931d:f9d344acd4f559b152cc8f56efa217c9f16c077b3786aa081c3f013ca6e3db14c:t4892b771565789df91f49cc0d31b5dadc453c81fbe717e3daacb1c04ea272d13:cdc2c6bbf
    Pubkey  : P0100:K02D9AA1F693F152BC75651CB67C1BAEDF94EB56D78DA3A24808E06F5C2818BF3FA:M60E41182:N40E01180:Z4E27E5F9:S00013BDA:R0003:FF46E6B23046B80EBF3A3C96713EF793567CD9E1CF1970B54FC45035F039A1C4E:T039092B2D131A3E33AA90F5A3BC22AE373F88FB2FA573C3DAC2BCEF7B1FF9E9108:F2C1350B97E2B8C126A7DDA8F2B05384663C24721A9FF165C9789B4886AD50B47:T035D1E6C99068065D11F785B5120C5A046AA46A369BD77D82B91681DE7FEC883F7:F9D344ACD4F559B152CC8F56EFA217C9F16C077B3786AA081C3F013CA6E3DB14C:T03ECE6B9A7602B1FE181EA006D7A3630D7A829AE05C8A5926FACF78426ABC721B6:CCDF89CAA
    ```

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


