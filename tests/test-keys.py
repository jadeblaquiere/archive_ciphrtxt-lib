from ciphrtxt.keys import PrivateKey, PublicKey
from Crypto.Random import random
import time

from ecpy.curves import curve_secp256k1
from ecpy.point import Point, Generator

_C = curve_secp256k1
# _C = curve_secp384r1
# _C = curve_secp112r1
# _C = curve_bauer9

_G_Pt = Generator.init(_C['G'][0], _C['G'][1])

if __name__ == '__main__':  # pragma: no cover
    import sys
    sys.setrecursionlimit(512)
    alice = PrivateKey(name='Alice')
    alice.set_metadata('phone', '555-555-1212')
    print('name =', alice.name)
    print('phone=', alice.get_metadata('phone'))
    bob = PrivateKey()
    for i in range(100):
        alice.randomize(4)
        bob.randomize(4)
        print('p=', alice.serialize_privkey())
        ex = alice.serialize_pubkey()
        print('P=', str(ex))
        print('\n')
        apub = PublicKey.deserialize(ex)
        print('Q=', apub.serialize_pubkey())
        ex = alice.serialize_privkey()
        print(ex)
        apriv = PrivateKey.deserialize(ex)
        print('q=', apriv.serialize_privkey())
        assert alice.serialize_privkey() == apriv.serialize_privkey()
        assert alice.serialize_pubkey() == apub.serialize_pubkey()
        ex = bob.serialize_pubkey()
        bpub = PublicKey.deserialize(ex)
        for j in range(100):
            future = int(random.randint(int(time.time()), 0x7fffffff))
            z = alice.current_privkey_val(future)
            Z = alice.current_pubkey_point(future)
            W = (_G_Pt * z)
            assert Z == W