# Copyright (c) 2016, Joseph deBlaquiere <jadeblaquiere@yahoo.com>
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of ciphrtxt nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
    print('p= ' + str(alice))
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