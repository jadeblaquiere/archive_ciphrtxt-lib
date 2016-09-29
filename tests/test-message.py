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

from Crypto.Random import random

from ciphrtxt.keys import PublicKey, PrivateKey
from ciphrtxt.message import Message, MessageHeader, RawMessageHeader
from hashlib import sha256

def progress(status):
    print("hash = %x, %d bits, %d, %d iterations" % (status['besthash'], 
                                                 status['bestbits'],
                                                 status['nhash'],
                                                 status['nhash2']))

pkey = []
Pkey = []

test_keys = 1500
test_msgs = 1500

print('creating alice keys')
alice = PrivateKey()
alice.randomize(4)
aliceP = PublicKey.deserialize(alice.serialize_pubkey())
print('creating bob keys')
bob = PrivateKey()
bob.randomize(4)
bobP = PublicKey.deserialize(bob.serialize_pubkey())
print('keys complete')

mtxt = 'the quick brown fox jumped over the lazy dog'
msg1 = Message.encode(mtxt, bobP, alice, progress_callback=progress, version="0100")
print('message1 = ' + str(msg1))
print(' header ' + str(msg1.serialize_header()))
print(' hash ' + str(sha256(msg1.serialize_header()).hexdigest()))
msg1a = Message.deserialize(msg1.serialize())
print('message1a = ' + str(msg1a))
print(' header ' + str(msg1a.serialize_header()))
print(' hash ' + str(sha256(msg1a.serialize_header()).hexdigest()))
if msg1a.decode(bob):
    print('decoded:', msg1a.ptxt)
msg2 = Message.encode_impersonate(mtxt, aliceP, bob, progress_callback=progress, version="0100")
print('message2 = ' + str(msg2))
print(' header ' + str(msg2.serialize_header()))
print(' hash ' + str(sha256(msg2.serialize_header()).hexdigest()))
msg2a = Message.deserialize(msg2.serialize())
print('message2a = ' + str(msg2a))
print(' header ' + str(msg2a.serialize_header()))
print(' hash ' + str(sha256(msg2a.serialize_header()).hexdigest()))
if msg2a.decode(bob):
    print('decoded:', msg2a.ptxt)

assert (msg1 != msg2)
if msg1 > msg2:
    assert msg2 < msg1
    assert msg1 >= msg2
    assert not msg1 <= msg2
else:
    assert not msg2 < msg1
    assert not msg1 >= msg2
    assert msg1 <= msg2

mtxt = 'the quick brown fox jumped over the lazy dog'
msg1 = Message.encode(mtxt, bobP, alice, progress_callback=progress)
print('message1 = ' + str(msg1))
print(' header ' + str(msg1.serialize_header()))
print(' hash ' + str(sha256(msg1.serialize_header()).hexdigest()))
msg1a = Message.deserialize(msg1.serialize())
print('message1a = ' + str(msg1a))
print(' header ' + str(msg1a.serialize_header()))
print(' hash ' + str(sha256(msg1a.serialize_header()).hexdigest()))
if msg1a.decode(bob):
    print('decoded:', msg1a.ptxt)
msg2 = Message.encode_impersonate(mtxt, aliceP, bob, progress_callback=progress)
print('message2 = ' + str(msg2))
print(' header ' + str(msg2.serialize_header()))
print(' hash ' + str(sha256(msg2.serialize_header()).hexdigest()))
msg2a = Message.deserialize(msg2.serialize())
print('message2a = ' + str(msg2a))
print(' header ' + str(msg2a.serialize_header()))
print(' hash ' + str(sha256(msg2a.serialize_header()).hexdigest()))
if msg2a.decode(bob):
    print('decoded:', msg2a.ptxt)

assert (msg1 != msg2)
if msg1 > msg2:
    assert msg2 < msg1
    assert msg1 >= msg2
    assert not msg1 <= msg2
else:
    assert not msg2 < msg1
    assert not msg1 >= msg2
    assert msg1 <= msg2

print('generating %d test keys' % test_keys)
    
for i in range(0,test_keys):
    a = PrivateKey()
    a.randomize(random.randint(0,8))
    b = PublicKey.deserialize(a.serialize_pubkey())
    pkey.append(a)
    Pkey.append(b)

print('generating %d test messages' % test_msgs)
    
versions=['0100', '0200']

for i in range(0,test_msgs):
    for ver in versions:
        ztxt = ''
        for j in range(1,random.randint(2,10)):
            ztxt += mtxt
        f = random.randint(0,test_keys-1)
        t = random.randint(0,test_keys-1)
        # encode "from"
        m = Message.encode(ztxt, Pkey[t], pkey[f], version=ver)
        # encode reversed - impersonate sender from pubkey
        mi = Message.encode_impersonate(ztxt, Pkey[f], pkey[t], version=ver)
        # encode anonymous - randomized send addr
        ma = Message.encode(ztxt, Pkey[t], version=ver)
        ms = m.serialize()
        mis = mi.serialize()
        mas = ma.serialize()
        print('msg  ' + str(i) + ' = ' + ms.decode())
        print(' header ' + str(m.serialize_header()))
        print(' hash ' + str(sha256(m.serialize_header()).hexdigest()))
        print('msgi ' + str(i) + ' = ' + mis.decode())
        print(' header ' + str(mi.serialize_header()))
        print(' hash ' + str(sha256(mi.serialize_header()).hexdigest()))
        print('msga ' + str(i) + ' = ' + mas.decode())
        print(' header ' + str(ma.serialize_header()))
        print(' hash ' + str(sha256(ma.serialize_header()).hexdigest()))
        md = Message.deserialize(ms)
        mid = Message.deserialize(mis)
        mad = Message.deserialize(mas)

        assert md.decode(pkey[t])
        assert md.decode_sent(pkey[f], m.altK)
        assert md.is_from(Pkey[f])
        assert mid.decode(pkey[t])
        assert mid.decode_sent(pkey[f], mi.altK)
        assert mid.is_from(Pkey[f])
        assert mad.decode(pkey[t])
        assert not mad.decode_sent(pkey[f], ma.altK)
        assert not mad.is_from(Pkey[f])

        nmh = MessageHeader.deserialize(ms)
        nrmh = RawMessageHeader.deserialize(ms)

        assert nmh == nrmh

        assert (m != mi)
        if m > mi:
            assert mi < m
            assert m >= mi
            assert not m <= mi
            assert mi < nmh
            assert nmh >= mi
            assert not nmh <= mi
            assert mi < nrmh
            assert nrmh >= mi
            assert not nrmh <= mi
        else:
            assert not mi < m
            assert not m >= mi
            assert m <= mi
            assert not mi < nmh
            assert not nmh >= mi
            assert nmh <= mi
            assert not mi < nrmh
            assert not nrmh >= mi
            assert nrmh <= mi

        # tampered/error messages should fail based on signature
        mdte = Message.deserialize(ms)
        mdte.time += 1
        mdee = Message.deserialize(ms)
        mdee.expire += 1
        mdie = Message.deserialize(ms)
        mdie.I = mdie.I * 2
        mdie.J = mdie.J * 2
        mdct = Message.deserialize(ms)
        mdct.ctxt = mdct.ctxt[:-1]
        print('mtxt = ' + md.ptxt)
        for j in range(0,test_keys):
            if j != t:
                assert not md.decode(pkey[j])
                assert not mid.decode(pkey[j])
                assert not mad.decode(pkey[j])
            if j != f:
                assert not md.decode_sent(pkey[j], m.altK)
                assert not mid.decode_sent(pkey[j], mi.altK)
                assert not md.is_from(Pkey[j])
                assert not mid.is_from(Pkey[j])
            assert not mad.decode_sent(pkey[j], ma.altK)
            assert not mdte.decode(pkey[j])
            assert not mdee.decode(pkey[j])
            assert not mdie.decode(pkey[j])
            assert not mdct.decode(pkey[j])
            assert not mad.is_from(Pkey[j])
