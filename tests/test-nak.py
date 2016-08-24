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

from ciphrtxt.nak import NAK
from binascii import hexlify, unhexlify

message = 'the quick brown fox jumped over the lazy dog'

kcount = 1500

alice = NAK()
alice.randomize()
ex = alice.serialize()
ajson = alice.dumpjson()
ajcopy = NAK.loadjson(ajson)
print('Alice nak = ' + str(hexlify(ex)))
print('Alice nak str = ' + str(alice))
print('Alice nak json = ' + str(ajson))
print('Alice nak json copy str = ' + str(ajcopy))
print('Alice privkey = %x' % alice.privkey)
print('Alice pubkey = ' + str(hexlify(alice.pubkeybin())))
alice_pub = NAK.deserialize(ex)
assert alice_pub is not None
sig = alice.sign(message)
assert alice_pub.verify(sig,message)
assert alice.verify(sig,message)

print('')

atwin = NAK(expire=alice.expire, privkey=alice.privkey)
stwin = atwin.sign(message)
print('Alice nak = ' + str(hexlify(atwin.serialize())))
print('Alice nak str = ' + str(atwin))
print('Alice privkey = %x' % atwin.privkey)
print('Alice pubkey = ' + str(hexlify(atwin.pubkeybin())))
assert alice_pub.verify(stwin,message)
assert alice.verify(stwin,message)
assert atwin.verify(stwin,message)

print('')

print('creating %d keys' % kcount)

nakpriv = []
nakpub = []
for i in range(0,kcount):
    k = NAK()
    k.randomize()
    nakpriv.append(k)
    nakpub.append(NAK.deserialize(k.serialize()))

print('validating %d keys' % kcount)

for i in range(0,kcount):
    print('i = %d' % i)
    sig = nakpriv[i].sign(message)
    assert nakpriv[i].verify(sig,message)
    assert nakpub[i].verify(sig,message)
    for j in range(0,kcount):
        if j != i:
            assert not nakpriv[j].verify(sig,message)
            assert not nakpub[j].verify(sig,message)
