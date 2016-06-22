# Copyright (c) 2016, Joseph deBlaquiere <jadeblaquiere@yahoo.com>
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

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import random
from binascii import hexlify
import time

from ciphrtxt.keys import PrivateKey

from ecpy.curves import curve_secp256k1
_C = curve_secp256k1

# parameters for time based keys, median = 24h, sd = 4h, min 12h, max 36h
_tstarget = (60 * 60 * 24)
_tssigma = (60 * 60 * 4)
_tsmin = (60 * 60 * 12)
_tsmax = (60 * 60 * 36)
_tsrange = _tsmax - _tsmin

_masksize = min(32, _C['bits'])
_maskbits = (int((_masksize / 3) + 0))

_my_prf = lambda key, msg: HMAC.new(key, msg, SHA256).digest()


class TopicKey (PrivateKey):
    def __init__(self, topic):
        super(TopicKey, self).__init__()
        self.topic = topic
        self._recalculate(1)

    def _recalculate(self, ntbk=1):
        nbytes = (_C['bits'] + 7) // 8
        keysize = ((2 + (2*ntbk)) * nbytes)
        topic = self.topic.encode()
        keyval = PBKDF2(topic, topic, keysize, 100000, _my_prf)
        self.p = int(hexlify(keyval[0:nbytes]), 16) % _C['n']
        self.tbk=[]
        for n in range(1,ntbk+1):
            tbk = {}
            tbk['otp'] = int(hexlify(keyval[nbytes*2*n:nbytes*((2*n)+1)]), 16)
            tbk['t'] = int(hexlify(keyval[nbytes*((2*n)+1):nbytes*(2*(n+1))]),
                           16) % _C['n']
            self.tbk.append(tbk)
        rehash = keyval[-nbytes:]
        self.t0 = 0x40000000 + (0x0FFFFFFF & int(hexlify(rehash[:4]), 16))
        self.ts = _tsmin + (int(hexlify(rehash[4:8]), 16) % _tsrange)
        maskall = (1 << _masksize) - 1
        maskseed = int(hexlify(rehash), 16)
        mask = maskseed & maskall
        mtgt = (maskseed >> _masksize) & mask
        while bin(mask).count('1') != _maskbits:
            rehash = SHA256.new(rehash).digest()
            maskseed = int(hexlify(rehash), 16)
            mask = maskseed & maskall
            mtgt = (maskseed >> _masksize) & mask
        self.addr['mask'] = mask
        self.addr['mtgt'] = mtgt
        self.calc_public_key()
        self.initialized = True
