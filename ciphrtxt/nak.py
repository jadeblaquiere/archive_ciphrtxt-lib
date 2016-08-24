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

from Crypto.Random import random

from binascii import hexlify, unhexlify
import time
import json

from ecpy.curves import curve_secp256k1
from ecpy.point import Point, Generator
from ecpy.ecdsa import ECDSA

_def_curve = curve_secp256k1
Point.set_curve(_def_curve)
ECDSA.set_curve(_def_curve)
ECDSA.set_generator(Generator.init(_def_curve['G'][0], _def_curve['G'][1]))

class NAK(object):
    n = _def_curve['n']
    G = Generator.init(_def_curve['G'][0], _def_curve['G'][1])
    ecdsa = ECDSA()
    
    def __init__(self, expire=None, pubkey=None, signature=None, privkey=None):
        self.expire = expire
        self.pubkey = pubkey
        self.signature = signature
        self.privkey = privkey
        if privkey is not None and pubkey is None:
            self.pubkey = NAK.G * privkey
        if self.pubkey is not None:
            self.pubkeyb = unhexlify(self.pubkey.compress())
        else:
            self.pubkeyb = None

    @staticmethod
    def deserialize(rawbytes):
        etime = int(hexlify(rawbytes[0:4]), 16)
        #print('time = ' + str(time.gmtime(etime)))
        Pkey = Point.decompress(hexlify(rawbytes[4:37]))
        #print('point = ' + Pkey.compress())
        sig0 = int(hexlify(rawbytes[37:69]),16)
        sig1 = int(hexlify(rawbytes[69:101]),16)
        sig = (sig0, sig1)
        #print('sig = (0x%032x, 0x%032x)' % (sig[0], sig[1]))
        #print('verifying %s' % hexlify(rawbytes[:37]))
        if not NAK.ecdsa.verify(Pkey,sig,rawbytes[:37]):
            #print('verify failed')
            return None
        return NAK(etime, Pkey, sig)

    def serialize(self):
        hexmsg = b'%08x' % self.expire
        hexmsg += self.pubkey.compress()
        if self.signature is None:
            if self.privkey is None:
                return None
            else:
                bmsg = unhexlify(hexmsg)
                self.signature = NAK.ecdsa.sign(self.privkey, bmsg)
        hexmsg += b'%064x' % self.signature[0]
        hexmsg += b'%064x' % self.signature[1]
        return unhexlify(hexmsg)

    def randomize(self, expire=None):
        self.privkey = random.randint(1,NAK.n-1)
        self.pubkey = NAK.G * self.privkey
        if expire is not None:
            self.expire = expire
        else:
            self.expire = int(time.time()) + (365*24*60*60)
        self.serialize()

    def dumpjson(self):
        exp = {}
        if self.signature is None:
            serialized = self.serialize()
            if serialized is None:
                return None
        exp['pubkey'] = self.pubkey.compress().decode()
        exp['expire'] = self.expire
        exp['signature'] = self.signature
        return json.dumps(exp)

    @staticmethod
    def loadjson(load):
        try:
            raw = json.loads(load)
            expire = raw['expire']
            pubkey = Point.decompress(raw['pubkey'])
            signature = raw['signature']
            return NAK(expire, pubkey, signature)
        except:
            return None

    def sign(self,message):
        if self.privkey is None:
            return None
        return NAK.ecdsa.sign(self.privkey, message.encode('UTF8'))

    def verify(self,signature,message):
        if self.pubkey is None:
            return False
        return NAK.ecdsa.verify(self.pubkey, signature, message.encode('UTF-8'))

    def pubkeybin(self):
        if self.pubkeyb is not None:
            return self.pubkeyb
        if self.pubkey is not None:
            self.pubkeyb = unhexlify(self.pubkey.compress())
            return self.pubkeyb
        return None

    def __eq__(self, r):
        if self.expire != r.expire:
            return False
        if self.pubkey != r.pubkey:
            return False
        return True

    def __ne__(self, r):
        return not (self == r)

    def __gt__(self, r):
        if self.expire == r.expire:
            return self.pubkey.compress() > r.pubkey.compress()
        return self.expire > r.expire

    def __lt__(self, r):
        if self.expire == r.expire:
            return self.pubkey.compress() < r.pubkey.compress()
        return self.expire < r.expire

    def __le__(self, r):
        return not (self > r)

    def __ge__(self, r):
        return not (self < r)
    
    def __str__(self):
        return str(self.pubkey) + ' expires ' + str(time.gmtime(self.expire))
    
    def __repr__(self):
        ser = self.serialize()
        if ser is not None:
            return 'NAK.deserialize(unhexlify(%s))' % hexlify(ser)
        return 'NAK(0x%08x,Point.decompress(%s))' % (self.expire, self.pubkey.compress())
