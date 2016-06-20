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
# * Neither the name of ecpy nor the names of its
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

import ciphrtxt.keys as keys
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode
import time
import hashlib

from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.Util import Counter

from ecpy.curves import curve_secp256k1
from ecpy.point import Point, Generator
from ecpy.ecdsa import ECDSA

# version = 1.00 in fixed point
_msg_api_ver = b'M0100'

_C = curve_secp256k1
# _C = curve_secp384r1
# _C = curve_secp112r1
# _C = curve_bauer9

_masksize = min(32, _C['bits'])
_maskbits = (int((_masksize / 3) + 0))

_G = Generator.init(_C['G'][0], _C['G'][1])
ECDSA.set_curve(_C)
ECDSA.set_generator(_G)
_ecdsa = ECDSA()

# convert integer to hex string
_pfmt = b'%%0%dx' % (((_C['bits'] + 7) >> 3) << 1)
_mfmt = b'%%0%dx' % (((_masksize + 7) >> 3) << 1)

_header_size = (5+1+8+1+8+1+66+1+66+1+66)

_default_ttl = (7*24*60*60)

class MessageHeader (object):
    def __init__(self):
        self.time = None
        self.expire = None
        self.I = None
        self.J = None
        self.K = None

    def _serialize_header(self):
        hdr = _msg_api_ver + ':' + ('%08X' % self.time) + ':'
        hdr += ('%08X' % self.expire) + ':' + self.I.compress() + ':'
        hdr += self.J.compress() + ':' + self.K.compress()
        return hdr

    def serialize(self):
        return self._serialize_header()

    @staticmethod
    def deserialize(cmsg):
        z = MessageHeader()
        if z._deserialize_header(cmsg):
            return z
        else:
            return None

    def _deserialize_header(self, cmsg):
        if len(cmsg) < _header_size:
            return False
        hdrdata = cmsg[:_header_size].split(':')
        if len(hdrdata) != 6:
            return False
        if hdrdata[0] != _msg_api_ver:
            return False
        self.time = int(hdrdata[1], 16)
        self.expire = int(hdrdata[2], 16)
        self.I = Point.decompress(hdrdata[3])
        self.J = Point.decompress(hdrdata[4])
        self.K = Point.decompress(hdrdata[5])
        return True

    def is_for(self, privkey):
        if ((self.I.affine()[0] >> (_C['bits'] - keys._masksize)) &
                privkey.addr['mask']) != privkey.addr['mtgt']:
            return False
        return self.I * privkey.current_privkey_val(self.time) == self.J

    def __eq__(self,h):
        if self.time != h.time:
            return False
        if self.expire != h.expire:
            return False
        if self.I != h.I:
            return False
        if self.J != h.J:
            return False
        if self.K != h.K:
            return False
        return True
    
    def __ne__(self, h):
        return not (self == h)

    def __str__(self):
        return self.serialize()

    def __repr__(self):
        return 'MessageHeader.deserialize('+ self.serialize() + ')'



class Message (MessageHeader):
    def __init__(self, cmsg=None):
        super(self.__class__, self).__init__()
        self.s = None
        self.ptxt = None
        self.ctxt = None
        self.altK = None
        self.sig = None
        if cmsg is not None:
            self.import_message(cmsg)

    @staticmethod
    def deserialize(cmsg):
        hdrdata = cmsg.split(':')
        if len(hdrdata) != 9:
            return None
        z = Message()
        if not z._deserialize_header(cmsg[:_header_size]):
            return None
        try:
            z.sig = (int(hdrdata[6], 16), int(hdrdata[7], 16))
            z.ctxt = b64decode(hdrdata[8])
        except:
            return None
        return z

    def serialize(self):
        return (self._serialize_header() + ':' + _pfmt % self.sig[0] + ':' +
                _pfmt % self.sig[1] + ':' + b64encode(self.ctxt))

    def _decode(self,DH):
        sigpriv = int(hashlib.sha256((DH.compress()).encode()).hexdigest(), 16) % _C['n']
        sigpub = _G * sigpriv
        if not _ecdsa.verify(sigpub, self.sig, self.ctxt, self._serialize_header()):
            #print('signature error, aborting decode')
            return False
        iv = int(self.I.compress()[-32:],16)
        keybin = unhexlify(DH.compress()[-64:])
        counter = Counter.new(128,initial_value=iv)
        cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
        etxt = cryptor.decrypt(self.ctxt)
        msg = etxt.split(':')
        if len(msg) != 2:
            # print('split failed')
            return False
        if len(msg[0]) != 64:
            # print('s length failed')
            return False
        s = 0
        try:
            s = int(msg[0],16)
        except ValueError:
            return False
        if self.I != (_G * s):
            # print('I did not match s')
            return False
        try:
            self.ptxt = b64decode(msg[1])
        except:
            # print('base64 decode failed')
            return False
        self.s = s
        return True

    def decode(self, privkey):
        if not self.is_for(privkey):
            # print('not for me')
            return False
        DH = self.K * privkey.current_privkey_val(self.time)
        return self._decode(DH)

    def decode_sent(self, privkey, altK=None):
        if altK is None:
            if self.altK is None:
                return False
            altk = self.altK
        DH = altK * privkey.current_privkey_val(self.time)
        if self._decode(DH):
            self.altK = altK
            return True
        return False

    @staticmethod
    def encode(ptxt, pubkey, privkey=None, progress_callback=None, 
               ttl=_default_ttl):
        if ptxt is None or len(ptxt) == 0:
            print('message of zero length')
            return None
        tval = int(time.time())
        texp = tval + ttl
        if privkey is None:
            q = random.randint(2, _C['n']-1)
        else:
            q = privkey.current_privkey_val(tval)
            if q is None:
                print('privkey is None')
                return None
        P = pubkey.current_pubkey_point(tval)
        if P is None:
            print('pubkey is None')
            return None
        status = {}
        status['besthash'] = 0
        status['bestbits'] = _masksize
        status['nhash'] = 0
        while True:
            s = random.randint(2, _C['n']-1)
            I = _G * s
            maskval = ((I.affine()[0] >> (_C['bits'] - _masksize)) &
                       pubkey.addr['mask'])
            maskmiss = bin(maskval ^ pubkey.addr['mtgt']).count('1')
            if maskmiss < status['bestbits']:
                status['bestbits'] = maskmiss
                status['besthash'] = maskval
            if maskval == pubkey.addr['mtgt']:
                break
            if progress_callback:
                if (status['nhash'] % 10) == 0:
                    progress_callback(status)
            status['nhash'] += 1
        J = P * s
        stext = _pfmt % s
        h = int(hashlib.sha256((stext + ptxt).encode()).hexdigest(), 16)
        k = (q * h) % _C['n']
        K = _G * k
        DH = P * k
        iv = int(I.compress()[-32:],16)
        keybin = unhexlify(DH.compress()[-64:])
        counter = Counter.new(128,initial_value=iv)
        cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
        msg = (_pfmt % s) + ':' + b64encode(ptxt)
        ctxt = cryptor.encrypt(msg)
        altK = P * h
        z = Message()
        z.time = tval
        z.expire = texp
        z.s = s
        z.I = I
        z.J = J
        z.K = K
        z.ptxt = ptxt
        z.ctxt = ctxt
        z.altK = altK
        header = z._serialize_header()
        sigpriv = int(hashlib.sha256((DH.compress()).encode()).hexdigest(), 16) % _C['n']
        z.sig = _ecdsa.sign(sigpriv, ctxt, header)
        return z
        
    @staticmethod
    def encode_impersonate(ptxt, pubkey, privkey, progress_callback=None, 
               ttl=_default_ttl):
        if ptxt is None or len(ptxt) == 0:
            return False
        tval = int(time.time())
        texp = tval + ttl
        q = privkey.current_privkey_val(tval)
        if q is None:
            return False
        Q = privkey.current_pubkey_point(tval)
        P = pubkey.current_pubkey_point(tval)
        if P is None:
            return False
        status = {}
        status['besthash'] = 0
        status['bestbits'] = _masksize
        status['nhash'] = 0
        while True:
            s = random.randint(2, _C['n']-1)
            I = _G * s
            maskval = ((I.affine()[0] >> (_C['bits'] - _masksize)) &
                       privkey.addr['mask'])
            maskmiss = bin(maskval ^ privkey.addr['mtgt']).count('1')
            if maskmiss < status['bestbits']:
                status['bestbits'] = maskmiss
                status['besthash'] = maskval
            if maskval == privkey.addr['mtgt']:
                break
            if progress_callback:
                if (status['nhash'] % 10) == 0:
                    progress_callback(status)
            status['nhash'] += 1
        J = Q * s
        stext = _pfmt % s
        h = int(hashlib.sha256((stext + ptxt).encode()).hexdigest(), 16)
        k = (q * h) % _C['n']
        K = P * h
        DH = P * k
        iv = int(I.compress()[-32:],16)
        keybin = unhexlify(DH.compress()[-64:])
        counter = Counter.new(128,initial_value=iv)
        cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
        msg = (_pfmt % s) + ':' + b64encode(ptxt)
        ctxt = cryptor.encrypt(msg)
        altK = Q * h
        z = Message()
        z.time = tval
        z.expire = texp
        z.s = s
        z.I = I
        z.J = J
        z.K = K
        z.ptxt = ptxt
        z.ctxt = ctxt
        z.altK = altK
        header = z._serialize_header()
        sigkey = int(hashlib.sha256((DH.compress()).encode()).hexdigest(), 16) % _C['n']
        z.sig = _ecdsa.sign(sigkey, ctxt, header)
        return z

    def __eq__(self, r):
        if not super(self.__class__, self).__eq__(r):
            return False
        if self.ctxt != r.ctxt:
            return False
        return True
    
    def __ne__(self, r):
        return not (self == r)

    def __str__(self):
        return self.serialize()

    def __repr__(self):
        return 'Message.deserialize(' + self.serialize() + ')'
    