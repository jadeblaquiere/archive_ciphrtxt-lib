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

import ciphrtxt.keys as keys
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode
import time
from hashlib import sha256
import struct

from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.Util import Counter

from ecpy.curves import curve_secp256k1
from ecpy.point import Point, Generator
from ecpy.ecdsa import ECDSA

# version = 1.00 in fixed point
_msg_api_ver_v1 = b'M0100'
_msg_api_ver_v2 = b'M\x02\x00\x00'

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
_pfmt = '%%0%dx' % (((_C['bits'] + 7) >> 3) << 1)
_mfmt = '%%0%dx' % (((_masksize + 7) >> 3) << 1)

# 256 bit message seed
_s_bytes = 32 
# 64 bit plaintext length field
_l_bytes = 8

_lfmt = '%016x'

_header_size_v1 = (5+1+8+1+8+1+66+1+66+1+66)
_header_size_w_sig_v1 = (5+1+8+1+8+1+66+1+66+1+66+1+64+1+64)

#v2 header = "M" + b"x02\x00\x00" (version) + time (32 bit/4 byte uint) + 
#            expire (32 bit/4 byte uint) + I + J + K (33 byte ECC points) +
#            blocklen (32 bit/4 byte uint) + reserved (8 bytes)
#          = 123 bytes (binary) -> 164bytes (b64) 
_header_size_v2 = (1+3+4+4+33+33+33+4+8)
_header_size_b64_v2 = (_header_size_v2 * 4 // 3)
#          + r + s (32 byte uints *2) + nonce (5 byte uint) 
#          = 69 bytes (binary) -> 92 bytes (b64)
#   total  : 192 bytes (binary) -> 256 bytes b64
_header_size_w_sig_v2 = (_header_size_v2+32+32+5)
_header_size_w_sig_b64_v2 = (_header_size_w_sig_v2 * 4 // 3)

_v2_blocksize = 192
_v2_blocksize_b64 = (_v2_blocksize * 4 // 3)

#minimum valid message payload = one "block" 
_minimum_cipher_payload = _v2_blocksize
_minimum_cipher_payload_b64 = (_minimum_cipher_payload * 4 // 3)

_default_ttl = (7*24*60*60)

#defines the target for hashcash-like message nonce
_default_nbits = 16

class MessageHeader (object):
    def __init__(self):
        self.time = None
        self.expire = None
        self.I = None
        self.J = None
        self.K = None
        self.sig = None
        self.nonce = None
        self.blocklen = 0
        self.reserved = 0
        self.version = "0200"

    def _short_header_v1(self):
        hdr = _msg_api_ver_v1 + b':' + ('%08X' % self.time).encode() + b':'
        hdr += ('%08X' % self.expire).encode() + b':' + self.Iraw() + b':'
        hdr += self.Jraw() + b':' + self.Kraw()
        return hdr

    def _short_header_v2(self):
        # print('short header blocklen = ' + str(self.blocklen))
        hdr = _msg_api_ver_v2 + unhexlify('%08X' % self.time) 
        hdr += unhexlify('%08X' % self.expire) + unhexlify(self.Iraw())
        hdr += unhexlify(self.Jraw()) + unhexlify(self.Kraw())
        hdr += unhexlify('%08X' % self.blocklen)
        hdr += unhexlify('%016X' % self.reserved)
        return b64encode(hdr)

    def _short_header(self):
        if self.version == "0100":
            return self._short_header_v1()
        else:
            return self._short_header_v2()

    def _long_header(self):
        if self.version == "0100":
            return self._short_header() + b':' + (_pfmt % self.sig[0]).encode() + b':' + (_pfmt % self.sig[1]).encode()
        else:
            h2 = unhexlify(_pfmt % self.sig[0]) + unhexlify(_pfmt % self.sig[1])
            h2 += unhexlify("%010X" % self.nonce)
            return self._short_header_v2() + b64encode(h2)

    def serialize(self):
        return self._short_header()

    def serialize_header(self):
        return self._long_header()

    @staticmethod
    def deserialize(cmsg):
        if isinstance(cmsg, str):
            cmsg = cmsg.encode()
        z = MessageHeader()
        if z._deserialize_header(cmsg):
            return z
        else:
            return None
        
    def _deserialize_header(self,cmsg):
        if cmsg[0:3] == b'M01':
            return self._deserialize_header_v1(cmsg)
        else:
            return self._deserialize_header_v2(cmsg)

    def _deserialize_header_v1(self, cmsg):
        if len(cmsg) < _header_size_v1:
            return False
        hdrdata = cmsg[:_header_size_v1].split(b':')
        if len(hdrdata) != 6:
            return False
        if hdrdata[0] != _msg_api_ver_v1:
            return False
        self.time = int(hdrdata[1], 16)
        self.expire = int(hdrdata[2], 16)
        self.I = Point.decompress(hdrdata[3])
        self.J = Point.decompress(hdrdata[4])
        self.K = Point.decompress(hdrdata[5])
        self.version = "0100"
        if len(cmsg) >= _header_size_w_sig_v1:
            hdrdata = cmsg[:_header_size_w_sig_v1].split(b':')
            if len(hdrdata) != 8:
                return False
            self.sig = (int(hdrdata[6], 16), int(hdrdata[7], 16))
        return True

    def _deserialize_header_v2(self, cmsg):
        if len(cmsg) < _header_size_b64_v2:
            return False
        binmsg = b64decode(cmsg[:_header_size_b64_v2])
        if binmsg[0:4] != _msg_api_ver_v2:
            return False
        hexmsg = hexlify(binmsg)
        self.time = int(hexmsg[8:16], 16)
        self.expire = int(hexmsg[16:24], 16)
        if not (hexmsg[24:26] == b'02' or hexmsg[24:26] == b'03'):
            return False
        if not (hexmsg[90:92] == b'02' or hexmsg[90:92] == b'03'):
            return False
        if not (hexmsg[156:158] == b'02' or hexmsg[156:158] == b'03'):
            return False
        self.I = Point.decompress(hexmsg[24:90])
        self.J = Point.decompress(hexmsg[90:156])
        self.K = Point.decompress(hexmsg[156:222])
        self.blocklen = int(hexmsg[222:230], 16)
        self.reserved = int(hexmsg[230:246], 16)
        # print('deserialize blocklen = ' + str(self.blocklen))
        if len(cmsg) >= _header_size_w_sig_b64_v2:
            sig_b64 = cmsg[_header_size_b64_v2:_header_size_w_sig_b64_v2]
            sighex = hexlify(b64decode(sig_b64))
            self.sig = (int(sighex[0:64], 16), int(sighex[64:128], 16))
            self.nonce = int(sighex[128:138], 16)
        return True

    def is_for(self, privkey):
        if ((self.I.affine()[0] >> (_C['bits'] - keys._masksize)) &
                privkey.addr['mask']) != privkey.addr['mtgt']:
            return False
        return self.I * privkey.current_privkey_val(self.time) == self.J

    def Iraw(self):
        return self.I.compress()

    def Jraw(self):
        return self.J.compress()

    def Kraw(self):
        return self.K.compress()

    def _decompress(self):
        return

    def __eq__(self,h):
        if self.time != h.time:
            return False
        if self.expire != h.expire:
            return False
        if isinstance(h, RawMessageHeader):
            h._decompress()
        if self.I != h.I:
            return False
        if self.J != h.J:
            return False
        if self.K != h.K:
            return False
        return True

    def __ne__(self, h):
        return not (self == h)

    def __gt__(self, h):
        if self.time > h.time:
            return True
        if self.time < h.time:
            return False
        return self.Iraw() > h.Iraw()

    def __lt__(self, h):
        if self.time < h.time:
            return True
        if self.time > h.time:
            return False
        return self.Iraw() < h.Iraw()

    def __ge__(self, h):
        return not self < h

    def __le__(self, h):
        return not self > h

    def __str__(self):
        return self.serialize().decode()

    def __repr__(self):
        return 'MessageHeader.deserialize('+ self.serialize().decode() + ')'


class RawMessageHeader(MessageHeader):
    def __init__(self):
        super(RawMessageHeader, self).__init__()
        self._Iraw = None
        self._Jraw = None
        self._Kraw = None

    @staticmethod
    def deserialize(cmsg):
        if isinstance(cmsg, str):
            cmsg = cmsg.encode()
        z = RawMessageHeader()
        if z._deserialize_header(cmsg):
            return z
        else:
            return None

    def _deserialize_header(self, cmsg):
        if cmsg[0:3] == b'M01':
            return self._deserialize_header_v1(cmsg)
        else:
            return self._deserialize_header_v2(cmsg)

    def _deserialize_header_v1(self, cmsg):
        if len(cmsg) < _header_size_v1:
            return False
        hdrdata = cmsg[:_header_size_v1].split(b':')
        if len(hdrdata) != 6:
            return False
        if hdrdata[0] != _msg_api_ver_v1:
            return False
        self.time = int(hdrdata[1], 16)
        self.expire = int(hdrdata[2], 16)
        self._Iraw = hdrdata[3]
        self._Jraw = hdrdata[4]
        self._Kraw = hdrdata[5]
        self.I = None
        self.J = None
        self.K = None
        self.version = "0100"
        if len(cmsg) >= _header_size_w_sig_v1:
            hdrdata = cmsg[:_header_size_w_sig_v1].split(b':')
            if len(hdrdata) != 8:
                return False
            self.sig = (int(hdrdata[6], 16), int(hdrdata[7], 16))
        return True

    def _deserialize_header_v2(self, cmsg):
        if len(cmsg) < _header_size_b64_v2:
            return False
        binmsg = b64decode(cmsg[:_header_size_b64_v2])
        if binmsg[0:4] != _msg_api_ver_v2:
            return False
        hexmsg = hexlify(binmsg)
        self.time = int(hexmsg[8:16], 16)
        self.expire = int(hexmsg[16:24], 16)
        if not (hexmsg[24:26] == b'02' or hexmsg[24:26] == b'03'):
            return False
        if not (hexmsg[90:92] == b'02' or hexmsg[90:92] == b'03'):
            return False
        if not (hexmsg[156:158] == b'02' or hexmsg[156:158] == b'03'):
            return False
        self._Iraw = hexmsg[24:90]
        self._Jraw = hexmsg[90:156]
        self._Kraw = hexmsg[156:222]
        self.I = None
        self.J = None
        self.K = None
        self.blocklen = int(hexmsg[222:230], 16)
        self.reserved = int(hexmsg[230:246], 16)
        if len(cmsg) >= _header_size_w_sig_b64_v2:
            sig_b64 = cmsg[_header_size_b64_v2:_header_size_w_sig_b64_v2]
            sighex = hexlify(b64decode(sig_b64))
            self.sig = (int(sighex[0:64], 16), int(sighex[64:128], 16))
            self.nonce = int(sighex[128:138], 16)
        return True

    def Iraw(self):
        return self._Iraw

    def Jraw(self):
        return self._Jraw

    def Kraw(self):
        return self._Kraw

    def __eq__(self,h):
        if self.time != h.time:
            return False
        if self.expire != h.expire:
            return False
        if self.Iraw() != h.Iraw():
            return False
        if self.Jraw() != h.Jraw():
            return False
        if self.Kraw() != h.Kraw():
            return False
        return True

    def __repr__(self):
        return 'RawMessageHeader.deserialize('+ self.serialize().decode() + ')'

    def _decompress(self):
        self.I = Point.decompress(self._Iraw)
        self.J = Point.decompress(self._Jraw)
        self.K = Point.decompress(self._Kraw)


class Message (MessageHeader):
    def __init__(self, cmsg=None):
        super(Message, self).__init__()
        self.s = None
        self.ptxt = None
        self.ctxt = None
        self.altK = None
        self.h = None
        if cmsg is not None:
            self.import_message(cmsg)

    @staticmethod
    def deserialize(cmsg):
        if isinstance(cmsg, str):
            cmsg = cmsg.encode()
        z = Message()
        if z._deserialize(cmsg):
            return z
        else:
            return None

    def _deserialize(self,cmsg):
        if cmsg[0:3] == b'M01':
            return self._deserialize_v1(cmsg)
        else:
            return self._deserialize_v2(cmsg)

    def _deserialize_v1(self,cmsg):
        hdrdata = cmsg.split(b':')
        if len(hdrdata) != 9:
            return False
        if not self._deserialize_header_v1(cmsg[:_header_size_w_sig_v1]):
            return False
        try:
            self.ctxt = b64decode(hdrdata[8])
        except:
            return False
        return True

    def _deserialize_v2(self,cmsg):
        if (len(cmsg) & 0xFF) != 0:
            return False
        if len(cmsg) < (_header_size_w_sig_b64_v2 + _minimum_cipher_payload_b64):
            return False
        if not self._deserialize_header_v2(cmsg[:_header_size_w_sig_b64_v2]):
            return False
        blocks = (len(cmsg) - _header_size_w_sig_b64_v2) // _v2_blocksize_b64
        if self.blocklen != blocks:
            print('block length mismatch ' + str(blocks) + ' != ' + str(self.blocklen))
            return False
        try:
            self.ctxt = b64decode(cmsg[_header_size_w_sig_b64_v2:])
        except:
            return False
        return True

    def serialize(self):
        if self.version == "0100":
            return self._serialize_v1()
        else:
            return self._serialize_v2()

    def _serialize_v1(self):
        return (self._short_header() + b':' + (_pfmt % self.sig[0]).encode() + b':' +
                (_pfmt % self.sig[1]).encode() + b':' + b64encode(self.ctxt))

    def _serialize_v2(self):
        h2 = unhexlify(_pfmt % self.sig[0]) + unhexlify(_pfmt % self.sig[1])
        h2 += unhexlify("%010X" % self.nonce)
        return self._short_header_v2() + b64encode(h2) + b64encode(self.ctxt)

    def _decode_v1(self,DH):
        sp = int(sha256(DH.compress()).hexdigest(), 16) % _C['n']
        SP = _G * sp
        if not _ecdsa.verify(SP, self.sig, self.ctxt, self._short_header()):
            return False
        iv = int(self.I.compress()[-32:],16)
        keybin = unhexlify(DH.compress()[-64:])
        counter = Counter.new(128,initial_value=iv)
        cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
        etxt = cryptor.decrypt(self.ctxt)
        msg = etxt.split(b':')
        if len(msg) != 2:
            return False
        if len(msg[0]) != 64:
            return False
        s = 0
        try:
            s = int(msg[0],16)
        except ValueError:
            return False
        if self.I != (_G * s):
            return False
        try:
            self.ptxt = b64decode(msg[1])
        except:
            return False
        self.ptxt = self.ptxt.decode()
        self.s = s
        stext = (_pfmt % s).encode()
        self.h = int(sha256(stext + self.ptxt.encode()).hexdigest(), 16)
        return True

    def _decode_v2(self,DH):
        sp = int(sha256(DH.compress()).hexdigest(), 16) % _C['n']
        SP = _G * sp
        if not _ecdsa.verify(SP, self.sig, self.ctxt, self._short_header()):
            return False
        iv = int(self.I.compress()[-32:],16)
        keybin = unhexlify(DH.compress()[-64:])
        counter = Counter.new(128,initial_value=iv)
        cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
        etxt = cryptor.decrypt(self.ctxt)
        if len(etxt) < _minimum_cipher_payload:
            return False
        s = int(hexlify(etxt[:32]), 16)
        if self.I != (_G * s):
            return False
        l = int(hexlify(etxt[32:40]), 16)
        if len(etxt) < (40 + l):
            return False
        self.ptxt = etxt[40:40+l].decode()
        self.s = s
        self.h = int(sha256(etxt).hexdigest(), 16)
        return True

    def decode(self, privkey):
        if not self.is_for(privkey):
            return False
        DH = self.K * privkey.current_privkey_val(self.time)
        if self.version == "0100":
            return self._decode_v1(DH)
        else:
            return self._decode_v2(DH)

    def decode_sent(self, privkey, altK=None):
        if altK is None:
            if self.altK is None:
                return False
            altk = self.altK
        DH = altK * privkey.current_privkey_val(self.time)
        if self.version == "0100":
            if self._decode_v1(DH):
                self.altK = altK
                return True
            return False
        else:
            if self._decode_v2(DH):
                self.altK = altK
                return True
            return False

    @staticmethod
    def encode(ptxt, pubkey, privkey=None, progress_callback=None, 
               ttl=_default_ttl, version="0200", nbits=_default_nbits):
        z = Message()
        if version == "0100":
            return z._encode_v1(ptxt, pubkey, privkey, progress_callback,
                             ttl=_default_ttl)
        else:
            return z._encode_v2(ptxt, pubkey, privkey, progress_callback,
                             ttl=_default_ttl, nbits=nbits)

    @staticmethod
    def encode_impersonate(ptxt, pubkey, privkey, progress_callback=None, 
               ttl=_default_ttl, version="0200", nbits=_default_nbits):
        z = Message()
        if version == "0100":
            return z._encode_impersonate_v1(ptxt, pubkey, privkey, progress_callback,
                             ttl=_default_ttl)
        else:
            return z._encode_impersonate_v2(ptxt, pubkey, privkey, progress_callback,
                             ttl=_default_ttl, nbits=nbits)
    
    def _encode_v1(self, ptxt, pubkey, privkey=None, progress_callback=None, 
               ttl=_default_ttl):
        if ptxt is None or len(ptxt) == 0:
            return None
        tval = int(time.time())
        texp = tval + ttl
        if privkey is None:
            q = random.randint(2, _C['n']-1)
        else:
            q = privkey.current_privkey_val(tval)
            if q is None:
                return None
        P = pubkey.current_pubkey_point(tval)
        if P is None:
            return None
        status = {}
        status['besthash'] = 0
        status['bestbits'] = _masksize
        status['nhash'] = 0
        status['nhash2'] = 0
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
        stext = (_pfmt % s).encode()
        h = int(sha256(stext + ptxt.encode()).hexdigest(), 16)
        k = (q * h) % _C['n']
        K = _G * k
        DH = P * k
        iv = int(I.compress()[-32:],16)
        keybin = unhexlify(DH.compress()[-64:])
        counter = Counter.new(128,initial_value=iv)
        cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
        msg = (_pfmt % s).encode() + b':' + b64encode(ptxt.encode())
        ctxt = cryptor.encrypt(msg)
        altK = P * h
        self.time = tval
        self.expire = texp
        self.s = s
        self.I = I
        self.J = J
        self.K = K
        self.ptxt = ptxt
        self.ctxt = ctxt
        self.altK = altK
        self.h = h
        self.version = "0100"
        header = self._short_header()
        sigpriv = int(sha256(DH.compress()).hexdigest(), 16) % _C['n']
        self.sig = _ecdsa.sign(sigpriv, ctxt, header)
        return self

    def _encode_impersonate_v1(self, ptxt, pubkey, privkey, progress_callback=None, 
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
        status['nhash2'] = 0
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
        stext = (_pfmt % s).encode()
        h = int(sha256(stext + ptxt.encode()).hexdigest(), 16)
        k = (q * h) % _C['n']
        K = P * h
        DH = P * k
        iv = int(I.compress()[-32:],16)
        keybin = unhexlify(DH.compress()[-64:])
        counter = Counter.new(128,initial_value=iv)
        cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
        msg = (_pfmt % s).encode() + b':' + b64encode(ptxt.encode())
        ctxt = cryptor.encrypt(msg)
        altK = Q * h
        self.time = tval
        self.expire = texp
        self.s = s
        self.I = I
        self.J = J
        self.K = K
        self.ptxt = ptxt
        self.ctxt = ctxt
        self.altK = altK
        self.version = "0100"
        header = self._short_header()
        sigkey = int(sha256(DH.compress()).hexdigest(), 16) % _C['n']
        self.sig = _ecdsa.sign(sigkey, ctxt, header)
        return self

    def _encode_v2(self, ptxt, pubkey, privkey=None, progress_callback=None, 
               ttl=_default_ttl, nbits=_default_nbits):
        if ptxt is None or len(ptxt) == 0:
            return None
        tval = int(time.time())
        texp = tval + ttl
        if privkey is None:
            q = random.randint(2, _C['n']-1)
        else:
            q = privkey.current_privkey_val(tval)
            if q is None:
                return None
        P = pubkey.current_pubkey_point(tval)
        if P is None:
            return None
        status = {}
        while True:
            status['besthash'] = 0
            status['bestbits'] = _masksize
            status['nhash'] = 0
            status['nhash2'] = 0
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
            ptxtenc = ptxt.encode()
            ptxtlen = len(ptxtenc)
            padlen = _v2_blocksize - ((ptxtlen + _s_bytes + _l_bytes) % _v2_blocksize)
            stxt = unhexlify(_pfmt % s) + unhexlify(_lfmt % ptxtlen) +  ptxtenc + (struct.pack('>B',padlen) * padlen)
            h = int(sha256(stxt).hexdigest(), 16)
            k = (q * h) % _C['n']
            K = _G * k
            DH = P * k
            iv = int(I.compress()[-32:],16)
            keybin = unhexlify(DH.compress()[-64:])
            counter = Counter.new(128,initial_value=iv)
            cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
            ctxt = cryptor.encrypt(stxt)
            altK = P * h
            self.time = tval
            self.expire = texp
            self.s = s
            self.I = I
            self.J = J
            self.K = K
            self.blocklen = len(stxt) // _v2_blocksize
            self.ptxt = ptxt
            self.ctxt = ctxt
            self.altK = altK
            self.h = h
            print("message len " + str(ptxtlen) + " + 40 + padlen " + str(padlen) + " = total " + str(len(stxt)) + ", encoded to " + str(len(ctxt)) + " bytes, " + str(self.blocklen) + " blocks")
            header = self._short_header_v2()
            sigpriv = int(sha256(DH.compress()).hexdigest(), 16) % _C['n']
            self.sig = _ecdsa.sign(sigpriv, ctxt, header)
            nonceM = 0
            nonceL = 0
            hhash = 0
            htgt = 1 << (256 - nbits)
            hval = htgt + 1
            while True:
                h2 = unhexlify(_pfmt % self.sig[0]) + unhexlify(_pfmt % self.sig[1])
                h2 += unhexlify("%04X" % nonceM)
                p_hdr = header + b64encode(h2)
                Msha = sha256(p_hdr)
                while True:
                    Lsha = Msha.copy()
                    Lsha.update(b64encode(unhexlify("%06X" % nonceL)))
                    hval = int(Lsha.hexdigest(), 16)
                    if hval < htgt:
                        break
                    nonceL += 1
                    if nonceL >= (1 << 24):
                        nonceM += 1
                        nonceL = 0
                        break
                    if progress_callback:
                        if (status['nhash2'] % 100) == 0:
                            progress_callback(status)
                        status['nhash2'] += 1
                if hval < htgt:
                    break
            self.nonce = (nonceM << 24) + nonceL
            if hval < htgt:
                break
        return self

    def _encode_impersonate_v2(self, ptxt, pubkey, privkey, progress_callback=None, 
               ttl=_default_ttl, nbits=_default_nbits):
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
        while True:
            status['besthash'] = 0
            status['bestbits'] = _masksize
            status['nhash'] = 0
            status['nhash2'] = 0
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
            ptxtenc = ptxt.encode()
            ptxtlen = len(ptxtenc)
            padlen = _v2_blocksize - ((ptxtlen + _s_bytes + _l_bytes) % _v2_blocksize)
            stxt = unhexlify(_pfmt % s) + unhexlify(_lfmt % ptxtlen) +  ptxtenc + (b'\x00' * padlen)
            h = int(sha256(stxt).hexdigest(), 16)
            k = (q * h) % _C['n']
            K = P * h
            DH = P * k
            iv = int(I.compress()[-32:],16)
            keybin = unhexlify(DH.compress()[-64:])
            counter = Counter.new(128,initial_value=iv)
            cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
            ctxt = cryptor.encrypt(stxt)
            print("message imp len " + str(ptxtlen) + " + 40 + padlen " + str(padlen) + " = total " + str(len(stxt)) + ", encoded to " + str(len(ctxt)) + " bytes")
            altK = Q * h
            self.time = tval
            self.expire = texp
            self.s = s
            self.I = I
            self.J = J
            self.K = K
            self.blocklen = len(stxt) // _v2_blocksize
            self.ptxt = ptxt
            self.ctxt = ctxt
            self.altK = altK
            header = self._short_header_v2()
            sigpriv = int(sha256(DH.compress()).hexdigest(), 16) % _C['n']
            self.sig = _ecdsa.sign(sigpriv, ctxt, header)
            nonceM = 0
            nonceL = 0
            hhash = 0
            htgt = 1 << (256 - nbits)
            hval = htgt + 1
            while True:
                h2 = unhexlify(_pfmt % self.sig[0]) + unhexlify(_pfmt % self.sig[1])
                h2 += unhexlify("%04X" % nonceM)
                p_hdr = header + b64encode(h2)
                Msha = sha256(p_hdr)
                while True:
                    Lsha = Msha.copy()
                    Lsha.update(b64encode(unhexlify("%06X" % nonceL)))
                    hval = int(Lsha.hexdigest(), 16)
                    if hval < htgt:
                        break
                    nonceL += 1
                    if nonceL >= (1 << 24):
                        nonceM += 1
                        nonceL = 0
                        break
                    if progress_callback:
                        if (status['nhash2'] % 100) == 0:
                            progress_callback(status)
                        status['nhash2'] += 1
                if hval < htgt:
                    break
            self.nonce = (nonceM << 24) + nonceL
            if hval < htgt:
                break
        return self

    def is_from(self, pubkey):
        if self.h is None:
            return False
        Q = self.h * pubkey.current_pubkey_point(self.time)
        return Q == self.K

    def __eq__(self, r):
        if not super(Message, self).__eq__(r):
            return False
        if self.ctxt != r.ctxt:
            return False
        return True

    def __ne__(self, r):
        return not (self == r)

    def __str__(self):
        return self.serialize().decode()

    def __repr__(self):
        return 'Message.deserialize(' + self.serialize() + ')'

