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

import time
from Crypto.Random import random
from Crypto.Cipher import AES
import hashlib
import hmac
import sys
import base64
#import aes
#import point
from ecpy.curves import curve_secp256k1
from ecpy.point import Point, Generator

_C = curve_secp256k1
# _C = curve_secp384r1
# _C = curve_secp112r1
# _C = curve_bauer9

_masksize = min(32, _C['bits'])
_maskbits = (int((_masksize / 3) + 0))

Generator.set_curve(_C)
_G = Generator.init(_C['G'][0], _C['G'][1])

# parameters for time based keys, median = 24h, sd = 4h, min 12h, max 36h
_tstarget = (60 * 60 * 24)
_tssigma = (60 * 60 * 4)
_tsmin = (60 * 60 * 12)
_tsmax = (60 * 60 * 36)

# convert integer to hex string
_pfmt = b'%%0%dx' % (((_C['bits'] + 7) >> 3) << 1)
_mfmt = b'%%0%dx' % (((_masksize + 7) >> 3) << 1)

# v1.0 in fixed point
_format_version = 0x0100


#def compress_point(P):
#    return ('03' if (P[1] % 2) else '02') + (_pfmt % P[0])


#def decompress_point(K):
#    P = [0, 0]
#    x = P[0] = int(K[2:], 16)
#    sign = int(K[:2], 16) & 1
#    beta = pow(int(x * x * x + _C['a'] * x + _C['b']),
#               int((_C['p'] + 1) // 4), int(_C['p']))
#    P[1] = (_C['p']-beta) if ((beta + sign) & 1) else beta
#    return (P[0], P[1])


class PublicKey (object):
    def __init__(self, name=None):
        self.P = Point(0,0)
        self.addr = {'mask': 0, 'mtgt': 0}
        self.t0 = 0
        self.ts = 0
        self.Tbk = ({'otp' : 0, 'T' : Point(0,0)})
        self.name = name
        self.metadata = {}
        self.initialized = False
        self.last_steps = None
        self.last_pubkey_point = None

    def set_metadata(self, metakey, metavalue):
        self.metadata[metakey] = metavalue

    def get_metadata(self, metakey):
        if metakey not in self.metadata:
            return None
        return self.metadata[metakey]

    def label(self):
        txt = str(self.P)[:8]
        if self.name:
            txt = self.name + '_' + txt
        return txt

    def current_pubkey_point(self, timeval=None):
        """Calulates the current EC public key point as a pseudorandom linear
        combination of the primary P key and multiple time-based T keys using
        an algorithm based on HOTP/TOTP"""
        if not self.initialized:
            return None
        if timeval is None:
            timeval = int(time.time())
        steps = (timeval - self.t0) / self.ts
        if steps == self.last_steps:
            return self.last_pubkey_point
        P = self.P
        for i in range(len(self.Tbk)):
            okeyt = _pfmt % (self.Tbk[i]['otp'])
            stepsd = '%07d' % (steps % 10000000)
            otphmac = hmac.new(okeyt.encode(), stepsd.encode(), hashlib.sha256)
            hashv = otphmac.hexdigest()
            hashi = int(hashv, 16) % _C['p']
            S = (self.Tbk[i]['T']) * hashi
            P = S + P
        self.last_steps = steps
        self.last_pubkey_point = P
        return P

    def serialize_pubkey(self):
        ekey = b'P%04x' % _format_version
        ekey += b':K' + str(self.P)
        ekey += b':M' + (_mfmt % self.addr['mask'])
        ekey += b':N' + (_mfmt % self.addr['mtgt'])
        ekey += b':Z' + (b'%08x' % self.t0)
        ekey += b':S' + (b'%08x' % self.ts)
        ekey += b':R' + (b'%04x' % len(self.Tbk))
        for Tbk in self.Tbk:
            ekey += b':F' + (_pfmt % Tbk['otp'])
            ekey += b':T' + str(Tbk['T'])
        ekey += b':C' + hashlib.sha256(ekey.encode()).hexdigest()[-8:]
        return ekey

    def serialize(self):
        return self.serialize_pubkey()

    @staticmethod
    def deserialize(ikey):
        # verify checksum
        inp = ikey.split(':C')
        if len(inp) != 2:
            return None
        ckck = hashlib.sha256(inp[0].encode()).hexdigest()[-8:]
        if ckck != inp[1]:
            return None
        # verify keys
        inp = inp[0].split(':')
        if len(inp) < 7:
            return None
        if ((inp[0][:1] != 'P') or (inp[1][:1] != 'K') or
                (inp[2][:1] != 'M') or (inp[3][:1] != 'N') or
                (inp[4][:1] != 'Z') or (inp[5][:1] != 'S') or
                (inp[6][:1] != 'R')):
            return None
        # verify version
        if (inp[0][1:] != '0100'):
            return None
        # decompress point
        z = PublicKey()
        z.P = Point.decompress(inp[1][1:])
        #
        z.addr['mask'] = int(inp[2][1:], 16)
        z.addr['mtgt'] = int(inp[3][1:], 16)
        z.t0 = int(inp[4][1:], 16)
        z.ts = int(inp[5][1:], 16)
        # time base key(s)
        ntbk = int(inp[6][1:])
        Tbk = []
        for i in range(ntbk):
            key = {}
            key['otp'] = int(inp[7 + (2 * i)][1:], 16)
            key['T'] = Point.decompress(inp[8 + (2 * i)][1:])
            Tbk.append(key)
        z.Tbk = Tbk
        z.initialized = True
        return z
    
    def __str__(self):
        return self.serialize()
    
    def __repr__(self):
        return 'PublicKey.deserialize(' + self.serialize() + ')'


class PrivateKey (PublicKey):
    def __init__(self, name=None):
        self.p = 0
        self.tbk = ({'otp': 0, 't': 0})
        self.initialized = False
        super(self.__class__, self).__init__(name=name)
        self.last_psteps = None
        self.last_privkey_val = None

    def label(self):
        txt = (_pfmt % self.p)[:8]
        if self.name:
            txt = self.name + '_' + txt
        return txt

    def pubkey_label(self):
        return super(self.__class__, self).label()

    def randomize(self, ntbk=1):
        # base key
        self.p = random.randint(2, _C['n']-1)
        # address mask, value
        maskshift, maskval = 0, 0
        while (maskval == 0) or (_C['n'] < maskshift):
            mask, maskval, match = [], 0, 0
            for i in range(_maskbits):
                while True:
                    r = random.randint(0, _masksize-1)
                    if r not in mask:
                        break
                mask.append(r)
                bit = 1 << r
                maskval = maskval + bit
                match += bit * random.randint(0, 1)
                maskshift = match << (_C['bits'] - _masksize)
        self.addr['mask'] = maskval
        self.addr['mtgt'] = match
        # time zero, step size for rotating key(s)
        self.t0 = random.randint(0, int(time.time()))
        while True:
            r = random.randint(_tstarget-_tssigma, _tstarget+_tssigma)
            if (r > _tsmin) and (r < _tsmax):
                break
        self.ts = r
        # time-based-keys
        self.tbk = []
        for i in range(ntbk):
            tbk = {}
            tbk['otp'] = random.getrandbits(_C['bits'])
            tbk['t'] = random.randint(2, _C['n']-1)
            self.tbk.append(tbk)
        self.calc_public_key()
        self.initialized = True

    def calc_public_key(self):
        self.P = _G * self.p
        self.Tbk = []
        for i in range(len(self.tbk)):
            Tbk = {}
            Tbk['otp'] = self.tbk[i]['otp']
            Tbk['T'] = _G * self.tbk[i]['t']
            self.Tbk.append(Tbk)

    def current_privkey_val(self, timeval=None):
        """Calulates the current EC private key value as a pseudorandom linear
        combination of the primary p key and multiple time-based t keys using
        an algorithm based on HOTP/TOTP"""
        if not self.initialized:
            return None
        if timeval is None:
            timeval = int(time.time())
        steps = (timeval - self.t0) / self.ts
        if steps == self.last_psteps:
            return self.last_privkey_val
        p = self.p
        for i in range(len(self.tbk)):
            okeyt = _pfmt % (self.tbk[i]['otp'])
            stepsd = '%07d' % (steps % 10000000)
            otphmac = hmac.new(okeyt.encode(), stepsd.encode(), hashlib.sha256)
            hashv = otphmac.hexdigest()
            hashi = int(hashv, 16) % _C['p']
            s = (self.tbk[i]['t'] * hashi) % _C['n']
            p = (s + p) % _C['n']
        self.last_psteps = steps
        self.last_privkey_val = p
        return p

    def serialize_privkey(self):
        ekey = 'p%04x' % _format_version
        ekey += ':k' + (_pfmt % self.p)
        ekey += ':m' + (_mfmt % self.addr['mask'])
        ekey += ':n' + (_mfmt % self.addr['mtgt'])
        ekey += ':z' + ('%08x' % self.t0)
        ekey += ':s' + ('%08x' % self.ts)
        ekey += ':r' + ('%04x' % len(self.tbk))
        for tbk in self.tbk:
            ekey += ':f' + (_pfmt % tbk['otp'])
            ekey += ':t' + (_pfmt % tbk['t'])
        ekey += ':c' + hashlib.sha256(ekey.encode()).hexdigest()[-8:]
        return ekey

    def serialize(self):
        return self.serialize_privkey()

    @staticmethod
    def deserialize(ikey):
        # verify checksum
        inp = ikey.split(':c')
        if len(inp) != 2:
            return None
        ckck = hashlib.sha256(inp[0].encode()).hexdigest()[-8:]
        if ckck != inp[1]:
            return None
        # verify keys
        inp = inp[0].split(':')
        if len(inp) < 7:
            return None
        if ((inp[0][:1] != 'p') or (inp[1][:1] != 'k') or
                (inp[2][:1] != 'm') or (inp[3][:1] != 'n') or
                (inp[4][:1] != 'z') or (inp[5][:1] != 's') or
                (inp[6][:1] != 'r')):
            return None
        # verify version
        if (inp[0][1:] != '0100'):
            return None
        z = PrivateKey()
        z.p = int(inp[1][1:], 16)
        z.addr['mask'] = int(inp[2][1:], 16)
        z.addr['mtgt'] = int(inp[3][1:], 16)
        z.t0 = int(inp[4][1:], 16)
        z.ts = int(inp[5][1:], 16)
        # time base key(s)
        ntbk = int(inp[6][1:])
        tbk = []
        for i in range(ntbk):
            key = {}
            key['otp'] = int(inp[7+(2*i)][1:], 16)
            key['t'] = int(inp[8+(2*i)][1:], 16)
            tbk.append(key)
        z.tbk = tbk
        z.calc_public_key()
        z.initialized = True
        return z

    def __str__(self):
        return self.serialize()
    
    def __repr__(self):
        return 'PrivateKey.deserialize(' + self.serialize() + ')'

