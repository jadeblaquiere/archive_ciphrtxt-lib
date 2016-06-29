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

from ecpy.point import Point, Generator
import ecpy.curves as curves
from Crypto.Random import random
from Crypto.Hash import RIPEMD
from hashlib import sha256
import hashlib
from binascii import hexlify, unhexlify
from base58 import b58encode, b58decode

# set up elliptic curve environment
_C = curves.curve_secp256k1
Point.set_curve(_C)
_G = Generator.init(_C['G'][0], _C['G'][1])

_network_id = {
    'ct-indigo': { 'pub': b'1c', 'priv': b'bb' },
    'ct-red': { 'pub': b'50', 'priv': b'a3' },
    'bt-main': { 'pub': b'00', 'priv': b'80' },
    'bt-test': { 'pub': b'6f', 'priv': b'ef' },
    'bt-simtest': { 'pub': b'3f', 'priv': b'64' },
}

_pfmt = b'%%0%dx' % (((_C['bits'] + 7) >> 3) << 1)
_default_network = _network_id['ct-indigo']


class WalletPubkey (object):
    network = _default_network

    def __init__(self, point=None):
        self.P = point

    @classmethod
    def set_network(cls, name="ct-indigo"):
        if name not in _network_id:
            raise Value
        cls.network = _network_id['name']

    def serialize_pubkey(self):
        if self.P is None:
            return None
        # generate V1 Address format
        # see: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
        # hash key - sha256 then ripemd160
        aff = self.P.affine()
        long_pt = b'04' + (_pfmt % aff[0]) + (_pfmt % aff[1])
        h = RIPEMD.new(sha256(unhexlify(long_pt)).digest())
        # add header prefix
        h_hashkey = WalletPubkey.network['pub'] + hexlify(h.digest()).decode('utf-8')
        # calc checksum
        cksum = sha256(sha256(unhexlify(h_hashkey)).digest()).hexdigest()[:8]
        # encode base58
        return b58encode(unhexlify(h_hashkey + cksum)).encode()

    def serialize_pubkey_compressed(self):
        if self.P is None:
            return None
        # generate V1 Address format
        # see: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
        # hash key - sha256 then ripemd160
        h = RIPEMD.new(sha256(unhexlify(self.P.compress())).digest())
        # add header prefix
        h_hashkey = WalletPubkey.network['pub'] + hexlify(h.digest()).decode('utf-8')
        # calc checksum
        cksum = sha256(sha256(unhexlify(h_hashkey)).digest()).hexdigest()[:8]
        # encode base58
        return b58encode(unhexlify(h_hashkey + cksum)).encode()

    def serialize(self):
        return self.serialize_pubkey()

    def serialize_compressed(self):
        return self.serialize_pubkey_compressed()


class WalletPrivkey(WalletPubkey):
    def __init__(self, value=None):
        self.p = value
        if value is None:
            self.P = None
        else:
            self.P = _G * p

    def serialize_privkey(self):
        if self.p is None:
            return None
        # generate WIF format
        # see: https://en.bitcoin.it/wiki/Wallet_import_format
        # add header prefix
        h_key = WalletPrivkey.network['priv'] + (_pfmt % self.p)
        # calc checksum
        cksum = sha256(sha256(unhexlify(h_key)).digest()).hexdigest()[:8]
        # encode base58
        return b58encode(unhexlify(h_key + cksum)).encode()

    def serialize_privkey_compressed(self):
        if self.p is None:
            return None
        # generate WIF format
        # see: https://en.bitcoin.it/wiki/Wallet_import_format
        # add header prefix
        h_key = WalletPrivkey.network['priv'] + (_pfmt % self.p) + b'01'
        # calc checksum
        cksum = sha256(sha256(unhexlify(h_key)).digest()).hexdigest()[:8]
        # encode base58
        return b58encode(unhexlify(h_key + cksum)).encode()

    def serialize(self):
        return self.serialize_privkey()

    def serialize_compressed(self):
        return self.serialize_privkey_compressed()

    @staticmethod
    def deserialize(keyb58):
        return WalletPrivkey.deserialize_privkey(keyb58)

    @staticmethod
    def deserialize_privkey(keyb58):
        raw = hexlify(b58decode(keyb58.decode()))
        h_key = raw[:66]
        cksum = sha256(sha256(unhexlify(h_key)).digest()).hexdigest()[:8]
        if cksum != raw[66:].decode('utf-8'):
            #raise ValueError('checksum mismatch')
            return None
        return h_key[2:].decode('utf-8')

    @staticmethod
    def deserialize_privkey_compressed(keyb58):
        raw = hexlify(b58decode(keyb58.decode()))
        h_key = raw[:68]
        cksum = sha256(sha256(unhexlify(h_key)).digest()).hexdigest()[:8]
        if raw[66:68].decode('utf-8') != '01':
            raise ValueError('format error')
        if cksum != raw[68:].decode('utf-8'):
            raise ValueError('checksum mismatch')
        return h_key[2:66].decode('utf-8')
    
    def randomize(self):
        self.p = random.randint(2, _C['n']-1)
        self.P = _G * self.p
