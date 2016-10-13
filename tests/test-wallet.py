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

from ciphrtxt.wallet import WalletPubkey, WalletPrivkey

alice = WalletPrivkey()
alice.randomize()

print()
print('ciphrtxt-indigo network : ')
print()

print('Alice key hex value = %64x' % alice.p)
print('Alice key point (compressed) = ' + alice.P.compress().decode())
print('Alice key point = ' + alice.P.uncompressed_format().decode())
print('Alice privkey (WIF) = ' + alice.serialize_privkey().decode())
print('Alice pubkey (WIF) = ' + alice.serialize_pubkey().decode())
print('Alice privkey (WIF), "compressed" = ' + alice.serialize_privkey_compressed().decode())
print('Alice pubkey (WIF), "compressed" = ' + alice.serialize_pubkey_compressed().decode())

exp = alice.serialize_privkey()
exP = alice.serialize_pubkey()

apriv = WalletPrivkey.deserialize(exp)

print()
print('ciphrtxt-red (test) network : ')
print()

WalletPubkey.set_network('ct-red')

bob = WalletPrivkey()
bob.randomize()

print('Bob key hex value = %64x' % bob.p)
print('Bob key point (compressed) = ' + bob.P.compress().decode())
print('Bob key point = ' + bob.P.uncompressed_format().decode())
print('Bob privkey (WIF) = ' + bob.serialize_privkey().decode())
print('Bob pubkey (WIF) = ' + bob.serialize_pubkey().decode())
print('Bob privkey (WIF), "compressed" = ' + bob.serialize_privkey_compressed().decode())
print('Bob pubkey (WIF), "compressed" = ' + bob.serialize_pubkey_compressed().decode())

exp = bob.serialize_privkey()
exP = bob.serialize_pubkey()

bpriv = WalletPrivkey.deserialize(exp)
