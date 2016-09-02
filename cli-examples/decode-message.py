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
from ciphrtxt.message import Message
from argparse import ArgumentParser
import sys

parser = ArgumentParser(description='read encoded message from stdin and write message plaintext to stdout')
parser.add_argument('recipient', default='', help='recipient private key (hint: starts with p0100)')
parser.add_argument('--sender', default=None, help='sender public key (optional for signature verification)')
clargs = parser.parse_args()

f_key = None

if clargs.sender:
    f_key = PublicKey.deserialize(clargs.sender)
    if f_key is None:
        print('Error: unable to parse sender key', file=sys.stderr)
        exit()

t_key = PrivateKey.deserialize(clargs.recipient)
if t_key is None:
    print('Error: unable to parse recipient key', file=sys.stderr)
    exit()

ctext = sys.stdin.read()

m = Message.deserialize(ctext)
if not m.decode(t_key):
    print('Error: cannot decrypt message', file=sys.stderr)
    exit()

if f_key is not None:
    if not m.is_from(f_key):
        print('Error: message signature failed', file=sys.stderr)
        exit()

print(m.ptxt)
    
