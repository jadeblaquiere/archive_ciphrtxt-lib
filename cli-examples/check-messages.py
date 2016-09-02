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

from ciphrtxt.message import Message
from ciphrtxt.keys import PrivateKey
from ciphrtxt.network import MsgStore, CTClient
from argparse import ArgumentParser
import time
import dateutil.parser as duparser
import sys

parser = ArgumentParser(description='check server for messages, output list of message ID to recipient')
parser.add_argument('recipient', help='recipient private key')
parser.add_argument('--host', default='ciphrtxt.com', help='hostname or IP address of server')
parser.add_argument('--port', default=7754, help='specify server port (default = 7754)')
#parser.add_argument('--since', default=None, help='only look for messages posted after date/time (default = forever)')
clargs = parser.parse_args()

#since = None

#if clargs.since is not None:
#    try:
#        since = int(duparser.parse(clargs.since).timestamp())
#    except:
#        print('Error: Invalid datetime string: ' + clargs.since, file=sys.stderr)
#        exit()

k = PrivateKey.deserialize(clargs.recipient)
if k is None:
    print('Error: Invalid recipient private key', file=sys.stderr)
    exit()

with CTClient() as c:
    ms = MsgStore(str(clargs.host), int(clargs.port))
    reachable = ms.refresh()
    if not reachable:
        print('Error: host unreachable', file=sys.stderr)
        exit()
    
    hdrs = ms.get_headers()
    
    for hdr in hdrs:
        if hdr.is_for(k):
            t = time.localtime(hdr.time)
            print(time.asctime(t) + ' ' + hdr.I.compress().decode())
