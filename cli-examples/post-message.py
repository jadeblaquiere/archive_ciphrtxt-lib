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
from ciphrtxt.network import MsgStore, CTClient
from argparse import ArgumentParser
import sys

parser = ArgumentParser(description='post encoded message read from stdin to server')
parser.add_argument('--host', default='ciphrtxt.com', help='hostname or IP address of server (default ciphrtxt.com)')
parser.add_argument('--port', default=7754, help='specify server port (default = 7754)')
clargs = parser.parse_args()

with CTClient() as c:
    mtxt = sys.stdin.read()

    msg = Message.deserialize(mtxt)
    if msg is None:
        print('Error: Message format invalid', file=sys.stderr)
        exit()

    ms = MsgStore(str(clargs.host), int(clargs.port))
    reachable = ms.refresh()
    if not reachable:
        print('Error: host unreachable', file=sys.stderr)
        exit()

    metadata = ms.post_message(msg)
    if metadata is None:
        print('Error: upload failed', file=sys.stderr)
        exit()
    
    print("message ID " + str(msg.Iraw()) + " posted to " + clargs.host)
