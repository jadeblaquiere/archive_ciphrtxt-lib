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

from ciphrtxt.network import MsgStore, CTClient
from ciphrtxt.keys import PrivateKey, PublicKey
from ciphrtxt.message import Message, MessageHeader
from ciphrtxt.nak import NAK
import random
import time
import tornado.ioloop
import tornado.gen

mlist = []
slist = []

nakpriv=int('4b13b7e5f7caf9627b0eefeaa3ee3523a764a8abccdb4e63908454cd01a724a0',16)
nak = NAK(privkey=nakpriv)

@tornado.gen.coroutine
def print_message(m):
    mlist.append(m)

@tornado.gen.coroutine
def register_message(r):
    slist.append(r)

m = MsgStore('violet.ciphrtxt.com', 7754)  
m2 = MsgStore('indigo.bounceme.net', 7754)  
    
@tornado.gen.coroutine
def run_test1():
    with CTClient() as c:
        # syncronous calls
        m.refresh()
        print('MsgStore opened as ' + str(m))
        print()
        hdrs = m.get_headers()
        print('MsgStore all headers : ' + str(hdrs))
        print()
        peers = m.get_peers()
        print('MsgStore found ' + str(len(peers)) + ' peers : ')
        for p in peers:
            print('    ' + str(p))
        print()
        for i in range(0,5):
            h = random.choice(hdrs)
            msg = m.get_message(h)
            print('random message retreived as ' + msg.serialize().decode())
            msg_test = m.get_message_by_id(h.Iraw())
            assert msg == msg_test
            #print('random message retreived as ' + msg_test.serialize().decode())
            print()
        Apriv = PrivateKey()
        Apriv.randomize(4)
        Apub = PublicKey.deserialize(Apriv.serialize_pubkey())
        Bpriv = PrivateKey()
        Bpriv.randomize(4)
        Bpub = PublicKey.deserialize(Apriv.serialize_pubkey())
        mtxt = 'the quick brown fox jumped over the lazy dog'
        msg = Message.encode(mtxt, Bpub, Apriv)
        r = m.post_message(msg)
        print('message posted, server metadata' + str(r))
        print()

@tornado.gen.coroutine
def run_test2():
    with CTClient() as c:
        # syncronous call
        m.refresh()
        print('MsgStore opened as ' + str(m))
        print()
        hdrs = m.get_headers()
        # asynchronous calls
        mlist = []
        for i in range(0,5):
            h = random.choice(hdrs)
            r = yield m.get_message(h, callback=print_message)
            print('sent request for header ' + h.serialize().decode())
            print()

def run_test3():
    print('messages')
    for msg in mlist:
        print('msg received = ' + msg.serialize().decode())
    print('... that is all')
    print()

@tornado.gen.coroutine
def run_test4():
    with CTClient() as c:
        # syncronous call
        m.refresh()
        print('MsgStore opened as ' + str(m))
        print()
        Apriv = PrivateKey()
        Apriv.randomize(4)
        Apub = PublicKey.deserialize(Apriv.serialize_pubkey())
        Bpriv = PrivateKey()
        Bpriv.randomize(4)
        Bpub = PublicKey.deserialize(Apriv.serialize_pubkey())
        # asynchronous calls
        mtxt = 'the quick brown fox jumped over the lazy dog'
        msgs = []
        print('Encoding messages ')
        print()
        for i in range(0,5):
            msg = Message.encode(mtxt, Bpub, Apriv)
            msgs.append(msg)
        print('Posting messages')
        print()
        slist = []
        for msg in msgs:
            h = MessageHeader.deserialize(msg._serialize_header())
            r = yield m.post_message(msg, callback=register_message)
            print('sent async post for ' + h.serialize().decode())
            print()
            mtxt += 'the quick brown fox jumped over the lazy dog'

def run_test5():
    print('sent')
    for s in slist:
        print('sent metadata = ' + str(s))
    print('... that is all')
    print()

@tornado.gen.coroutine
def run_test6():
    with CTClient() as c:
        # synchronous onion get
        m.refresh()
        peers = m.get_peers()
        hdrs = m.get_headers()
        onions = []
        for p in peers:
            onion = MsgStore(p['host'], p['port'])
            onion.refresh()
            if onion.Pkey is not None:
                onions.append(onion)
        nonion = len(onions)
        print('found ' + str(nonion) + ' onion hosts')
        for o in onions:
            print('    ' + str(o))
            onion._sync_headers()
        for i in range (0,5):
            h = random.choice(hdrs)
            orand = random.sample(onions, min(nonion-1,3))
            print('fetching from onions')
            for o in orand:
                print('    ' + str(o))
            print()
            msg = orand[0].get_message(h, nak=nak, onions=orand[1:])
            # msg = m.get_message(h, nak=nak, onions=[m, m2])
            # msg = m2.get_message(h, nak=nak, onions=[m2, m])
            print(msg.serialize().decode())
        
@tornado.gen.coroutine
def run_test7():
    with CTClient() as c:
        # synchronous onion post
        m.refresh()
        m2.refresh()
        peers = m.get_peers()
        hdrs = m.get_headers()
        onions = []
        for p in peers:
            onion = MsgStore(p['host'], p['port'])
            onion.refresh()
            if onion.Pkey is not None:
                onions.append(onion)
        nonion = len(onions)
        print('found ' + str(nonion) + ' onion hosts')
        for o in onions:
            print('    ' + str(o))
            onion._sync_headers()
        Apriv = PrivateKey()
        Apriv.randomize(4)
        Apub = PublicKey.deserialize(Apriv.serialize_pubkey())
        Bpriv = PrivateKey()
        Bpriv.randomize(4)
        Bpub = PublicKey.deserialize(Apriv.serialize_pubkey())
        mtxt = 'the quick brown fox jumped over the lazy dog'
        msgs = []
        print('Encoding messages ')
        print()
        for i in range(0,5):
            msg = Message.encode(mtxt, Bpub, Apriv)
            msgs.append(msg)
        for msg in msgs:
            orand = random.sample(onions, min(nonion-1,3))
            print('posting via onions')
            for o in orand:
                print('    ' + str(o))
            print()
            conf = orand[0].post_message(msg, nak=nak, onions=orand[1:])
            # conf = m.post_message(msg, nak=nak, onions=[m, m2])
            # conf = m2.post_message(msg, nak=nak, onions=[m2])
            print(conf)
        
@tornado.gen.coroutine
def run_test8():
    with CTClient() as c:
        # syncronous call
        m.refresh()
        print('MsgStore opened as ' + str(m))
        print()
        peers = m.get_peers()
        hdrs = m.get_headers()
        onions = []
        for p in peers:
            onion = MsgStore(p['host'], p['port'])
            onion.refresh()
            if onion.Pkey is not None:
                onions.append(onion)
        nonion = len(onions)
        print('found ' + str(nonion) + ' onion hosts')
        for o in onions:
            print('    ' + str(o))
            onion._sync_headers()
        # asynchronous calls
        mlist = []
        for i in range (0,5):
            h = random.choice(hdrs)
            orand = random.sample(onions, min(nonion-1,3))
            print('fetching from onions')
            for o in orand:
                print('    ' + str(o))
            print()
            r = yield orand[0].get_message(h, nak=nak, onions=orand[1:], callback=print_message)
            print('sent request for header ' + h.serialize().decode())
            print()# msg = m.get_message(h, nak=nak, onions=[m, m2])

def run_test9():
    print('messages')
    for msg in mlist:
        print('msg received = ' + msg.serialize().decode())
    print('... that is all')
    print()


@tornado.gen.coroutine
def run_test10():
    with CTClient() as c:
        # synchronous onion post
        m.refresh()
        m2.refresh()
        peers = m.get_peers()
        hdrs = m.get_headers()
        onions = []
        for p in peers:
            onion = MsgStore(p['host'], p['port'])
            onion.refresh()
            if onion.Pkey is not None:
                onions.append(onion)
        nonion = len(onions)
        print('found ' + str(nonion) + ' onion hosts')
        for o in onions:
            print('    ' + str(o))
            onion._sync_headers()
        Apriv = PrivateKey()
        Apriv.randomize(4)
        Apub = PublicKey.deserialize(Apriv.serialize_pubkey())
        Bpriv = PrivateKey()
        Bpriv.randomize(4)
        Bpub = PublicKey.deserialize(Apriv.serialize_pubkey())
        # asynchronous calls
        mtxt = 'the quick brown fox jumped over the lazy dog'
        msgs = []
        print('Encoding messages ')
        print()
        for i in range(0,5):
            msg = Message.encode(mtxt, Bpub, Apriv)
            msgs.append(msg)
        for msg in msgs:
            h = MessageHeader.deserialize(msg._serialize_header())
            orand = random.sample(onions, min(nonion-1,3))
            print('posting via onions')
            for o in orand:
                print('    ' + str(o))
            print()
            r = yield orand[0].post_message(msg, nak=nak, onions=orand[1:], callback=register_message)
            # conf = m.post_message(msg, nak=nak, onions=[m, m2])
            # conf = m2.post_message(msg, nak=nak, onions=[m2])
            print('sent post for header ' + h.serialize().decode())
            print()# msg = m.get_message(h, nak=nak, onions=[m, m2])
        
def run_test11():
    print('sent')
    for s in slist:
        print('sent metadata = ' + str(s))
    print('... that is all')
    print()

tornado.ioloop.IOLoop.current().run_sync(run_test1)

tornado.ioloop.IOLoop.current().run_sync(run_test2)

run_test3()

tornado.ioloop.IOLoop.current().run_sync(run_test4)

run_test5()

tornado.ioloop.IOLoop.current().run_sync(run_test6)

tornado.ioloop.IOLoop.current().run_sync(run_test7)

tornado.ioloop.IOLoop.current().run_sync(run_test8)

run_test9()

tornado.ioloop.IOLoop.current().run_sync(run_test10)

run_test11()
