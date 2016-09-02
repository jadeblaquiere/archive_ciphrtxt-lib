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

import time
import json
import hashlib
import mimetypes
from binascii import hexlify, unhexlify
import base64
from ciphrtxt.message import Message, MessageHeader
from tornado.httpclient import AsyncHTTPClient, HTTPClient, HTTPRequest

from ecpy.curves import curve_secp256k1
from ecpy.point import Point, Generator
from ecpy.ecdsa import ECDSA
from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.Util import Counter

from threading import Lock

_C = curve_secp256k1
Point.set_curve(_C)

Generator.set_curve(_C)
_G = Generator.init(_C['G'][0], _C['G'][1])

ECDSA.set_generator(_G)
_ecdsa = ECDSA()

_statusPath = 'api/status/'

_server_time = 'api/time/'
_headers_since = 'api/header/list/since/'
_download_message = 'api/message/download/'
_upload_message = 'api/message/upload/'
_peer_list = 'api/peer/list/'

_cache_expire_time = 5 # seconds
_high_water = 50
_low_water = 20

# NOTE: encode_multipart_formdata and get_content_type copied from public
# domain code posted at : http://code.activestate.com/recipes/146306/


def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be
    uploaded as files.
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        # print ('encoding ' + key + ' ' + filename + ' ' + str(value))
        filename = filename.encode("utf8")
        L.append('--' + BOUNDARY)
        L.append(
            'Content-Disposition: form-data; name="%s"; filename="%s"' % (
                key, filename
            )
        )
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body


def get_content_type(filename):
    # return mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    return 'application/octet-stream'


class CTClient (object):
    _aclient = None
    _sclient = None
    def __init__(self):
        pass

    def __enter__(self):
        CTClient._aclient = AsyncHTTPClient(max_clients=100)
        CTClient._sclient = HTTPClient()

    def __exit__(self, exc_type, exc_value, traceback):
        CTClient._aclient.close()
        CTClient._aclient = None
        CTClient._sclient.close()
        CTClient._sclient = None


class OnionHost(object):
    def __init__(self, host, port=7754, Pkey=None):
        self.host = host
        self.port = port
        self.Pkey = Pkey
    
    def _baseurl(self):
        return 'http://' + self.host + ':' + str(self.port) + '/'

    def refresh(self):
        req = HTTPRequest(self._baseurl() + _statusPath, method='GET')
        r = CTClient._sclient.fetch(req)
        if r.code != 200:
            return False
        pub = json.loads(r.body.decode('UTF-8'))['pubkey']
        self.Pkey = Point.decompress(pub.encode('UTF-8'))
        return True
    
    def __str__(self):
        return 'CT Onion host @ ' + self._baseurl() + ' key = ' + self.Pkey.compress().decode()
    
    def get(self, path, nak=None, callback=None, headers=None, onions=None):
        if onions is None:
            if nak is not None:
                raise(ValueError, 'Using NAK requires Onions route list is provided')
            return OnionRequest().get(self._baseurl(), path, callback=callback, headers=headers)
        if nak is None:
            raise ValueError('Onion routing requires NAK is provided')
        return OnionRequest().get(self, path, nak=nak, callback=callback, headers=headers, onions=onions)
    
    def post(self, path, body, nak=None, callback=None, headers=None, onions=None):
        if onions is None:
            if nak is not None:
                raise(ValueError, 'Using NAK requires Onions route list is provided')
            return OnionRequest().post(self._baseurl(), path, body, callback=callback, headers=headers)
        if nak is None:
            raise ValueError('Onion routing requires NAK is provided')
        return OnionRequest().post(self, path, body, nak=nak, callback=callback, headers=headers, onions=onions)


class NestedRequest(object):
    def __init__(self):
        self.callback = None
        self.callback_next = None
        
    def _callback(self, resp):
        return self.callback(resp, self.callback_next)
    
    def get(self, ohost, path, callback, callback_next, headers=None, nak=None, onions=None):
        self.callback = callback
        self.callback_next = callback_next
        if onions is None:
            if nak is not None:
                raise(ValueError, 'Using NAK requires Onions route list is provided')
            return OnionRequest().get(ohost._baseurl(), path, nak=nak, callback=self._callback, headers=headers, onions=onions)
        if nak is None:
            raise ValueError('Onion routing requires NAK is provided')
        return OnionRequest().get(ohost, path, nak=nak, callback=self._callback, headers=headers, onions=onions)
        
    
    def post(self, ohost, path, body, callback, callback_next, headers=None, nak=None, onions=None):
        self.callback = callback
        self.callback_next = callback_next
        if onions is None:
            if nak is not None:
                raise(ValueError, 'Using NAK requires Onions route list is provided')
            return OnionRequest().post(ohost._baseurl(), path, body, nak=nak, callback=self._callback, headers=headers, onions=onions)
        if nak is None:
            raise ValueError('Onion routing requires NAK is provided')
        return OnionRequest().post(ohost, path, body, nak=nak, callback=self._callback, headers=headers, onions=onions)


class OnionRequest(object):
    def __init__(self):
        self.callback = None
        self.reply_pkey = None
        self.reply_Pkey = None
        self.reply_ohost = None
 
    def _format_get(self, path, headers):
        self.reply_pkey = random.randint(1,_C['n']-1)
        self.reply_Pkey = _G * self.reply_pkey
        r = {}
        r['local'] = True
        r['url'] = path
        r['action'] = 'GET'
        r['headers'] = headers
        r['replykey'] = self.reply_Pkey.compress().decode()
        return r
    
    def _format_post(self, path, body, headers):
        self.reply_pkey = random.randint(1,_C['n']-1)
        self.reply_Pkey = _G * self.reply_pkey
        r = {}
        r['local'] = True
        r['url'] = path
        r['action'] = 'POST'
        r['headers'] = headers
        r['body'] = str(body)
        r['replykey'] = self.reply_Pkey.compress().decode()
        return r

    def _wrap(self, onion, req):
        if not req['local']:
            req['body'] = base64.b64encode(req['body']).decode()
        session_pkey = random.randint(1,_C['n']-1)
        session_Pkey = _G * session_pkey
        if onion.Pkey is None:
            if not onion.refresh():
                return None
        ECDH = onion.Pkey * session_pkey
        keybin = hashlib.sha256(ECDH.compress()).digest()
        iv = random.randint(0,(1 << 128)-1)
        ivbin = unhexlify('%032x' % iv)
        counter = Counter.new(128, initial_value=iv)
        cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
        # print('req = ' + str(req))
        # print('req type = ' + str(type(req)))
        ciphertext = cryptor.encrypt(json.dumps(req))
        r = {}
        r['local'] = False
        r['host'] = onion.host
        r['port'] = onion.port
        r['pubkey'] = session_Pkey.compress().decode()
        r['body'] = ivbin+ciphertext
        return r

    def _decrypt_reply(self, ohost, text):
        d_bd = base64.b64decode(text)
        sig = (int(hexlify(d_bd[0:32]),16), int(hexlify(d_bd[32:64]),16))
        if not _ecdsa.verify(ohost.Pkey, sig, d_bd[64:]):
            return None
        d_ecdh = ohost.Pkey * self.reply_pkey
        d_keybin = hashlib.sha256(d_ecdh.compress()).digest()
        d_ivcount = int(hexlify(d_bd[64:80]),16)
        d_counter = Counter.new(128,initial_value=d_ivcount)
        d_cryptor = AES.new(d_keybin, AES.MODE_CTR, counter=d_counter)
        d_plaintext = d_cryptor.decrypt(d_bd[80:])
        return d_plaintext.decode('UTF-8')

    def _nakit(self, nak, request):
        sig = nak.sign(request)
        return unhexlify('%064x' % sig[0]) + unhexlify('%064x' % sig[1])

    def _callback(self, resp):
        self.callback(resp.body)

    def _decrypt_callback(self, resp):
        if self.callback is None:
            raise ValueError('_decrypt_callback called with no chain callback')
        d_resp = self._decrypt_reply(self.reply_ohost, resp.body)
        self.callback(d_resp)

    def _issue(self, ohost, path, body=None, rtype='GET', nak=None, callback=None, onions=None, headers=None):
        if isinstance(ohost, OnionHost):
            if nak is None:
                raise ValueError('Onion routing requires network access key')
            if rtype.lower() == 'get':
                inner = self._format_get(path, headers)
            else:
                inner = self._format_post(path, body, headers)
            outer = self._wrap(ohost, inner)
            if outer is None:
                print('wrap failed for host' + str(ohost))
                return None
            for o in reversed(onions):
                inner = outer
                outer = self._wrap(o,inner)
                if outer is None:
                    print('wrap failed for host' + str(ohost))
                    return None
            naksig = self._nakit(nak, outer['body'])
            body = nak.pubkeybin() + naksig + outer['body']
            body = base64.b64encode(body).decode()
            url = 'http://' + outer['host'] + ':' + str(outer['port']) + '/onion/' + outer['pubkey']
            req = HTTPRequest(url, method='POST', body=body, headers=headers)
            if callback is None:
                r = CTClient._sclient.fetch(req)
                if r.code != 200:
                    return None
                return self._decrypt_reply(ohost,r.body)
            else:
                self.callback = callback
                self.reply_ohost = ohost
                return CTClient._aclient.fetch(req, self._decrypt_callback)
        
        else:
            if onions is not None:
                print('ohost type = ' + str(type(ohost)))
                raise ValueError('Cannot onion route to non-onion target')
            url = ohost + path
            if rtype.lower() == 'get':
                # print('sending GET to ' + url)
                req = HTTPRequest(url, method='GET', headers=headers)
                if callback is None:
                    r = CTClient._sclient.fetch(req)
                    if r.code != 200:
                        return None
                    # print('return 200')
                    return r.body
                else:
                    self.callback = callback
                    # print('url = ' + url + ', callback = ' + str(callback))
                    return CTClient._aclient.fetch(req, callback=self._callback)
            else:
                # print('sending POST to ' + url)
                req = HTTPRequest(url, method='POST', body=body, headers=headers)
                if callback is None:
                    r = CTClient._sclient.fetch(req)
                    if r.code != 200:
                        return None
                    # print('return 200')
                    return r.body
                else:
                    self.callback = callback
                    return CTClient._aclient.fetch(req, self._callback)
        
    
    def get(self, ohost, path, nak=None, callback=None, onions=None, headers=None):
        return self._issue(ohost, path, rtype='GET', nak=nak, callback=callback, onions=onions, headers=headers)

    def post(self, ohost, path, body, nak=None, callback=None, onions=None, headers=None):
        return self._issue(ohost, path, body=body, rtype='POST', nak=nak, callback=callback, onions=onions, headers=headers)


class MsgStore (OnionHost):
    """Client library for message store server"""
    def __init__(self, host, port):
        super(MsgStore, self).__init__(host, port)
        self.headers = []
        self.cache_dirty = True
        self.last_sync = time.time()
        self.servertime = 0
        self._get_queue = []
        self._post_queue = []
        self._insert_lock = Lock()
        self._gq_lock = Lock()
        self.reply_log = []

    def _sync_headers(self, onions=None):
        if self.Pkey is None:
            self.refresh()
        now = time.time()
        if not self.cache_dirty:
            delay = now - self.last_sync
            if (now - self.last_sync) < _cache_expire_time:
                return True
        r = self.get(_server_time)
        if r is None:
            return False
        servertime = json.loads(r.decode())['time']
        for h in self.headers:
            if servertime > h.expire:
                self._insert_lock.acquire()
                # print('expiring ' + h.I.compress().decode())
                self.headers.remove(h)
                self._insert_lock.release()
        self.last_sync = time.time()
        r = self.get(_headers_since + str(self.servertime))
        if r is None:
            return False
        self.servertime = servertime
        self.cache_dirty = False
        remote = sorted(json.loads(r.decode())['header_list'],
                        key=lambda k: int(k[6:14],16), reverse=True)
        for rstr in reversed(remote):
            rhdr = MessageHeader()
            if rhdr._deserialize_header(rstr.encode()):
                self._insert_lock.acquire()
                if rhdr not in self.headers:
                    self.headers.insert(0, rhdr)
                self._insert_lock.release()
        self._insert_lock.acquire()
        self.headers.sort(reverse=True)
        self._insert_lock.release()
        return True
    
    def get_headers(self):
        self._sync_headers()
        return self.headers
    
    def get_peers(self):
        if self.Pkey is None:
            self.refresh()
        r = self.get(_peer_list)
        if r is None:
            return None
        return json.loads(r.decode())

    def _cb_get_message(self, resp, callback_next):
        self.reply_log.append((resp, callback_next))
        if resp is None:
            return callback_next(None)
        m = Message.deserialize(resp)
        return callback_next(m)

    def get_message(self, hdr, callback=None, nak=None, onions=None):
        self._sync_headers()
        if hdr not in self.headers:
            return None
        if callback is None:
            r = self.get(_download_message + hdr.I.compress().decode(), nak=nak, onions=onions)
            if r is None:
                return None
            return Message.deserialize(r)
        else:
            # print('submitting NestedRequest for ' + self._baseurl() + _download_message + hdr.I.compress().decode() + ' with callback ' + str(callback))
            return NestedRequest().get(self, _download_message + hdr.I.compress().decode(), callback=self._cb_get_message, callback_next=callback, nak=nak, onions=onions)
            #r = self.get(_download_message + hdr.I.compress().decode())
            #return self._cb_get_message(r, callback)
    
    def get_message_by_id(self, msgid, callback=None, nak=None, onions=None):
        if isinstance(msgid, bytes):
            msgid = msgid.decode()
        if callback is None:
            r = self.get(_download_message + msgid, nak=None, onions=None)
            if r is None:
                return None
            return Message.deserialize(r)
        else:
            # print('submitting NestedRequest for ' + self._baseurl() + _download_message + hdr.I.compress().decode() + ' with callback ' + str(callback))
            return NestedRequest().get(self, _download_message + msgid, callback=self._cb_get_message, callback_next=callback, nak=nak, onions=onions)
            #r = self.get(_download_message + hdr.I.compress().decode())
            #return self._cb_get_message(r, callback)
    
    def post_message(self, msg, callback=None, nak=None, onions=None):
        if msg in self.headers:
            return
        raw = msg.serialize()
        nhdr = MessageHeader.deserialize(raw)
        fields = []
        files = [('message', 'message', raw.decode())]
        content_type, body = encode_multipart_formdata(fields, files)
        headers = {"Content-Type": content_type, 'content-length': str(len(body))}
        r = self.post(_upload_message, body, headers=headers, callback=callback, nak=nak, onions=onions)
        if r is None:
            return None
        self._insert_lock.acquire()
        if nhdr not in self.headers:
            self.headers.insert(0,nhdr)
        self._insert_lock.release()
        self.cache_dirty = True
        return r


class Network (object):
    pass
