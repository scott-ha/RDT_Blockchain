#
#

from collections import OrderedDict
import binascii
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


class Transaction(object):

    def __init__(self, sender, sender_key, recipient, amount):
        self.sender = sender
        self.sender_key = sender_key
        self.recipient = recipient
        self.amount = amount
        return

    def __getattr__(self, attr):
        return self.data[attr]

    # not need sender key???
    def makeDict(self):
        return OrderedDict({
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount
        })

    # bug : this is developed in Python 3.5
    # but now version is Python 3.8
    # so in signer.sign(h), there's type error bug here...
    def signTransaction(self):
        private_key = RSA.importKey(binascii.unhexlify(self.sender_key))
        signer = PKCS1_v1_5.new(private_key)
        h_byte = str(self.makeDict()).encode()
        h = SHA.new(h_byte)
        # SHA.new() method
        # h = str(h).encode()
        # print(type(h))
        # <class 'Crypto.Hash.SHA.SHA1Hash'>
        # print(h)
        # <Crypto.Hash.SHA.SHA1Hash object at 0x10aaa4c40>
        # bug in return
        # bug here... TypeError: a bytes-like object is required, not 'str'
        # print('----bug here----')
        # last issue...
        # signer.sign working in 3.7.4
        # not working 3.8.0
        # solution????
        # a = signer.sign(h)
        return binascii.hexlify(signer.sign(h)).decode('ascii')


# EOF
