from Crypto.Cipher import PKCS1_OAEP, ARC4
from Crypto.Hash import SHA1
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from base64 import b64encode as b64e, b64decode as b64d


# key needs to be in pem format
KEY_PATH = './keys/key.pem'

def decrypt(ciphertext):
	key = read_key(KEY_PATH)
	cipher = PKCS1_OAEP.new(key=key, hashAlgo=SHA1, mgfunc=lambda x,y: pss.MGF1(x,y, SHA1))
	return cipher.decrypt(b64d(ciphertext))

def read_key(path):
	with open(path,'r') as f:
		data = f.read()
	return RSA.importKey(data)

def encrypt(plaintext, key):
	if isinstance(plaintext,str):
		plaintext = plaintext.encode()
	cipher = ARC4.new(key)
	return b64e(cipher.encrypt(plaintext))

def rc4_decrypt(ciphertext, key):
	if isinstance(ciphertext, str):
		plaintext = plaintext.encode()
	cipher = ARC4.new(key)
	return cipher.decrypt(b64d(ciphertext))

