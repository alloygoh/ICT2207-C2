from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.Signature import pss
from Crypto.PublicKey import RSA

# key needs to be in pem format
KEY_PATH = './key.pem'

def decrypt(ciphertext,key):
	cipher = PKCS1_OAEP.new(key=key, hashAlgo=SHA1, mgfunc=lambda x,y: pss.MGF1(x,y, SHA1))
	cipher.decrypt(ciphertext)

def read_key(path):
	with open(path,'r') as f:
		data = f.read()
	return RSA.importKey(data)
