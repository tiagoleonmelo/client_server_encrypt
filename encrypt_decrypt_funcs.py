import os
import sys
from getpass import getpass
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from Crypto.Hash import SHA256, SHA512

def keyGen(size, salt=None):
	pwd = getpass("Password?")
	pwd = pwd.encode()
	backend = default_backend()
	
	# Salts should be randomly generated
	if salt==None:
		#salt = os.urandom(16)
		salt=b'10'
	# derive
	
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=size, salt=salt, iterations=100000, backend=backend)
	key = kdf.derive(pwd)
	return key


def decrypt(algoritmo, mode, data, iv):

	# fin = open(filename, "rb")
	# output_file = "decrypted_" + filename
	# fout = open(output_file, "wb")

	txt = data
	
	if isinstance(txt,list):
		print(type(txt),len(txt),AES.block_size)
		txt=bytes(txt)

	
	if algoritmo == '3DES':
		key= keyGen(24)
		if mode=='CBC':
			m=DES3.MODE_CBC
			cipher = DES3.new(key, m,iv)
		if mode=='ECB':
			m=DES3.MODE_ECB
			cipher = DES3.new(key, m)
		data = unpad(cipher.decrypt(txt), DES3.block_size)

			
	elif algoritmo == 'AES-128':
		if mode=='CBC':
			m=AES.MODE_CBC
		if mode=='GCM':
			m=AES.MODE_GCM
		key=keyGen(16)
		cipher = AES.new(key, m, iv)
		data = unpad(cipher.decrypt(txt), AES.block_size)
		
			
	else:
		print("Algoritmo nao suportado. Aborting..")
		sys.exit(0)	
				
		
	

	# fout.write(data)
	
	# fin.close()
	# fout.close()
	return data


def encrypt(algoritmo, mode, data):
	
	# fin = open(filename, "rb")
	# output_file = "encrypted_" + filename
	# fout = open(output_file, "wb")
	txt = data

	iv=0

	if algoritmo == '3DES':
		key= keyGen(24)
		iv = get_random_bytes(8)
		if mode=='CBC':
			m=DES3.MODE_CBC
			cipher = DES3.new(key, m,iv)
		if mode=='ECB':
			m=DES3.MODE_ECB
			cipher = DES3.new(key, m)
		text= pad(txt,DES3.block_size)


			
	elif algoritmo == 'AES-128':
		iv = get_random_bytes(16)
		if mode=='CBC':
			m=AES.MODE_CBC
		if mode=='GCM':
			m=AES.MODE_GCM
		key= keyGen(16)
		cipher = AES.new(key, m, iv)
		text=pad(txt,AES.block_size)


	
	else:
		print("Algoritmo nao suportado. Aborting..")
		sys.exit(0)
	

	# Store the salt somewhere in the file
	#header = {'salt':salt}
	#h=json.dumps(header)
	#fout.write(salt+"\n")


	# fout.write(cipher.encrypt(text))
	encrypted = cipher.encrypt(text)
	
	# fin.close()
	# fout.close()
	
	return encrypted, iv


def sintese(algoritmo, data):

	if algoritmo == "SHA-256":
		h = SHA256.new(data)

	elif algoritmo == "SHA-512":
		h = SHA512.new(data)

	else:
		print("ERROR: Unsupported algorithm")
		sys.exit(0)

	return h.hexdigest()