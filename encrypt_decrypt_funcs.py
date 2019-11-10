import os
import sys
from getpass import getpass
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import ChaCha20

def keyGen(size, salt=None):
	pwd = getpass("Password?")
	pwd = pwd.encode()
	backend = default_backend()
	
	# Salts should be randomly generated
	if salt==None:
		salt = os.urandom(16)
	# derive
	
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=size, salt=salt, iterations=100000, backend=backend)
	key = kdf.derive(pwd)
	return key,salt
	
def decrypt(algoritmo, mode, filename):

	fin = open(filename, "rb")
	output_file = "decrypted_" + filename
	fout = open(output_file, "wb")

	jsonSalt=fin.readline()
	print(jsonSalt)#handle TODO

	txt = fin.readlines() #reads the remaining

	
	if algoritmo == '3DES':
		if mode=='CBC':
			m=DES3.MODE_CBC
		if mode=='ECB':
			m=DES3.MODE_ECB
		key,salt = keyGen(24,jsonSalt)
		cipher = DES3.new(key, m)

			
	elif algoritmo == 'AES-128':
		if mode=='CBC':
			m=AES.MODE_CBC
		if mode=='GCM':
			m=AES.MODE_GCM
		key,salt = keyGen(16,jsonSalt)
		cipher = AES.new(key, m)
		
			
	else:
		print("Algoritmo nao suportado. Aborting..")
		sys.exit(0)	
				
		
	data = cipher.decrypt(txt)

	fout.write(data)
	
	fin.close()
	fout.close()
	return 0



def encrypt(algoritmo, mode, filename):
	padder = padding.PKCS7(128).padder()
	
	fin = open(filename, "rb")
	output_file = "encrypted_" + filename
	fout = open(output_file, "wb")
	txt = fin.read()

	
	if algoritmo == '3DES':
		if mode=='CBC':
			m=DES3.MODE_CBC
		if mode=='ECB':
			m=DES3.MODE_ECB
		key,salt = keyGen(24)
		cipher = DES3.new(key, m)

		# Store the salt somewhere in the file
		header = {'salt':salt}
		h = json.dumps(header)
		fout.write(h)

			
	elif algoritmo == 'AES-128':
		if mode=='CBC':
			m=AES.MODE_CBC
		if mode=='GCM':
			m=AES.MODE_GCM
		key,salt = keyGen(16)
		cipher = AES.new(key, m)
		
		# Store the salt somewhere in the file
		header = {'salt':salt}
		h = json.dumps(header)
		fout.write(h)
			
	else:
		print("Algoritmo nao suportado. Aborting..")
		sys.exit(0)	
				
		
	enc = padder.update(txt)
	fout.write(cipher.encrypt(enc))
	
	fin.close()
	fout.close()
	return 0
