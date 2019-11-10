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
from Crypto.Util.Padding import pad, unpad

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

	salt=fin.readline()

	txt = fin.readlines() #reads the remaining
	
	if isinstance(txt,list):
		#print(type(txt),len(txt),AES.block_size)
		txt=bytes(txt)

	
	if algoritmo == '3DES':
		if mode=='CBC':
			m=DES3.MODE_CBC
		if mode=='ECB':
			m=DES3.MODE_ECB
		key,salt = keyGen(24,salt)
		cipher = DES3.new(key, m)
		data = unpad(cipher.decrypt(txt), DES3.block_size)

			
	elif algoritmo == 'AES-128':
		if mode=='CBC':
			m=AES.MODE_CBC
		if mode=='GCM':
			m=AES.MODE_GCM
		key,salt = keyGen(16,salt)
		cipher = AES.new(key, m)
		data = unpad(cipher.decrypt(txt), AES.block_size)
		
			
	else:
		print("Algoritmo nao suportado. Aborting..")
		sys.exit(0)	
				
		
	

	fout.write(data)
	
	fin.close()
	fout.close()
	return 0



def encrypt(algoritmo, mode, filename):
	#padder = padding.PKCS7(128).padder()
	
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
		text=pad(txt,DES3.block_size)


			
	elif algoritmo == 'AES-128':
		if mode=='CBC':
			m=AES.MODE_CBC
		if mode=='GCM':
			m=AES.MODE_GCM
		key,salt = keyGen(16)
		cipher = AES.new(key, m)
		text=pad(txt,AES.block_size)
			
	else:
		print("Algoritmo nao suportado. Aborting..")
		sys.exit(0)
	

	# Store the salt somewhere in the file
	#header = {'salt':salt}
	#h=json.dumps(header)
	fout.write(salt)
				
		
	#enc = padder.update(txt)
	fout.write(cipher.encrypt(text))
	
	fin.close()
	fout.close()
	return 0


filename="ola.txt"
encrypt('AES-128','CBC',filename)
decrypt('AES-128','CBC',"encrypted_" + filename)