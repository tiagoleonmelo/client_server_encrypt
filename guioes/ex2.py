import os
import sys
import getpass
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import ChaCha20

def pwd_alias(size, pwd):
	backend = default_backend()
	
	# Salts should be randomly generated
	salt = b"10"
	# derive
	
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=size, salt=salt, iterations=100000, backend=backend)
	key = kdf.derive(pwd)
	return key
	
def decrypt(filename, outputfile, pwd):
	fin = open(filename, "rb")
	fout = open(outputfile, "wb")

	txt = fin.read()

	key = pwd_alias(24, pwd)
	cipher = DES3.new(key, DES3.MODE_CFB)
	data = cipher.decrypt(txt)

	fout.write(data)



def crypto(algoritmo, filename, pwd):
	padder = padding.PKCS7(128).padder()
	
	fin = open(filename, "rb")
	output_file = "encrypted_" + filename
	fout = open(output_file, "wb")
	txt = fin.read()

	
	if algoritmo == '3DES':
		key = pwd_alias(24, pwd)
		cipher = DES3.new(key, DES3.MODE_CFB)

			
	elif algoritmo == 'AES':
		key = pwd_alias(16, pwd)
		cipher = AES.new(key, AES.MODE_ECB)
		
		# Store the salt somewhere in the file
		# Store the encryption algorithm
		header = {'salt':10, 'alg':'AES'}
		h = json.dumps(header)
		fout.write(h)
			
	elif algoritmo == 'CC20':
		cipher = ChaCha20.new(key=key)
		for l in fin:
			fout.write(cipher.iv + cipher.encrypt(l))
			
	else:
		print("Algoritmo nao suportado. Aborting..")
		sys.exit(0)	
				
		
	enc = padder.update(txt)
	fout.write(cipher.encrypt(enc))
	
	fin.close()
	fout.close()
	return 0


pwd = getpass.getpass()
pwd = pwd.encode()
crypto(sys.argv[1], sys.argv[2], pwd)
decrypt("encrypted_raposa_uvas.txt", "decrypted.txt", pwd)
