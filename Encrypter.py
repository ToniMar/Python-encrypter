#Salaa -aliohjelmassa on kaytetty lahteena osoitteessa http://edu.pegax.com/doku.php?id=tietoturva:harjoitukset2011:aes_crypt.py olevaa koodia

import sys, os,random, struct
from Crypto.Cipher import AES
import base64
from Crypto import Random
import Crypto.PublicKey.RSA as RSA
import Crypto.Hash.SHA256 as SHA
from Crypto.Util.randpool import RandomPool
import hashlib

def salaa():
	#Allerkirjoitetaan sisalto
	#RSA avaimen luonti
	RSAkey=RSA.generate(1024, RandomPool().get_bytes)
	#Allekirjoitettavan tiedoston avaus ja luku
	SignFile=open(sys.argv[2],'rb')
	contents=SignFile.read()
	SignFile.close()
	#Hashin laskeminen datalle
	hash1=SHA.new(contents).digest()
	#Datan allekirjoitus
	signature=RSAkey.sign(hash1,"")
	#Julkisen avaimen tallennus
	pubkey=RSAkey.publickey()
	PubkeyFILE=open("pubkey.pem",'w')
	PubkeyFILE.write(pubkey.exportKey('PEM'))
	PubkeyFILE.close()
	#Allekirjoituksen tallennus
	SigFILE=open("signature.txt",'wb')
	test=signature[0]
	SigFILE.write(str(test))
	SigFILE.close()

	password=raw_input("Anna salasana:")
	key=hashlib.sha256(password).digest()
	#Luetaan julkinen avain tiedostoon
	publickeyFILE=open("julkinenavain",'wb')
	publickeyFILE.write(key)
	publickeyFILE.close()
	#Moden valinta
	mode = AES.MODE_CBC
	iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
	#Salaimen luonti
	cipher = AES.new(key, mode,iv)
	#Salattavan tiedoston koko
	filesize = os.path.getsize(sys.argv[2])
	#Lohkon koko
	chunksize=AES.block_size * 16
	with open(sys.argv[2], 'rb') as infile:
        	with open("salattusopimus.txt", 'wb') as outfile:
			#Tiedoston koon kirjoitus tiedoston alkuun
            		outfile.write(struct.pack('<Q', filesize))
			outfile.write(iv)
            		while True:
                		chunk = infile.read(chunksize)
                		if len(chunk) == 0:
                    			break
                		elif len(chunk) % 16 != 0:
                    			chunk += ' ' * (AES.block_size - len(chunk) % AES.block_size)
				outfile.write(cipher.encrypt(chunk))
	outfile.close()
	infile.close()
	
	
	
	
				
def pura():
	
	#Avataan julkisen avaimen sisaltama tiedosto
	publickeyFILE=open(sys.argv[3],'rb')
	key=publickeyFILE.read()
	publickeyFILE.close()
	#Moodi
	mode=AES.MODE_CBC
	#Luettavan lohkon koon maaritys.
	chunksize=AES.block_size * 16
	#Avataan purettava tiedosto
	with open(sys.argv[2], 'rb')as infile:
		size = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
		iv = infile.read(16)
		cipher = AES.new(key, mode, iv)
		with open("purettusopimus.txt",'wb') as outfile:
			while True:
				chunk=infile.read(chunksize)
				if len(chunk)==0:
					break
				outfile.write(cipher.decrypt(chunk))
			outfile.truncate(size)
	infile.close()
	outfile.close()
	#Avataan allekirjoitus
	SigFILE=open("signature.txt",'rb')
	signaturetemp=SigFILE.read()
	signature=long(signaturetemp)
	SigFILE.close()
	#Avataan julkinen avain
	pubKeyFILE=open("pubkey.pem",'rb')
	pubkey=RSA.importKey(pubKeyFILE.read())
	pubKeyFILE.close()
	#Avataan purettu sompimus
	VeriFILE=open("purettusopimus.txt",'rb')
	contents=VeriFILE.read()
	VeriFILE.close()
	hash2=SHA.new(contents).digest()
	#Tarkistetaan allekirjoitus
	if pubkey.verify(hash2,(signature,)):
		print "Allekirjoitus OK"
	else:
		print "Allekirjoitus ei kelpaa"
	



#Paaohjelma

if sys.argv[1]=="-salaa":
	salaa()

if sys.argv[1]=="-pura":
	pura()
