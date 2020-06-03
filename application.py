from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import send_file
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.Random import get_random_bytes
import gzip
import io
import os
import sys

application = Flask(__name__)

def crypto(file, passphrase, encryption):
    #capture file name and extension
	nameAndExtension = file.filename.rsplit(sep='.', maxsplit=1)
	name = nameAndExtension[0]
	extension = nameAndExtension[1]
	
	if encryption is True:
		#generate salt and nonce, derive key from passphrase
		salt = get_random_bytes(16)
		nonce = get_random_bytes(8)
		key = scrypt(passphrase, salt, 32, N=2**18, r=8, p=1)
		
		#encrypt file with key and nonce
		cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
		ciphertext = cipher.encrypt(file.read())
		
		#write output to file
		encrypted_FileName = name + '.protected'
		encrypted_File = open(encrypted_FileName, 'xb')
		encrypted_File.write(len(extension).to_bytes(1, 'big') + extension.encode() + salt + nonce + ciphertext)
		encrypted_File.close()
		
		#return encrypted file
		return encrypted_FileName
    
	else:
		#get file extension
		extensionSize = file.read(1)
		extension = file.read(extensionSize[0])
		
		#file name and extension
		fullName = name + '.' + extension.decode()
		
		#get salt and extract key
		salt = file.read(16)
		key = scrypt(passphrase, salt, 32, N=2**18, r=8, p=1)
		
		#get nonce
		nonce = file.read(8)
		
		#decrypt file with key and nonce
		cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
		plaintext = cipher.decrypt(file.read())
		
		#write decompressed data to file
		decrypted_FileName = fullName
		decrypted_File = open(decrypted_FileName, 'xb')
		decrypted_File.write(plaintext)
		decrypted_File.close()
		
		#return file
		return fullName
    
@application.route("/", methods=['GET'])
def home():

    return render_template("home.html")
    
@application.route("/encrypt.html", methods=['GET'])
def encryptPage():

    return render_template("encrypt.html")
    
@application.route("/decrypt.html", methods=['GET'])
def decryptPage(script=""):

    return render_template("decrypt.html", script=script)
    
@application.route("/encrypt", methods=['POST'])
def encryptFile():

	#run AES encryption using file
	return render_template('download.html', file=crypto(request.files['file'], request.form['phrase'], True))

@application.route("/decrypt", methods=['POST'])
def decryptFile():

    #run AES decryption using files
	return render_template('download.html', file=crypto(request.files['file'], request.form['phrase'], False))
	
@application.route("/download/<file>", methods=['GET'])
def downloadFile(file):

    #send file to user
	return send_file(file, as_attachment=True)
    
@application.route("/cleanup/<file>", methods=['GET'])
def cleanupFile(file):

	#destroy file
	os.remove(file)
	return redirect("/")

if __name__ == "__main__":
	application.run(debug=True)
