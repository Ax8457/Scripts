import binascii
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad

def blocks(hex_data):
    blocks = [hex_data[i:i+32] for i in range(0, len(hex_data), 32)]
    print("[+] 16 bytes Blocks extracted :")
    for i, block in enumerate(blocks, 1):
    	print(f"	Bloc {i}: {block}")
    return blocks

def read_aesEncryptedfile(f_path):
	with open(f_path, 'rb') as f:
    		data = f.read()
	data_hex = data.hex()
	print(f"[+] Lenght : {len(data)} bytes")
	print(f"[+] Data extracted : { data_hex }")
	bl = blocks(data_hex)
	
	return bl,data

def retreive_AESKey(target):
	key_infile = target[4:24]
	AES_KEY = bytearray(16)
	for i in range(20):
		AES_KEY[i%16] ^= key_infile[i]
	print(f"[+] AES Key (hex) retreived in mylogin.cnf encrypted : {AES_KEY.hex()}")
	print(f"[+] AES Key length : {len(AES_KEY)} bytes")
	return AES_KEY
	
def extract_encrypted_data(file_path):
	encrypted_data = b""
	ind = 0
	with open(file_path, "rb") as f:
		f.seek(24) # Ignoring 24 first bytes => 0 + key_infile
		while True: 
            		len_bytes = f.read(4)
            		if not len_bytes: # end of file
                		break 
            		length = int.from_bytes(len_bytes, byteorder='little')
            		ind += 1
            		print(f"[+] Encrypted Segment Found, N°{ind}")
            		print(f"	[+] Segment length : {length}")
            		enc_part = f.read(length)
            		if len(enc_part) != length:
                		print("[x] Error : Wrong size.")
                		break 
            		encrypted_data += enc_part
	print(f"[+] Encrypted (hex) Data retreived : {encrypted_data.hex()}")
	return encrypted_data
 
def decrypt_myloginCNF(key,f):
	data = extract_encrypted_data(f)
	if len(data) % AES.block_size != 0:
        	data = pad(data, AES.block_size)
        	print(f"[+] Data length : {len(data)} bytes")
	print(f"[+] Data length : {len(data)} bytes")
	cipher = AES.new(key, AES.MODE_ECB)  
	dec_data = unpad(cipher.decrypt(data), AES.block_size)
	print(f"[+] Data retreived : \n {dec_data.decode('utf-8', errors='ignore')}")
		
bl,data= read_aesEncryptedfile(sys.argv[1])
AES_KEY = retreive_AESKey(data)
decrypt_myloginCNF(AES_KEY,sys.argv[1])

