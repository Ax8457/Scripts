#!/usr/bin/python3

import struct
import sys
import os

def int_to_ASCII(l1):
	ASCII_str = ''.join(map(chr, l1))
	is_ASCII =  ASCII_str.isascii()
	if is_ASCII == False :
		return "[x] Error, Invalid ASCII characters"
	else:
		return ASCII_str

def fcTL_chunk_parser(f,f_size,c,l1,l2):

    try:
    	length_bytes = f.read(4)
    	length = struct.unpack(">I", length_bytes)[0] # it decodes length bytes (BIG ENDIAN)
    	chunk_type = f.read(4).decode("ascii", errors='ignore')         
    	chunk_data = f.read(length) # it moves the pointer to 8 (Magic bytes) + chunk's length byte position
    	f.read(4) # it moves the pointer to the next chunk (+ 4 byte for the CRC)
    	pointer_pos = f.tell()
    	if f_size == pointer_pos :
    	     print(f"[=>] {c} fcTL chunks detected & analyzed")
    	     req = input("Try to decode delay numerator values & delay denominator values as ASCII characters ? [Y/N]")
    	     if req == "Y" :
    	     	l1_ascii = int_to_ASCII(l1)
    	     	l2_ascii = int_to_ASCII(l2)
    	     	print(f"[+] Delay numerator values found : {l1}")
    	     	print(f"[=>] decoded as : {l1_ascii}")
    	     	print(f"[+] Delay denominator values found {l2}")
    	     	print(f"[=>] decoded as : {l2_ascii}")
    	     print("[exit]")
    	     sys.exit(1)
    	     
    	return chunk_type, chunk_data
    	
    except Exception as e : 
        print(f"[x] Error : {e}")
        sys.exit(1)
    

def fcTL_chunk_Analyzer(filename,f_size):
    count = 0 
    delay_den_var = []
    delay_num_var = []
    with open(filename, "rb") as f:
        magic_bytes = f.read(8) #it moves the pointer to the 8th byte
        
        if magic_bytes != b'\x89PNG\r\n\x1a\n':
            print("[x] Invalid APNG file.")
            sys.exit(1)

        while True:
            chunk_type, chunk_data = fcTL_chunk_parser(f,f_size,count,delay_num_var,delay_den_var) 
            if chunk_type == 'fcTL':
            	print("[+] fcTL chunk detected")
            	print(f"Chunk {count}: Type = {chunk_type}")
            	sequence_number, width, height, x_offset, y_offset, delay_num, delay_den, dispose_op, blend_op = struct.unpack(">IiiiiHHBB", chunk_data)
            	delay_den_var.append(delay_den)
            	delay_num_var.append(delay_num)
            	print(f"  Sequence Number: {sequence_number}")
            	print(f"  Width: {width}, Height: {height}")
            	print(f"  X Offset: {x_offset}, Y Offset: {y_offset}")
            	print(f"  Delay: {delay_num}/{delay_den} (Numerator/Denominator)")
            	print(f"  Dispose Op: {dispose_op}, Blend Op: {blend_op}")
            	print("-" * 50)
            	count += 1
       
        
if __name__ == "__main__":
	if len(sys.argv) < 2:
    		print(f"[!] Usage : {sys.argv[0]} <APNG file>") 
    		sys.exit(1)
    		  
	print("=" * 50)
	print(f"==============  APNG Steganography  ==============")
	print("=" * 50)
      
	f = sys.argv[1]  
	f_size = os.path.getsize(f)
	fcTL_chunk_Analyzer(f,f_size)
