#!/usr/bin/python3

from datetime import datetime, timezone
import re
import random
    
def macAddress_checker(m):
    mac_regex = r'^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$'
    if re.match(mac_regex, m):
        return True
    else:
        return False	

def ts_checker(ts):
    timestamp_regex = r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}$'
    if re.match(timestamp_regex, ts):
        return True
    else:
        return False

def clockSeqAndVariant_generator():
    clock_sequence = random.randint(0, 0x3FFF)  
    clkv = clock_sequence | 0x8000
    return clkv

def variantAndClockSeq_Checker(h):
    if len(h) != 4:
    	print("invalid length, has to be 4.")
    	return False 
  	
    try:
        int(h, 16) 
        return True
    except ValueError:
    	print("invalid hex value")
    	return False
        

def ts_data_extractor(ts):
	dt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')
	data = {
		'year' : dt.year,
		'month' : dt.month,
		'day' : dt.day,
		'hour' : dt.hour,
		'min' : dt.minute,
		'sec' : dt.second,
		'ms' : dt.microsecond	
	}
	print(f"Data extracted from Timestamp : {data}") 
	return data	

def uuidv1_generator(dt,mac_address,variantAndCloqSeq=None) : 
	print(f"Generating UUID v1 based on {dt} and {mac_address}") 
	dt_epoch = datetime(1582, 10, 15,tzinfo=timezone.utc)
	mac_address = mac_address.replace(":", "")
	delta = dt - dt_epoch
	delta_100ns = delta.total_seconds() * 1e7
	delta_100ns_int = int(delta_100ns)
	time_low = delta_100ns_int & 0xFFFFFFFF
	time_mid = (delta_100ns_int >> 32) & 0xFFFF
	time_high = (delta_100ns_int >> 48) & 0xFFF
	version = 1 << 12
	time_high_version = version | time_high 
	print(f" ------------------------------") 
	print(f" Time_low : {time_low}")
	print(f" Hex Time_low : {time_low:04x}")
	print(f" ------------------------------") 
	print(f" Time_mid : {time_mid}")
	print(f" Hex Time_mid : {time_mid:04x}")
	print(f" ------------------------------") 
	print(f" Time_High : {time_high}")
	print(f" Time_High + version : {time_high_version}")
	print(f" Hex Time_High + version : {time_high_version:04x}")
	print(f" ------------------------------") 
	if variantAndCloqSeq == None :
		print(f"[!] Variant and cloq sequence parameter missing, generating a random one based on RFC 4122 'https://datatracker.ietf.org/doc/html/rfc4122#section-4.1.1' ...")
		variantAndCloqSeq = clockSeqAndVariant_generator()
		print(f"variant generated : {variantAndCloqSeq:04x} ")
		print(f"uuid v1 generated : {time_low:04x}-{time_mid:04x}-{time_high_version:04x}-{variantAndCloqSeq:04x}-{mac_address}")
	else : 
		print(f"uuid v1 generated : {time_low:04x}-{time_mid:04x}-{time_high_version:04x}-{variantAndCloqSeq}-{mac_address}")
	return 


if __name__ == "__main__":
	print(f"UUID V1 (timestamp and MAC address based) finder")
	
	m = input("Provide a valid MAC address : ")
	is_valid_macAddress = macAddress_checker(m)
	if is_valid_macAddress == False : 
		print(f"this mac Address ({m}) isn't valid.")
		exit(1)
		
	date_time = input("Provide a valid timestamp(UTC). Example : '2024-09-29 11:43:00.201771' : ")
	is_valid_ts = ts_checker(date_time)
	if is_valid_ts == False : 
		print(f"this timestamp ({date_time}) isn't valid.")
		exit(1)
		
	data = ts_data_extractor(date_time)
	dt = datetime(data['year'],data['month'],data['day'],data['hour'],data['min'],data['sec'],data['ms'],tzinfo=timezone.utc)
		
	ask =  input("Adding clock sequence and variant value (in hex if known) for generating UUID v1 ? [Y/N] : ")
	if ask == "Y" : 
		cloqSeqAndVariant = input("Provide a clock sequence and variant value in hex : ")
		is_valid = variantAndClockSeq_Checker(cloqSeqAndVariant)
		if is_valid != True : 
			exit(1)
		uuid_v1 = uuidv1_generator(dt, m, cloqSeqAndVariant)
		exit(1)
		
	uuid_v1 = uuidv1_generator(dt, m)		
		
	
	
	
	
	
	
	


















	
