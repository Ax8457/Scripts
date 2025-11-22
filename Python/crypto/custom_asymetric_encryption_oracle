import random
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD
from flask import Flask, request, jsonify

app = Flask(__name__)

def craft_E(message_size=160):
    E = []
    e_sum = random.getrandbits(64) # first value of E 
    E.append(e_sum)
    for _ in range(message_size - 1):
        offset = random.getrandbits(32)
        e = e_sum + offset
        e_sum += e
        E.append(e)
    return E

def craft_privateKey(message_size=160):
    print("Start pubkey generation")
    w = getPrime(1024)
    q = getPrime(1024)
    while GCD(w, q) != 1:
        w = getPrime(1024)
        q = getPrime(1024)	
    print(f"w = {w}")
    print(f"q = {q}")
    E = craft_E()
    print(f"Length of E {len(E)}")
    while(E[-1] * 2 >= q):
    	E = craft_E()
    print(E[-1])
    return E, w, q

E, w, q = craft_privateKey()
app.config['E'] = E
app.config['w'] = w
app.config['q'] = q

@app.route('/custom_encryption/publicKey/')
def craft_publicKey():
    E = app.config['E']
    w = app.config['w']
    q = app.config['q']
    H = [ (w * e) % q for e in E ]
    H_hex = [hex(h)[2:] for h in H]
    return jsonify({"Public Key": H_hex})

@app.route('/custom_encryption/encrypt/', methods=['POST'])
def custom_encryption():
    E = app.config['E']
    w = app.config['w']
    q = app.config['q']
    data = request.get_json()
    H = data.get('H')
    M = data.get('M')
    print(f"Message received {M}")
    H = [int(h, 16) for h in H]
    M = bytes_to_long(M.encode()) 
    B = list(map(int, bin(M)[2:].zfill(len(H))))
    print(f"Number of bits: {len(B)}")
    cipher = sum(h * b for h, b in zip(H, B))
    #cipher_hex = hex(cipher)[2:]
    return jsonify({"Cipher (int)": cipher})

@app.route('/custom_encryption/decrypt/', methods=['POST'])
def custom_decryption():
    E = app.config['E']
    w = app.config['w']
    q = app.config['q']
    data = request.get_json()
    c = data.get('Cipher')
    E = list(map(int, E))
    w_inv = inverse(w, q)
    c = pow(c * w_inv,1,q)
    m = []
    E = E[::-1]
    for e in E:
        if e <= c:
            c -= e
            m.append(1)
        else:
            m.append(0)
    m = m[::-1]
    M_int = 0
    bits = m
    for bit in bits:
        M_int = (M_int << 1) | bit
    return jsonify({"Plaintext": hex(M_int)[2:]})

if __name__ == '__main__':
    app.run(debug=True)
