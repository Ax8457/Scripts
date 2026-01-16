import random
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD
from flask import Flask, request, jsonify
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

def craft_E(message_size):
    E = []
    e_sum = random.getrandbits(64)
    E.append(e_sum)
    for _ in range(message_size - 1):
        offset = random.getrandbits(32)
        e = e_sum + offset
        E.append(e)
        e_sum += e
    return E, e_sum

def craft_privateKey(message_size):
    E, total_sum = craft_E(message_size)
    q = total_sum + random.getrandbits(64)
    w = random.getrandbits(1024)
    while GCD(w, q) != 1:
        w = random.getrandbits(1024)
    return E, w, q

@app.route('/custom_encryption/encrypt/', methods=['POST'])
def custom_encryption():
    data = request.get_json()
    M_str = data.get('M')
    M_bytes = M_str.encode()

    message_bits_size = len(M_bytes) * 8
    E, w, q = craft_privateKey(message_bits_size)

    app.config['E'] = E
    app.config['w'] = w
    app.config['q'] = q
    
    H = [(w * e) % q for e in E]
    
    m_int = bytes_to_long(M_bytes)
    B = list(map(int, bin(m_int)[2:].zfill(message_bits_size)))
    cipher = sum(h * b for h, b in zip(H, B))
    
    return jsonify({
        "Cipher": cipher,
        "MessageSizeBits": message_bits_size,
        "PublicKey": [hex(h)[2:] for h in H]
    })

@app.route('/custom_encryption/decrypt/', methods=['POST'])
def custom_decryption():
    E = app.config.get('E')
    w = app.config.get('w')
    q = app.config.get('q')
    data = request.get_json()
    c = data.get('Cipher')
    bits_size = data.get('MessageSizeBits')
    	
    w_inv = inverse(w, q)
    c_prime = pow(c * w_inv, 1, q)
    
    m_bits = []
    for e in reversed(E):
        if e <= c_prime:
            c_prime -= e
            m_bits.append(1)
        else:
            m_bits.append(0)
    
    m_bits.reverse()
    M_int = 0
    for bit in m_bits:
        M_int = (M_int << 1) | bit
        
    return jsonify({"Plaintext": long_to_bytes(M_int, bits_size // 8).decode()})

if __name__ == '__main__':
    app.run(debug=True)
