# Poly-alphabetic substitution cipher

# gonna need this
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
alphabet_index = {alphabet[i]: i for i in range(len(alphabet))}

# Let us make a simple vigenere square function
def vigenere_square():
    square = []
    for i in range(len(alphabet)):
        square.append(alphabet[i:] + alphabet[:i])
    return square

def vigenere_encrypt(plain_text: str, key: str) -> str:
    square = vigenere_square()
    key = key.upper()
    key_length = len(key)
    plain_text = plain_text.upper()
    cipher_text = []
    for i in range(len(plain_text)):
        key_char = key[i % key_length]
        plain_char = plain_text[i]
        if plain_char not in alphabet_index:
            cipher_text.append(plain_char)
            continue
        cipher_char = square[alphabet_index[plain_char]][alphabet_index[key_char]]
        cipher_text.append(cipher_char)
    return ''.join(cipher_text)

def vigenere_decrypt(cipher_text: str, key: str) -> str:
    square = vigenere_square()
    key, key_length = key.upper(), len(key)
    cipher_text = cipher_text.upper()
    plain_text = []
    
    for i in range(len(cipher_text)):
        key_char = key[i % key_length]
        cipher_char = cipher_text[i]
        if cipher_char not in alphabet_index:
            plain_text.append(cipher_char)
            continue
        row = alphabet_index[key_char]
        col = square[row].index(cipher_char)
        plain_char = alphabet[col]
        plain_text.append(plain_char)
    return ''.join(plain_text)

def run_tests():
    tests = [
        # Normal encryption and decryption
        ("HELLO", "WORLD", "DSCWR"),
        # Handling of spaces
        ("HELLO WORLD", "KEY", "RIJVS GSPVH"),
        # Mixed case inputs
        ("Hello World", "Key", "RIJVS GSPVH"),
        # Non-alphabetic characters
        ("HELLO, WORLD!", "KEY", "RIJVS, AMBPB!")
    ]
    
    for plain_text, key, expected_cipher in tests:
        encrypted = vigenere_encrypt(plain_text, key)
        decrypted = vigenere_decrypt(encrypted, key)
        print(f"Plaintext: {plain_text}")
        print(f"Key: {key}")
        print(f"Expected Cipher: {expected_cipher}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        assert encrypted == expected_cipher, f"Encryption failed for {plain_text} with key {key}"
        assert decrypted == plain_text.upper(), f"Decryption failed for {encrypted} with key {key}"
        print("Test passed.\n")

run_tests()