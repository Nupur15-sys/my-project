def encrypt_caesar(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

def decrypt_caesar(cipher, shift):
    return encrypt_caesar(cipher, -shift)

plain_text = "Hello World"
shift = 3
encrypted = encrypt_caesar(plain_text, shift)
decrypted = decrypt_caesar(encrypted, shift)
print("Encrypted:", encrypted)
print("Decrypted:", decrypted)
