import string

def base_encrypt(message, key):

    shift = key % 26
    cipher = str.maketrans(string.ascii_lowercase, string.ascii_lowercase[shift:] + string.ascii_lowercase[:shift])

    encrypted_message = message.lower().translate(cipher)

    return encrypted_message

def base_decrypt(encrypted_message, key):
    
    shift = 26 - (key % 26)
    cipher = str.maketrans(string.ascii_lowercase, string.ascii_lowercase[shift:] + string.ascii_lowercase[:shift])

    message = encrypted_message.translate(cipher)
    return message

message = 'Thank you for testing my code'
key = 3

encrypted_message = base_encrypt(message, key)
print(f'Encrypt message: {encrypted_message}')

decrypted_message = base_decrypt(encrypted_message, key)
print(f'Decrypted message: {decrypted_message}')