"""
Created on: 30/05/18
Author    : pacellig

Requires pycryptodome ($ pip install pycryptodome) in order to use 'AES.MODE_EAX' mode.

1) Produce a private/public key couple
2) Use the public key (RSA) to encrypt the generated OTP
3) Use the generated OTP to encrypt, via AES, the desired message
4) Decrypt the message using the corresponding private key (RSA)

"""
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


def key_gen():
    # Generate a public/ private key pair using 4096 bits key length
    key = RSA.generate(4096)

    # Private key in PEM format
    private_key = key.exportKey("PEM")

    # Public key in PEM format
    public_key = key.publickey().exportKey("PEM")

    # Save private and public keys to file
    fd = open("private_key.pem", "wb")
    fd.write(private_key)
    fd.close()

    fd = open("public_key.pem", "wb")
    fd.write(public_key)
    fd.close()


def encrypt_message(plaintext, public_key):
    # Generate a random session key, to use as OTP
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)
    enc_session_key = rsa_key.encrypt(session_key)

    # Encrypt the data with AES using encrypted session key
    aes_key = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = aes_key.encrypt_and_digest(plaintext)
    file_out = open("encrypted.bin", "wb")
    [file_out.write(x) for x in (enc_session_key, aes_key.nonce, tag, ciphertext)]
    file_out.close()


def decrypt_message(path_to_encrypted_file, private_key):
    encrypted_fd = open(path_to_encrypted_file, "rb")

    rsa_key = RSA.importKey(private_key)
    enc_session_key, nonce, tag, ciphertext = [encrypted_fd.read(x) for x in (rsa_key.size_in_bytes(), 16, 16, -1)]

    # Decrypt the session key with the private RSA key
    rsa_key = PKCS1_OAEP.new(rsa_key)
    session_key = rsa_key.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    aes_key = AES.new(session_key, AES.MODE_EAX, nonce)
    data = aes_key.decrypt_and_verify(ciphertext, tag)
    return data.decode("utf-8")


def test_encrypt_decrypt():
    # Use the public key for encryption
    fd = open("public_key.pem", "rb")
    public_key = fd.read()
    fd.close()

    # Read plaintext from file
    fd = open('plaintext.txt', 'r')
    plaintext = fd.read()
    encrypt_message(plaintext, public_key)

    # Use the private key for decryption
    fd = open("private_key.pem", "rb")
    private_key = fd.read()
    fd.close()

    decrypted = decrypt_message("encrypted.bin", private_key)
    print decrypted


if __name__ == '__main__':
    # Generate private/public keys pair
    key_gen()

    test_encrypt_decrypt()
