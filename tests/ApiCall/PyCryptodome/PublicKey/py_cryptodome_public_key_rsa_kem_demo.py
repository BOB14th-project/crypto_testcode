from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def main() -> None:
    key = RSA.generate(2048)
    cipher = PKCS1_OAEP.new(key.public_key())

    session_key = get_random_bytes(32)
    encrypted = cipher.encrypt(session_key)
    recovered = PKCS1_OAEP.new(key).decrypt(encrypted)

    print("RSA session key (enc):", encrypted.hex()[:32], "...")
    print("Keys match:", session_key == recovered)


if __name__ == "__main__":
    main()
