from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256


def main() -> None:
    password = b"classical-password"
    salt = b"salt"
    key = PBKDF2(password, salt, dkLen=32, count=10000, hmac_hash_module=SHA256)
    print("PBKDF2-HMAC-SHA256:", key.hex())


if __name__ == "__main__":
    main()
