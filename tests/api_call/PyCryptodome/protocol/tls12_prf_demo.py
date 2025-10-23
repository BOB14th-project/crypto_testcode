from Crypto.Protocol.KDF import TLS1_PRF
from Crypto.Random import get_random_bytes


def main() -> None:
    client_random = get_random_bytes(32)
    server_random = get_random_bytes(32)
    premaster = b"\x03\x03" + get_random_bytes(46)  # TLS 1.2 RSA premaster

    master_secret = TLS1_PRF(
        premaster,
        b"master secret",
        client_random + server_random,
        48,
        hashmod="SHA256",
    )
    key_block = TLS1_PRF(
        master_secret,
        b"key expansion",
        server_random + client_random,
        2 * (32 + 16),  # client/server write keys (AES-256-GCM) + IVs
        hashmod="SHA256",
    )

    print("Master secret:", master_secret.hex())
    print("Key block 1st 32 bytes:", key_block[:32].hex())


if __name__ == "__main__":
    main()
