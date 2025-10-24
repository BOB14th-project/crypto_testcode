from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


def main() -> None:
    key = ECC.generate(curve="P-256")
    signer = DSS.new(key, "fips-186-3")

    message = b"pycryptodome-signature-demo"
    digest = SHA256.new(message)
    signature = signer.sign(digest)

    verifier = DSS.new(key.public_key(), "fips-186-3")
    verifier.verify(SHA256.new(message), signature)
    print("ECDSA signature OK (len =", len(signature), ")")


if __name__ == "__main__":
    main()
