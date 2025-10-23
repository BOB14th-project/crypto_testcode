from Crypto.Random import get_random_bytes


def main() -> None:
    sample = get_random_bytes(32)
    print("PyCryptodome random sample:", sample.hex())


if __name__ == "__main__":
    main()
