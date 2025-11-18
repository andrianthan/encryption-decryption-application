# project logic

# source(s): https://pypi.org/project/cryptography/
# cryptography documentation: https://cryptography.io/en/latest/

from cryptography.fernet import Fernet

# generate a master key for decryption
def generate_master_key():
    m_key = Fernet.generate_key()
    with open("master_key.key", "wb") as master_file:
        master_file.write(m_key)

# load the key from master_key.key
def load_key():
    with open("master_key.key", "rb") as master_file:
        return master_file.read()

# encrypt a file using the master key
def encrypt_file(filename):
    key = load_key()
    f = Fernet(key)

    # open original file to be encrypted
    with open(filename, "rb") as file:
        data = file.read()

    # encrypt the data
    encrypted = f.encrypt(data)

    # write the encrypted data into a new file
    with open(filename + ".encrypted", "wb") as file:
        file.write(encrypted)

# decrypt the file using the master key
def decrypt_file(filename):
    key = load_key()
    f = Fernet(key)

    # open the encrypted file to be decrypted
    with open(filename, "rb") as file:
        encrypted_data = file.read()

    # decrypt the data
    decrypted = f.decrypt(encrypted_data)

    original_data = filename.replace(".encrypted", "")

    # write decrypted data into file
    with open(original_data, "wb") as file:
        file.write(decrypted)


# test
if __name__ == "__main__":
    generate_master_key()

    with open("test.txt", "w") as f:
        f.write("test file")

    encrypt_file("test.txt")
    decrypt_file("test.txt.encrypted")