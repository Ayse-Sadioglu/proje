import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

def encrypt(key, filename, output_path):
    chunksize = 64 * 1024
    outputFile = os.path.join(output_path, "enc_" + os.path.basename(filename))
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))

    # Calculate the hash of the ciphertext
    hash_obj = SHA256.new()
    with open(outputFile, 'rb') as encrypted_file:
        while True:
            chunk = encrypted_file.read(chunksize)
            if not chunk:
                break
            hash_obj.update(chunk)

    # Write the hash to a separate file
    hash_file_path = os.path.join(output_path, "enc_" + os.path.basename(filename) + ".hash")
    with open(hash_file_path, 'w') as hash_file:
        hash_file.write(hash_obj.hexdigest())

def decrypt(key, filename, output_path):
    chunksize = 64 * 1024
    original_filename = os.path.basename(filename)[4:]  # Remove the "(enc)" prefix
    outputFile = os.path.join(output_path, "dec_" + original_filename.strip())  # Prepend "dec_"
    hash_file_path = os.path.join(output_path, "enc_" + original_filename.strip() + ".hash")

    # Check if the directory exists
    if not os.path.isdir(output_path):
        raise FileNotFoundError(f"The specified output path '{output_path}' is not a directory or does not exist.")

    print(f"Output file path: {outputFile}")

    # Read the stored hash from the hash file
    with open(hash_file_path, 'r') as hash_file:
        stored_hash = hash_file.read().strip()

    # Calculate the hash of the ciphertext before decryption
    hash_obj = SHA256.new()
    with open(filename, 'rb') as encrypted_file:
        while True:
            chunk = encrypted_file.read(chunksize)
            if not chunk:
                break
            hash_obj.update(chunk)

    # Compare the calculated hash with the stored hash
    integrity_hash = hash_obj.hexdigest()
    if integrity_hash != stored_hash:
        print("Integrity check failed. The encrypted file may be corrupted.")

    # Proceed with decryption
    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(filesize)

def getKey(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

def Main():
    choice = input("Would you like to (E)encrypt or (D)Decrypt ")

    if choice == 'E':
        filename = input("File to encrypt: ")
        key = input("Key: ")
        output_path = input("Enter the path to save the encrypted file: ")
        encrypt(getKey(key), filename, output_path)
    elif choice == 'D':
        filename = input("File to decrypt: ")
        key = input("Key: ")
        output_path = input("Enter the path to save the decrypted file: ")
        decrypt(getKey(key), filename, output_path)
        
    else:
        print("No option selected, closing...")

if __name__ == "__main__":
    Main()
