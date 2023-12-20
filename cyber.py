import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2


def encrypt(password, filename, output_path):
    chunksize = 64 * 1024
    salt = os.urandom(16)  # Generate a random 16-byte salt
    key = getKey(password, salt)
    
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

    # Write the salt to a separate file
    salt_file_path = os.path.join(output_path, "enc_" + os.path.basename(filename) + ".salt")
    with open(salt_file_path, 'wb') as salt_file:
        salt_file.write(salt)


def decrypt(password, filename, output_path, salt):
    chunksize = 64 * 1024
    original_filename = os.path.basename(filename)[4:]  # Remove the "(enc)" prefix
    outputFile = os.path.join(output_path, "dec_" + original_filename.strip())  # Prepend "dec_"
    hash_file_path = os.path.join(output_path, "enc_" + original_filename.strip() + ".hash")
    salt_file_path = os.path.join(output_path, "enc_" + original_filename.strip() + ".salt")

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

    # Read the salt from the separate salt file
    with open(salt_file_path, 'rb') as salt_file:
        salt = salt_file.read()

    # Proceed with decryption
    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)
        key = getKey(password, salt)
        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(filesize)

    print("Decryption successful.")


def getKey(password, salt, iterations=100000):
    key = PBKDF2(password, salt, dkLen=32, count=iterations)
    return key

def print_intro():
    intro = """
                         .-.
                        |_:_|
                       /(_Y_)\\
.                     ( \\/M\\/ )
 '.                 _.'-/'-\\'._ 
   ':             _/.--'[[[[]'--.\\_
     ':          /_'  : |::"| :  '.\\
       ':       //   ./ |oUU| \\'  :\\
         ':    _:'..' \\_|___|_/ :   :|
           ':.  .'  |_[___]_|  :.':\\
            [::\\ |  :  | |  :   ; : \\
             '-'   \\/'.| |.' \\  .;.' |
             |\\_    \\ '-'   :       |
             |  \\    \\ .:    :   |   |
             |   \\    | '.   :    \\  |
            /       \\   :. .;       |
           /     |   |  :__/     :  \\
          |  |   |    \\:   | \\   |   ||
         /    \\  : :  |:   /  |__|   /|
         |     : : :_/_|  /'._\\  '--|_\\
          /___.-/_|-'   \\  \\
                         '-'

        *****Welcome to the File Encryption and Decryption Tool*****

    """

    print(intro)
def print_exit():
    exit = """
                         .-.
                        |_:_|
                       /(_Y_)\\
.                     ( \\/M\\/ )
 '.                 _.'-/'-\\'._ 
   ':             _/.--'[[[[]'--.\\_
     ':          /_'  : |::"| :  '.\\
       ':       //   ./ |oUU| \\'  :\\
         ':    _:'..' \\_|___|_/ :   :|
           ':.  .'  |_[___]_|  :.':\\
            [::\\ |  :  | |  :   ; : \\
             '-'   \\/'.| |.' \\  .;.' |
             |\\_    \\ '-'   :       |
             |  \\    \\ .:    :   |   |
             |   \\    | '.   :    \\  |
            /       \\   :. .;       |
           /     |   |  :__/     :  \\
          |  |   |    \\:   | \\   |   ||
         /    \\  : :  |:   /  |__|   /|
         |     : : :_/_|  /'._\\  '--|_\\
          /___.-/_|-'   \\  \\
                         '-'

        --------  See you!  --------

    """

    print(exit)



def Main():
    print_intro()

    while True:
        choice = input("Would you like to (E)encrypt or (D)Decrypt: ").lower()

        if choice == 'e':
            filename = input("File to encrypt: ")
            if filename.lower() == 'exit':
                print_exit()
                print("Exiting the program.")
                break

            password = input("Key: ")
            while not password:
                print("Password cannot be empty.")
                password = input("Key: ")

            # Generate a random salt
            salt = os.urandom(16)

            key = getKey(password, salt)
            output_path = input("Enter the path to save the encrypted file: ")
            if output_path.lower() == 'exit':
                print_exit()
                print("Exiting the program.")
                break

            encrypt(key, filename, output_path)

        elif choice == 'd':
            filename = input("File to decrypt: ")
            if filename.lower() == 'exit':
                print_exit()
                print("Exiting the program.")
                break

            password = input("Key: ")
            while not password:
                print("Password cannot be empty.")
                password = input("Key: ")

            # Generate a random salt
            salt = os.urandom(16)

            key = getKey(password, salt)
            output_path = input("Enter the path to save the decrypted file: ")
            if output_path.lower() == 'exit':
                print_exit()
                print("Exiting the program.")
                break

            decrypt(key, filename, output_path, salt) 

        elif choice == 'exit':
            print_exit()
            print("Exiting the program.")
            break

        else:
            print("Invalid option. Please enter 'E' for encryption, 'D' for decryption, or 'exit' to quit.")

if __name__ == "__main__":
    Main()
