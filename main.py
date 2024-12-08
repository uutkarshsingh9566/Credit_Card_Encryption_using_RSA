import pandas as pd
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Function to generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt data using public key
def encrypt_data(public_key, data):
    encrypted_data = []
    for item in data:
        encrypted_item = public_key.encrypt(
            item.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_data.append(encrypted_item.hex())  # Store as hex string
    return encrypted_data

# Function to decrypt data using private key
def decrypt_data(private_key, encrypted_data):
    decrypted_data = []
    for item in encrypted_data:
        decrypted_item = private_key.decrypt(
            bytes.fromhex(item),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_data.append(decrypted_item.decode())
    return decrypted_data

# Main function
def main():
    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Read data from card_info.csv
    df = pd.read_csv('card_info.csv')
    print("Original Data:\n", df)

    # Convert data into lists of strings
    data = df.applymap(str).values.tolist()  # Ensure all data is treated as string

    # Encrypt each row of data
    encrypted_data = [encrypt_data(public_key, row) for row in data]

    # Store encrypted data into encrypted_info.csv
    encrypted_df = pd.DataFrame(encrypted_data)
    encrypted_df.to_csv('encrypted_info.csv', index=False, header=False)
    print("Encrypted Data saved to encrypted_info.csv")

    # Read encrypted data back
    encrypted_df = pd.read_csv('encrypted_info.csv', header=None)
    encrypted_data = encrypted_df.values.tolist()

    # Decrypt the data
    decrypted_data = [decrypt_data(private_key, row) for row in encrypted_data]

    # Store decrypted data into card_info_after.csv
    decrypted_df = pd.DataFrame(decrypted_data, columns=df.columns)
    decrypted_df.to_csv('card_info_after.csv', index=False)
    print("Decrypted Data saved to card_info_after.csv")

if __name__ == "__main__":
    main()
