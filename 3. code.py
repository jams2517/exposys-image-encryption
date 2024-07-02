from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from PIL import Image
import os

def pad(data):
    """Padding for the data to be a multiple of 8 bytes"""
    while len(data) % 8 != 0:
        data += b' '
    return data

def encrypt_image(image_path, key, iv):
    try:
        # Open the image and convert it to bytes
        image = Image.open(image_path)
        image_bytes = image.tobytes()

        # Pad the image bytes
        padded_image_bytes = pad(image_bytes)

        # Create the cipher object and encrypt the data
        cipher = DES3.new(key, DES3.MODE_CFB, iv)
        encrypted_bytes = cipher.encrypt(padded_image_bytes)

        # Save the encrypted data to a new file
        encrypted_image_path = image_path + '.enc'
        with open(encrypted_image_path, 'wb') as enc_file:
            enc_file.write(encrypted_bytes)

        return encrypted_image_path
    except FileNotFoundError:
        print(f"File not found: {image_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

def decrypt_image(encrypted_image_path, key, iv, output_path):
    try:
        # Read the encrypted image data
        with open(encrypted_image_path, 'rb') as enc_file:
            encrypted_bytes = enc_file.read()

        # Create the cipher object and decrypt the data
        cipher = DES3.new(key, DES3.MODE_CFB, iv)
        decrypted_bytes = cipher.decrypt(encrypted_bytes)

        # Remove padding from decrypted bytes
        decrypted_bytes = decrypted_bytes.rstrip(b' ')

        # Create an image from the decrypted bytes
        original_image = Image.open(encrypted_image_path.replace('.enc', ''))
        decrypted_image = Image.frombytes(original_image.mode, original_image.size, decrypted_bytes)

        # Save the decrypted image
        decrypted_image.save(output_path)
    except FileNotFoundError:
        print(f"File not found: {encrypted_image_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Generate a random key and IV
key = DES3.adjust_key_parity(get_random_bytes(24))  # DES3 keys are 24 bytes long
iv = get_random_bytes(8)  # DES3 IV is 8 bytes long

# Paths to the image
image_path = r'C:\Users\MariAnn\Desktop\butterfly.png'  # Replace with your image path
encrypted_image_path = encrypt_image(image_path, key, iv)
if encrypted_image_path:
    print(f"Encrypted image saved to: {encrypted_image_path}")

    # Decrypt the image
    decrypted_image_path = r'C:\Users\MariAnn\Desktop\decrypted_image.png'  # Replace with your output path
    decrypt_image(encrypted_image_path, key, iv, decrypted_image_path)
    print(f"Decrypted image saved to: {decrypted_image_path}")
