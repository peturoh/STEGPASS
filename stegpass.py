import cv2
import base64
import pwinput
import sys
import re
from tkinter import filedialog, Tk
from Crypto.Cipher import AES
from Crypto import Random
import hashlib


class CustomAESCipher:
    # Standard AES Cipher class with encryption and padding functionalities using master password as KEY.
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()
    
    # Encryption function to encrypt the data
    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode())).decode('utf-8')
    
    # Decryption function to decrypt the data
    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
    
    # Padding function to fit the data in the block size of AES
    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
    
    # Unpadding function to remove the padding after decryption
    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]


def embed_message(image_path, message, output_path, gap=10):
    # Encode the message to base64
    message_encoded = base64.b64encode(message.encode()).decode('utf-8')
    
    # Convert the length of the encoded data directly to binary
    length_binary = format(len(message_encoded), '032b')  # 32 bits for message length
    
    # Convert the message to binary and concatenate the length binary and message binary
    full_message_binary = length_binary + ''.join(format(ord(c), '08b') for c in message_encoded)
    
    # Read the image data
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Image at {image_path} not found.")
    
    # Check if the message can be embedded into the image by checking the length of image data
    if len(full_message_binary) > (img.shape[0] * img.shape[1] // gap) * 8:
        raise ValueError("Message too long after encoding.")
    
    # Embed message bit into the least significant bit of the blue channel of the pixel data
    # by clearing the least significant bit and setting it to the message bit.
    for bit_index, bit in enumerate(full_message_binary):
        row = (bit_index * gap) // img.shape[1]
        col = (bit_index * gap) % img.shape[1]
        if row >= img.shape[0] or col >= img.shape[1]:
            break

        img[row, col, 0] = (img[row, col, 0] & ~1) | int(bit)
    
    # Save the image with the embedded message
    cv2.imwrite(output_path, img)



def extract_message(image_path, gap=10):
    # Read the image data
    img = cv2.imread(image_path)

    # Check if the image exists
    if img is None:
        raise FileNotFoundError(f"Image at {image_path} not found.")

    # Calculate the total number of bits that can be read from the image
    total_bits = (img.shape[0] * img.shape[1]) // gap

    # Extract the length of the message from the first 32 bits
    length_bits = []
    for i in range(32):  # First 32 bits for the length
        if i >= total_bits:
            raise ValueError("Image does not contain enough data.")
        row, col = (i * gap) // img.shape[1], (i * gap) % img.shape[1]
        length_bits.append(str(img[row, col, 0] & 1))

    # Convert the length bits to an integer
    message_length = int(''.join(length_bits), 2)

    # Extract the message bits from the least significant bit of the blue channel of the image data
    message_bits = []
    for i in range(32, 32 + message_length * 8):  # Offset by 32 bits for the length
        if i >= total_bits:
            message_decoded = ""
            return message_decoded
        row, col = (i * gap) // img.shape[1], (i * gap) % img.shape[1]
        message_bits.append(str(img[row, col, 0] & 1))

    # Convert the message bits to a string
    message_bin = ''.join(message_bits)
    message_encoded = ''.join([chr(int(message_bin[i:i+8], 2)) for i in range(0, len(message_bin), 8)])
    message_decoded = base64.b64decode(message_encoded).decode('utf-8')
    
    # Return the decoded message
    return message_decoded


def openFile():
    filepath = filedialog.askopenfilename(title="Select an Image",
                                          filetypes=[("PNG Files", "*.png")])
    return filepath


def print_ascii_art():
    ascii_art = r"""
     _____ _______ ______ _____ _____         _____ _____ 
    / ____|__   __|  ____/ ____|  __ \ /\    / ____/ ____|
    | (___   | |  | |__ | |  __| |__) /  \  | (___| (___  
    \___ \   | |  |  __|| | |_ |  ___/ /\ \  \___  \___ \ 
    ____) |  | |  | |___| |__| | |  / ____ \ ____) |___) |
    |_____/  |_|  |______\_____|_| /_/    \_\_____/_____/ 
    """
    print(ascii_art)

def check_password_strength(password):
    # Checking the password strength based on various criteria
    criteria = [
        lambda s: any(x.islower() for x in s), # Lowercase check
        lambda s: any(x.isupper() for x in s), # Uppercase check
        lambda s: any(x.isdigit() for x in s), # Digit check
        lambda s: len(s) >= 10, # Length check
        lambda s: re.search("[!@#$%^&*(),.?\":{}|<>]", s) is not None  # Special char check.
    ]
    
    score = sum(map(lambda criterion: criterion(password), criteria)) # Calculate the score based on criteria
    
    strength = "Very Weak"
    if score >= 4:
        strength = "Strong"
    elif score >= 3:
        strength = "Moderate"
    
    return strength, score

def main():
    Tk().withdraw() # To avoid the full GUI but access filedialog still.
    
    if len(sys.argv) != 2 or sys.argv[1] not in ['-e', '-d']:
        print("Usage: python stegpass.py -e to encode | -d to decode")
        sys.exit(1)

    if sys.argv[1] == '-e':
        # Encode mode
        image_path = openFile() # Open the file dialog to select an image
        service_name = input("What service is this password for?: ") # Get the service name
        master_password = pwinput.pwinput("Please enter your Master Password: ") # Get the master password
        
        while True:
            password = pwinput.pwinput(prompt="Enter the password to embed: ") # Get the password to embed
            confirm_password = pwinput.pwinput(prompt="Confirm your password: ") # Confirm the password
            
            if password == confirm_password: # Check if the passwords match
                strength, score = check_password_strength(password) # Check the password strength
                print(f"Password Strength: {strength} ({score}/5)")
                
                if strength == "Very Weak": # Issue a warning for very weak passwords
                    print("Warning: You have chosen a very weak password. Consider using a stronger one for better security.")
                    print("As a recommendation, use a password with at least 10 characters, including uppercase, lowercase, digits, and special characters.")
                    try_again = input("Would you like to enter a different password? (y/n): ").lower()
                    if try_again == "n":
                        break  # Proceed with caution
                else:
                    break
            else:
                print("Passwords do not match. Please try again.")
        
        aes_cipher = CustomAESCipher(master_password) # Create an AES cipher with the master password
        encrypted_password = aes_cipher.encrypt(password) # Encrypt the password
        output_path = f"{service_name}_stego.png" # Output path for the steganography image
        embed_message(image_path, encrypted_password, output_path, gap=10) # Embed the encrypted password into the image
        print(f"Password embedded into {output_path}")
        
    elif sys.argv[1] == '-d':
        # Decode mode
        image_path = openFile() # Open the file dialog to select an image
        master_password = pwinput.pwinput("Please enter your Master Password: ") # Get the master password
        aes_cipher = CustomAESCipher(master_password) # Create an AES cipher with the master password
        
        extracted_encrypted = extract_message(image_path, gap=10) # Extract the encrypted password from the image
        try:
            extracted_password = aes_cipher.decrypt(extracted_encrypted) # Decrypt the extracted password
            if not extracted_password: # Check if the extracted password is blank
                print("Warning: The extracted password is blank. Please make sure the master password is correct and try again.")
            else: # Print the extracted password
                print("Extracted Password:", extracted_password)
        except Exception as e: # Handle decryption errors
            print("An error occurred during decryption. Please make sure the master password is correct and try again.")



if __name__ == "__main__":
    main()

