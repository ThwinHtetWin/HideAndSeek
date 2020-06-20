import cv2
import numpy as np
import os
from cryptography.fernet import Fernet
from colorama import init
init()

green = "\033[1;32m"
end   = "\033[0;0m"
def main(): 

    print(green+"                        [:: Steganography tool using LSB Method - "
        "Presented by Group(2) ::]\n"+end)
    a = int(input("\n=>  Enter ( 1 ) to Hide the data in the image\n"
                    "=>  Enter ( 2 ) to Reveal the data from the encoded image : ")) 
    if (a == 1): 
        img_enc()
        
    elif (a == 2): 
        img_dec()
    else: 
        raise Exception("Enter correct input please!") 


def to_bin(data):

    if isinstance(data, str):
        return ''.join([ format(ord(i), "08b") for i in data ])
    elif isinstance(data, bytes) or isinstance(data, np.ndarray):
        return [ format(i, "08b") for i in data ]
    elif isinstance(data, int) or isinstance(data, np.uint8):
        return format(data, "08b")
    else:
        raise TypeError("Type not supported.")

def encode(image_name, secret_data):

    global clean_encoded_msg
    image = cv2.imread(image_name)
    # maximum bytes to encode
    n_bytes = image.shape[0] * image.shape[1] * 3 // 8
    if len(secret_data) > n_bytes:
        raise ValueError("[!] Insufficient bytes, need bigger image or less data.")
    # add stop sign
    clean_encoded_msg += "stop"
    data_index = 0
    binary_secret_data = to_bin(clean_encoded_msg)
    data_len = len(binary_secret_data)
    
    for row in image:
        for pixel in row:
            # convert RGB values to binary format
            r, g, b = to_bin(pixel)
            if data_index < data_len:
                pixel[0] = int(r[:-1] + binary_secret_data[data_index], 2)
                data_index += 1
            if data_index < data_len:
                pixel[1] = int(g[:-1] + binary_secret_data[data_index], 2)
                data_index += 1
            if data_index < data_len:
                pixel[2] = int(b[:-1] + binary_secret_data[data_index], 2)
                data_index += 1
            if data_index >= data_len:
                break
    return image

def decode(image_name):
    print("["+green+"!"+end+"] Please wait for 1 minute.\n["+green+"*"+end+"] Decoding image to retrieve the encrypted data...")
    image = cv2.imread(image_name)
    binary_data = ""
    for row in image:
        for pixel in row:
            r, g, b = to_bin(pixel)
            binary_data += r[-1]
            binary_data += g[-1]
            binary_data += b[-1]

    # split by 8-bits
    all_bytes = [ binary_data[i: i+8] for i in range(0, len(binary_data), 8) ]
    # convert from bits to characters
    decoded_data = ""
    for byte in all_bytes:
        decoded_data += chr(int(byte, 2))
        if decoded_data[-4:] == "stop":
            break
    return decoded_data[:-4]


def img_enc():
    global clean_encoded_msg
    key=Fernet.generate_key()
    clean_key = key.decode('utf-8')
    print("--------------------------------------------------------------")
    print(green+"Access key : ",clean_key+end)
    print("["+green+"!"+end+"] Keep this key in a safe place !\n--------------------------------------------------------------")
    fernet=Fernet(key)

    secret_data = input("["+green+"+"+end+"] Enter your message(data) : ").encode("utf-8")
    encoded=fernet.encrypt(secret_data)
    clean_encoded_msg = encoded.decode('utf-8')
    print("["+green+"*"+end+"]"+green+" Encrypted data           "+end+":",clean_encoded_msg,"\n")

        
    input_image = input("["+green+"*"+end+"] Enter your image         : ")
        # split the absolute path and the file
    path, file = os.path.split(input_image)
        # split the filename and the image extension
    filename, ext = file.split(".")
    output_image = os.path.join(path, f"{filename}_encoded.{ext}")
    encoded_image = encode(image_name=input_image, secret_data=secret_data)       
    cv2.imwrite(output_image, encoded_image)
    print("["+green+"*"+end+"]"+green+" Saved encoded image      : "+end+output_image,'\n')

def img_dec():
    print("--------------------------------------------------------------")
    to_decode = input("["+green+"+"+end+"] Enter your encoded image : ")

    decoded_data = decode(to_decode)
    print("\n--------------------------------------------------------------")
    print("["+green+"+"+end+"] Decoded data     :",decoded_data)
    key=input("["+green+"+"+end+"] Enter access key : ").encode()
    f=Fernet(key)

    decoded_data=decoded_data.encode()
    decrypt = f.decrypt(decoded_data)
    clean_decrypt = decrypt.decode('utf-8')
    print("\n["+green+"*"+end+"]"+green+" Decrypted data   "+end+":",clean_decrypt)

if __name__ == '__main__' : 
    
    main()  
