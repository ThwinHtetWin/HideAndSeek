import cv2
import numpy as np
import os
from tqdm import tqdm
from cryptography.fernet import Fernet

BGreen="\033[1;32m"       # Green
reset="\u001b[0m"         # Default 

def main(): 

    print("""
    {c}H I D E & S E E K - Presented By Group-2
    ----------------------------------------
    """.format(c=BGreen))

    print("""
{g}[ HIDE ]{reset}  Enter ( 1 ) to Hide the data in the image
{g}[ SEEK ]{reset}  Enter ( 2 ) to Reveal the data from the encoded image\n""".format(g=BGreen,reset=reset))
    a = int(input("Hide/Seek : "))
    if(a==1):  
        img_enc()
    elif(a==2):
        img_dec()
    else:
        print("Please enter 1 or 2 .")
        exit()


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
    print("[{g}RESULT{reset}] Please wait for 1 minute.\n[{g}RESULT{reset}] Decoding image to retrieve the encrypted data...".format(g=BGreen,reset=reset))
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
    print("-"*60)
    print("{g}Access key : ".format(g=BGreen),reset,clean_key)
    print("[{g}Note{reset}] Keep this key in a safe place ! {g}[!]".format(reset=reset,g=BGreen))
    print("-"*60,reset)
    fernet=Fernet(key)

    secret_data = input("[{g}TODO{reset}]   Enter your message(data) : ".format(g=BGreen,reset=reset)).encode("utf-8")
    encoded=fernet.encrypt(secret_data)
    clean_encoded_msg = encoded.decode('utf-8')
    print("[{g}RESULT{reset}] Encrypted data           :".format(g=BGreen,reset=reset),clean_encoded_msg)
    input_image = input("[{g}TODO{reset}]   Enter your image         : ".format(g=BGreen,reset=reset))
        # split the absolute path and the file
    path, file = os.path.split(input_image)
        # split the filename and the image extension
    filename, ext = file.split(".")
    output_image = os.path.join(path, f"{filename}_encoded.{ext}")
    encoded_image = encode(image_name=input_image, secret_data=secret_data)       
    cv2.imwrite(output_image, encoded_image)
    print("[{g}RESULT{reset}] Saved encoded image      : ".format(g=BGreen,reset=reset),output_image,'\n')

def img_dec():
    print("-"*60)
    to_decode = input("[{g}TODO{reset}]   Enter your encoded image : ".format(g=BGreen,reset=reset))

    decoded_data = decode(to_decode)
    print("-"*60)
    print("[{g}RESULT{reset}] Decoded data     :".format(g=BGreen,reset=reset),decoded_data)
    key=input("[{g}TODO{reset}]   Enter access key : ".format(g=BGreen,reset=reset)).encode()
    f=Fernet(key)

    decoded_data=decoded_data.encode()
    decrypt = f.decrypt(decoded_data)
    clean_decrypt = decrypt.decode('utf-8')
    print("[{g}RESULT{reset}] Decrypted data   :".format(g=BGreen,reset=reset),clean_decrypt)

#Here we goooo!!!
main()  
