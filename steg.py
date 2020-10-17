import os
import cv2
import magic
import numpy as np
from PIL import Image
from cryptography.fernet import Fernet

Green="\033[1;32m"       
Red="\u001b[31m"         
Yellow="\033[0;33m"
reset="\u001b[0m"       

def main(): 

    print(f"""
    {Green}H I D E & S E E K 
    ------------------------
    """)

    print(f"{Green}[ HIDE ]{reset}  Enter ( 1 ) to Hide the data in the image\n{Green}[ SEEK ]{reset}  Enter ( 2 ) to Reveal the data from the encoded image\n")

    a = int(input("Hide/Seek : "))
    if(a==1):  
        img_enc()
    elif(a==2):
        img_dec()
    else:
        print(f"{Red}[ERROR]{reset} Please enter 1 or 2.")
        exit()

def checkpoint(rawfile):

    global final_img_name

    is_exist=os.path.exists(rawfile)
    if is_exist==True:

        print(f"{Green}[RESULT]{reset} Input file [{Green} {rawfile} {reset}] exists.")

        file_type = magic.from_file(rawfile,mime=True)

        if file_type == "image/png":
            print(f"{Green}[RESULT]{reset} This is PNG image file.")

            handle_img=Image.open(rawfile).convert("RGB")
            filename=rawfile.split(".")[0]
            handle_img.save(f"{filename}.png","png")
            handle_img.close()
            final_img_name=f"{filename}.png"

        elif file_type == "image/jpg" or "image/jpeg":
            convert=input(f"{Yellow}[!]{reset} This is JPG/JPEG image file.Do u want to convert this JPG/JPEG to PNG file? [{Yellow} y/n {reset}] : ").lower()
            
            if convert=="y":
                handle_img=Image.open(rawfile).convert("RGB")
                filename=rawfile.split(".")[0]
                handle_img.save(f"{filename}.png","png")
                handle_img.close()
                final_img_name=f"{filename}.png"

                print(f"{Green}[RESULT]{reset} Created {final_img_name}")

            elif convert=="n":
                print("Goodbye.")
                exit()
        else:
            print("[{}!{}] Sorry.We only accept PNG and JPG/JPEG file.")
            exit()
    else:
        print("File doesn't exist.")
        exit()
        return final_img_name

def to_bin(data):

    if isinstance(data, str):
        return ''.join([ format(ord(i), "08b") for i in data ])
    elif isinstance(data, bytes) or isinstance(data, np.ndarray):
        return [ format(i, "08b") for i in data ]
    elif isinstance(data, int) or isinstance(data, np.uint8):
        return format(data, "08b")
    else:
        raise TypeError(f"{Red}[ERROR]{reset} Type not supported.")

def encode(image_name, secret_data):

    global clean_encoded_msg
    image = cv2.imread(image_name)
    # maximum bytes to encode
    n_bytes = image.shape[0] * image.shape[1] * 3 // 8
    if len(secret_data) > n_bytes:
        raise ValueError("{Red}[ERROR]{reset} Insufficient bytes, need bigger image or less data.")
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
    print(f"[{Green}RESULT{reset}] Please wait...\n[{Green}RESULT{reset}] Decoding image to retrieve the encrypted data...")
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

    print(f"{Green}[ Initial Checkpoint ]{reset}\n")
    rawfile = input(f"{Yellow}[TODO]{reset}   Enter Image : ")
    checkpoint(rawfile)
        # split the absolute path and the file
    path, file = os.path.split(final_img_name)
        # split the filename and the image extension
    filename, ext = file.split(".")
    output_image = os.path.join(path, f"{filename}_encoded.{ext}")

    key=Fernet.generate_key()
    clean_key = key.decode('utf-8')

    print("-"*60,
          f"\n{Green}Access key : {reset}{clean_key}")
    f=open("access.key","w")
    f.write(clean_key)
    f.write("\n[!] Keep this key in a safe place.\n")
    f.close()
    print(f"[{Green}RESULT{reset}] Access Key is saved as [{Green} access.key {reset}] !")
    print("-"*60)

    fernet=Fernet(key)

    secret_data = input(f"[{Yellow}TODO{reset}]   Enter your message(data) : ").encode("utf-8")
    encoded=fernet.encrypt(secret_data)
    clean_encoded_msg = encoded.decode('utf-8')
    print(f"[{Green}RESULT{reset}] Encrypted data           : {clean_encoded_msg}")
    
    encoded_image = encode(image_name=final_img_name, secret_data=secret_data)       
    cv2.imwrite(output_image, encoded_image)
    print(f"[{Green}RESULT{reset}] Saved encoded image      : {output_image}\n")

def img_dec():
    print("-"*60)
    to_decode = input(f"[{Yellow}TODO{reset}]   Enter your encoded image : ")

    decoded_data = decode(to_decode)
    print("-"*60)
    print(f"[{Green}RESULT{reset}] Decoded data     : {decoded_data}")
    key=input(f"[{Yellow}TODO{reset}]   Enter access key : ").encode()
    f=Fernet(key)

    decoded_data=decoded_data.encode()
    decrypt = f.decrypt(decoded_data)
    clean_decrypt = decrypt.decode('utf-8')
    print(f"[{Green}RESULT{reset}] Decrypted data   : {clean_decrypt}")

#Here we goooo!!!
main()
