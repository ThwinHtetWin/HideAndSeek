import os
import cv2
import magic
import numpy as np
from PIL import Image
from cryptography.fernet import Fernet

Cyan="\033[0;36m"
Green="\033[1;32m"       
Red="\u001b[31m"         
Yellow="\033[0;33m"
reset="\u001b[0m"

def checkpoint(rawfile):
    is_exist=os.path.exists(rawfile)
    if is_exist==True:

        print(f"[ {Green}RESULT{reset} ] Input file [{Green} {rawfile} {reset}] exists.")

        file_type = magic.from_file(rawfile,mime=True)

        if file_type == "image/png":
            print(f"[ {Green}RESULT{reset} ] This is PNG image file.")

            handle_img=Image.open(rawfile).convert("RGB")
            filename=rawfile.split(".")[0]
            handle_img.save(f"{filename}.png","png")
            handle_img.close()
            final_img_name=f"{filename}.png"

        elif file_type == "image/jpg" or file_type == "image/jpeg":
            convert=input(f"\n       {Yellow}[!]{reset} This is JPG/JPEG image file.Do u want to convert this JPG/JPEG to PNG file? [{Yellow} y/n {reset}] : ").lower()
            print("")
            
            if convert=="y":
                handle_img=Image.open(rawfile).convert("RGB")
                filename=rawfile.split(".")[0]
                handle_img.save(f"{filename}.png","png")
                handle_img.close()
                final_img_name=f"{filename}.png"

                print(f"[ {Green}RESULT{reset} ] Created {final_img_name}")

            elif convert=="n":
                print("Goodbye.")
                exit()
        else:
            print(f"[ {Red}RESULT{reset} ] Sorry.We only accept PNG and JPG/JPEG file.")
            exit()
    else:
        print(f"[ {Red}RESULT{reset} ] File doesn't exist.")
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
        raise TypeError(f"[ {Red}ERROR{reset} ] Type not supported.")

def data_encryption():
     
    generate = input(f"[ {Yellow}TODO{reset} ]   Generate new key (must generate new key if u are first time user) : [ {Yellow}y/n{reset} ]").lower()
    if generate == "y":
        key = Fernet.generate_key()
        clean_key = key.decode('utf-8')
        print("-"*60,
          f"\n{Green}Access key : {reset}{clean_key}")
        f=open("access.key","w")
        f.write(clean_key)
        f.write("\n[!] Keep this key in a safe place.\n")
        f.close()
        print(f"[ {Green}RESULT{reset} ] Access Key is saved as [{Green} access.key {reset}] !")
        print("-"*60)

    elif generate == "n":
        key = input(f"[ {Yellow}TODO{reset} ]   Enter key : ").encode()
        pass
    else:
            print(f"[ {Red}ERROR{reset} ] You must choose one option to encrypt the data.")

    fernet=Fernet(key)

    secret_data = input(f"[ {Yellow}TODO{reset} ]   Enter your message(data) : ").encode("utf-8")
    clean_encoded_msg = fernet.encrypt(secret_data).decode('utf-8')
    print(f"[ {Green}RESULT{reset} ] Encrypted data           : {clean_encoded_msg}")

    # add stop sign
    clean_encoded_msg += "##THW##"
    binary_secret_data = to_bin(clean_encoded_msg)

    return binary_secret_data

def image_encode():
    print(f"\n{Green}-- Initial Checkpoint --{reset}\n")

    rawfile = input(f"[ {Yellow}TODO{reset} ]   Enter Image : ")
    final_img_name=checkpoint(rawfile)

    path, file = os.path.split(final_img_name)
    filename, ext = file.split(".")
    output_image = os.path.join(path, f"{filename}_encoded.{ext}")

    image = cv2.imread(final_img_name)
    image_size = image.shape[0] * image.shape[1] * 3 // 8

    binary_secret_data=data_encryption()
    binary_secret_data_size = len(binary_secret_data)
    
    if binary_secret_data_size > image_size:
        raise ValueError("[ {Red}ERROR{reset} ] Insufficient bytes, need bigger image or less data.")

    data_index = 0
    for row in image:
        for pixel in row: #type(pixel)=<class 'numpy.ndarray'>
            # convert RGB values to binary format
            r, g, b = to_bin(pixel)
            if data_index < binary_secret_data_size:
                pixel[0] = int(r[:-1] + binary_secret_data[data_index], 2)
                data_index += 1
            if data_index < binary_secret_data_size:
                pixel[1] = int(g[:-1] + binary_secret_data[data_index], 2)
                data_index += 1
            if data_index < binary_secret_data_size:
                pixel[2] = int(b[:-1] + binary_secret_data[data_index], 2)
                data_index += 1
            if data_index >= binary_secret_data_size:
                break

    cv2.imwrite(output_image,image)
    print(f"[ {Green}RESULT{reset} ] Saved encoded image      : {output_image}\n")

def image_decode():
    print("-"*60)
    to_decode = input(f"[ {Yellow}TODO{reset} ]   Enter your encoded image : ")
    is_exist=os.path.exists(to_decode)
    if is_exist==True:
        pass
    else:
        print(f"[ {Red}RESULT{reset} ] File doesn't exist.")
        exit()

    decoded_data = data_decryption(to_decode)
    print("-"*60)
    print(f"[ {Green}RESULT{reset} ] Decoded data     : {decoded_data}")
    key=input(f"[ {Yellow}TODO{reset} ]   Enter access key : ").encode()
    f=Fernet(key)

    decoded_data=decoded_data.encode()
    decrypt = f.decrypt(decoded_data)
    clean_decrypt = decrypt.decode('utf-8')
    print(f"[ {Green}RESULT{reset} ] Decrypted data   : {clean_decrypt}\n")

def data_decryption(image_name):
    print(f"[ {Green}RESULT{reset} ] Decoding image to retrieve the encrypted data.Please wait.")
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
    decoded_data = ""
    for byte in all_bytes:
        decoded_data += chr(int(byte, 2))
        if decoded_data[-7:] == "##THW##":
            break
    return decoded_data[:-7]

def main(): 
    
    banner = f"""{Cyan}
    H I D E & S E E K  
   {Yellow}-------------------[ developed by ZuS ]{reset}
   {reset}"""
    
    print(banner)
    print(f"[ {Green}HIDE{reset} ] : Enter [ 1 ] to Hide the data in the image.\n[ {Green}SEEK{reset} ] : Enter [ 2 ] to Reveal the data from the encoded image.\n")

    a = int(input("[ Hide/Seek ] : "))
    if(a==1): 
        image_encode()
    elif(a==2):
        image_decode()
    else:
        print(f"[ {Red}ERROR{reset} ] Please enter 1 or 2.")
        exit()

#Here we goooo!!!
if __name__ == '__main__':
    main()
