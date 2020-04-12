from DES import DES_decrypter, DES_encrypter
import re
import time
import os
from operations import bin2string


global key, iv
with open("des_key.txt") as f:
    key = f.readlines()
    key = [x.strip() for x in key if x.strip() != ''] 
f.close()
key = "".join(key)
with open("des_vi.txt") as f:
    iv = f.readlines()
    iv = [x.strip() for x in iv if x.strip() != '']
f.close()
iv = "".join(iv)


def test1():
    """验证正确加密实验   
       从des_plain.txt中读取明文通过4种加密方式加密后写入des_cipher.txt中
       DES加密密钥从des_key.txt中获取
       CBC\CFB\OFB的初始iv向量从des_iv.txt中获取
    """
    with open("des_plain.txt") as f:
        plaintext = f.readlines()
        plaintext = [x.strip() for x in plaintext if x.strip() != '']
    f.close()
    plaintext = "".join(plaintext)
    
    ECBcrypter = DES_encrypter(plaintext, key, "ECB", iv)
    cipher_ECB = ECBcrypter.ciphertext

    CBCcrypter = DES_encrypter(plaintext, key, "CBC", iv)
    cipher_CBC = CBCcrypter.ciphertext

    CFBcrypter = DES_encrypter(plaintext, key, "CFB", iv)
    cipher_CFB = CFBcrypter.ciphertext

    OFBcrypter = DES_encrypter(plaintext, key, "OFB", iv)
    cipher_OFB = OFBcrypter.ciphertext

    with open("des_cipher.txt", "a") as f:
        f.write("\ntest1加密正确性验证实验结果:\n")
        f.write("cipher_ECB:"+cipher_ECB.upper+"\n")
        f.write("cipher_CBC:"+cipher_CBC.upper+"\n")
        f.write("cipher_CFB:"+cipher_CFB.upper+"\n")
        f.write("cipher_OFB:"+cipher_OFB.upper+"\n")
    f.close()


def test2():
    """验证正确解密实验
       将des_cipher.txt中的密文进行解密然后输出到des_plain.txt中
    """
    with open("des_cipher.txt") as f:
        ECB_cipher = f.readline().rstrip("\n")
        ECB_cipher = re.sub(r'^.*:', "", ECB_cipher)

        CBC_cipher = f.readline().rstrip("\n")
        CBC_cipher = re.sub(r'^.*:', "", CBC_cipher)

        CFB_cipher = f.readline().rstrip("\n")
        CFB_cipher = re.sub(r'^.*:', "", CFB_cipher)
        
        OFB_cipher = f.readline().rstrip("\n")
        OFB_cipher = re.sub(r'^.*:', "", OFB_cipher)
    f.close

    ECBcrypter = DES_decrypter(ECB_cipher, key, "ECB", iv)
    plaintext_ECB = ECBcrypter.plaintext

    CBCcrypter = DES_decrypter(CBC_cipher, key, "CBC", iv)
    plaintext_CBC = CBCcrypter.plaintext

    CFBcrypter = DES_decrypter(CFB_cipher, key, "CFB", iv)
    plaintext_CFB = CFBcrypter.plaintext

    OFBcrypter = DES_decrypter(OFB_cipher, key, "OFB", iv)
    plaintext_OFB = OFBcrypter.plaintext

    with open("des_plain.txt", "a") as f:
        f.write("\ntest2解密正确性验证实验结果:\n")
        f.write("plaintext_ECB:"+plaintext_ECB+"\n")
        f.write("plaintext_CBC:"+plaintext_CBC+"\n")
        f.write("plaintext_CFB:"+plaintext_CFB+"\n")
        f.write("plaintext_OFB:"+plaintext_OFB+"\n")
    f.close()


def test3():
    """四种方式加密记时实验
       使用四种方式加密随机生成的8KB数据并记时
       从random_data.txt中读取数据作为要加密的明文加密并输出到random_cipher.txt中
    """
    encodetimes = {"ECB_encodetime": [], "CBC_encodetime": [], "CFB_encodetime": [], "OFB_encodetime": []}
    encodespeeds = {"ECB_speeds": [], "CBC_speeds": [], "CFB_speeds": [], "OFB_speeds": []}
    for i in range(20):
        generateTXTFile()

        with open("random_data.txt") as f:
            plaintext = f.readlines()
            plaintext = [x.strip() for x in plaintext]
        f.close()
        plaintext = "".join(plaintext)

        print("正在进行第 " + str(i) + " 轮ECB加密...\n")
        start = time.time()
        ECBcrypter = DES_encrypter(plaintext, key, "ECB", iv)
        cipher_ECB = ECBcrypter.ciphertext
        end_ECB = time.time() - start
        speed_ECB = 8 / end_ECB
        encodetimes["ECB_encodetime"].append(end_ECB)
        encodespeeds["ECB_speeds"].append(speed_ECB)

        print("正在进行第 " + str(i) + " 轮CBC加密...\n")
        start = time.time()
        CBCcrypter = DES_encrypter(plaintext, key, "CBC", iv)
        cipher_CBC = CBCcrypter.ciphertext
        end_CBC = time.time() - start
        speed_CBC = 8 / end_CBC
        encodetimes["CBC_encodetime"].append(end_CBC)
        encodespeeds["CBC_speeds"].append(speed_CBC)

        print("正在进行第 " + str(i) + " 轮CFB加密...\n")
        start = time.time()
        CFBcrypter = DES_encrypter(plaintext, key, "CFB", iv)
        cipher_CFB = CFBcrypter.ciphertext
        end_CFB = time.time() - start
        speed_CFB = 8 / end_CFB
        encodetimes["CFB_encodetime"].append(end_CFB)
        encodespeeds["CFB_speeds"].append(speed_CFB) 

        print("正在进行第 " + str(i) + " 轮OFB加密...\n")
        start = time.time()
        OFBcrypter = DES_encrypter(plaintext, key, "OFB", iv)
        cipher_OFB = OFBcrypter.ciphertext
        end_OFB = time.time() - start
        speed_OFB = 8 / end_OFB
        encodetimes["OFB_encodetime"].append(end_OFB)
        encodespeeds["OFB_speeds"].append(speed_OFB)
    
    # 求平均
    encodetimes["ECB_encodetime"].append(sum(encodetimes["ECB_encodetime"]) / 20)
    encodetimes["CBC_encodetime"].append(sum(encodetimes["CBC_encodetime"]) / 20)
    encodetimes["CFB_encodetime"].append(sum(encodetimes["CFB_encodetime"]) / 20)
    encodetimes["OFB_encodetime"].append(sum(encodetimes["OFB_encodetime"]) / 20)
    encodespeeds["ECB_speeds"].append(sum(encodespeeds["ECB_speeds"]) / 20)
    encodespeeds["CBC_speeds"].append(sum(encodespeeds["CBC_speeds"]) / 20)
    encodespeeds["CFB_speeds"].append(sum(encodespeeds["CFB_speeds"]) / 20)
    encodespeeds["OFB_speeds"].append(sum(encodespeeds["OFB_speeds"]) / 20)

    with open("text3_result.txt", "a") as f:
        f.write("average cipher_ECB speed is " + str(encodespeeds["ECB_speeds"][-1]) + "KB/S \n")
        f.write("the average cost of time is " + str(encodetimes["ECB_encodetime"][-1]) + "S\n\n")
        f.write("average cipher_CBC speed is " + str(encodespeeds["CBC_speeds"][-1]) + "KB/S\n")
        f.write("the average cost of time is " + str(encodetimes["CBC_encodetime"][-1]) + "S\n\n")
        f.write("average cipher_CFB speed is " + str(encodespeeds["CFB_speeds"][-1]) + "KB/S\n")
        f.write("the average cost of time is " + str(encodetimes["CFB_encodetime"][-1]) + "S\n\n")
        f.write("average cipher_OFB speed is " + str(encodespeeds["OFB_speeds"][-1]) + "KB/S\n")
        f.write("the average cost of time is " + str(encodetimes["OFB_encodetime"][-1]) + "S\n\n")
    f.close()


def test4():
    """四种方式解密记时实验
       使用四种方式解密随机生成的8KB数据并记时
       从random_data.txt中读取数据作为要解密的密文解密并输出到random_plaintext.txt中
    """
    decodetimes = {"ECB_decodetime": [], "CBC_decodetime": [], "CFB_decodetime": [], "OFB_decodetime": []}
    decodespeeds = {"ECB_speeds": [], "CBC_speeds": [], "CFB_speeds": [], "OFB_speeds": []}
    for i in range(20):
        generateTXTFile()

        with open("random_data.txt") as f:
            plaintext = f.readlines()
            plaintext = [x.strip() for x in plaintext]
        f.close()
        plaintext = "".join(plaintext)

        print("正在进行第 " + str(i) + " 轮ECB解密...\n")
        start = time.time()
        ECBcrypter = DES_decrypter(plaintext, key, "ECB", iv)
        plain_ECB = ECBcrypter.plaintext
        end_ECB = time.time() - start
        speed_ECB = 8 / end_ECB
        decodetimes["ECB_decodetime"].append(end_ECB)
        decodespeeds["ECB_speeds"].append(speed_ECB)

        print("正在进行第 " + str(i) + " 轮CBC解密...\n")
        start = time.time()
        CBCcrypter = DES_decrypter(plaintext, key, "CBC", iv)
        plain_CBC = CBCcrypter.plaintext
        end_CBC = time.time() - start
        speed_CBC = 8 / end_CBC
        decodetimes["CBC_decodetime"].append(end_CBC)
        decodespeeds["CBC_speeds"].append(speed_CBC)

        print("正在进行第 " + str(i) + " 轮CFB解密...\n")
        start = time.time()
        CFBcrypter = DES_decrypter(plaintext, key, "CFB", iv)
        plain_CFB = CFBcrypter.plaintext
        end_CFB = time.time() - start
        speed_CFB = 8 / end_CFB
        decodetimes["CFB_decodetime"].append(end_CFB)
        decodespeeds["CFB_speeds"].append(speed_CFB) 

        print("正在进行第 " + str(i) + " 轮OFB解密...\n")
        start = time.time()
        OFBcrypter = DES_decrypter(plaintext, key, "OFB", iv)
        plain_OFB = OFBcrypter.plaintext
        end_OFB = time.time() - start
        speed_OFB = 8 / end_OFB
        decodetimes["OFB_decodetime"].append(end_OFB)
        decodespeeds["OFB_speeds"].append(speed_OFB)

    # 求平均
    decodetimes["ECB_decodetime"].append(sum(decodetimes["ECB_decodetime"]) / 20)
    decodetimes["CBC_decodetime"].append(sum(decodetimes["CBC_decodetime"]) / 20)
    decodetimes["CFB_decodetime"].append(sum(decodetimes["CFB_decodetime"]) / 20)
    decodetimes["OFB_decodetime"].append(sum(decodetimes["OFB_decodetime"]) / 20)
    decodespeeds["ECB_speeds"].append(sum(decodespeeds["ECB_speeds"]) / 20)
    decodespeeds["CBC_speeds"].append(sum(decodespeeds["CBC_speeds"]) / 20)
    decodespeeds["CFB_speeds"].append(sum(decodespeeds["CFB_speeds"]) / 20)
    decodespeeds["OFB_speeds"].append(sum(decodespeeds["OFB_speeds"]) / 20)

    with open("text4_result.txt", "a") as f:
        f.write("average decode_ECB speed is " + str(decodespeeds["ECB_speeds"][-1]) + "KB/S \n")
        f.write("the average cost of time is " + str(decodetimes["ECB_decodetime"][-1]) + "S\n\n")
        f.write("average decode_CBC speed is " + str(decodespeeds["CBC_speeds"][-1]) + "KB/S\n")
        f.write("the average cost of time is " + str(decodetimes["CBC_decodetime"][-1]) + "S\n\n")
        f.write("average decode_CFB speed is " + str(decodespeeds["CFB_speeds"][-1]) + "KB/S\n")
        f.write("the average cost of time is " + str(decodetimes["CFB_decodetime"][-1]) + "S\n\n")
        f.write("average decode_OFB speed is " + str(decodespeeds["OFB_speeds"][-1]) + "KB/S\n")
        f.write("the average cost of time is " + str(decodetimes["OFB_decodetime"][-1]) + "S\n\n")
    f.close()


def generateTXTFile():
    try:
        filesize = 8 * 1024
        while True:
            content = bin(int.from_bytes(os.urandom(filesize), byteorder='big', signed=False))
            content = bin2string(content[2:])
            if((len(content) % 64) == 0):
                break
            else:
                print("生成的content不符合要求！\n重新生成中...\n")
        with open("random_data.txt", "w") as f:
            f.write(content)
        f.close
    except TypeError:
        generateTXTFile()  # 由于urandom的不确定性，当捕捉到content一些内容异常时，重新生成content


if __name__ == "__main__":
    # test1()
    # test2()
    test3()
    test4()
