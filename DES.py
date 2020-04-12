# -*- coding: UTF-8 -*-

from operations import IpPermutation, InverseIpPermutation, ExtendPermutation, \
                      CreateSubKeys, SBoxPermutation, PBoxPermutation, \
                      string2bin, bin2string, xor


def cipher(message, key, mode='encrypt'):

    subkeys = CreateSubKeys(key) if mode == 'encrypt' else CreateSubKeys(key)[::-1]  # 顺序相反取密钥
    text = IpPermutation(message)

    for i in range(16):
        l, r = text[:32], text[32:]
        r_extend = ExtendPermutation(r)
        xor1 = xor(r_extend, subkeys[i])
        s_box_result = SBoxPermutation(xor1)
        p_box_result = PBoxPermutation(s_box_result)
        xor2 = xor(l, p_box_result)
        text = r + xor2

    text = text[32:] + text[:32]
    return InverseIpPermutation(text)


def fill(message):
    '''
    填充函数，若字符分组长度不为16的倍数，使用默认字符“0”补全为16的整数倍。
    '''
    try:
        mod = len(message) % 64
        space = 64 - mod
        while(space > 0):
            message = message.append("0")
            space -= 1
        return message
    except AttributeError:
        print(message)


class DES_encrypter:
    """
       DES加密器
       message：字符串类型表示的16进制明文
       key:加密密钥,字符串类型表示的16进制
       mean:操作方式（ECB, CBC, CFB, OFB）
       iv:字符串类型表示的16进制的初始化向量
    """
    def __init__(self, message, key, mean, iv):
        self.message = string2bin(message)
        self.key = string2bin(key)
        self.mean = mean
        self.iv = string2bin(iv)

    @property
    def ciphertext(self):
        if(self.mean == "ECB"):
            return bin2string(self.__ECBencrypt())
        if(self.mean == "CBC"):
            return bin2string(self.__CBCencrypt())
        if(self.mean == "CFB"):
            return bin2string(self.__CFBencrypt())
        else:
            return bin2string(self.__OFBencrypt())

    def __ECBencrypt(self):
        """密码本模式"""
        output = []
        length = len(self.message)
        times, mod = length // 64, length % 64

        if mod:
            self.message = fill(self.message)
            times += 1

        for i in range(times):
            result = cipher(self.message[i * 64:i * 64 + 64], self.key, 'encrypt')
            output.extend(result)

        return output

    def __CBCencrypt(self):
        """密码块链接模式"""
        output = []
        length = len(self.message)
        times, mod = length // 64, length % 64

        if mod:
            self.message = fill(self.message)
            times += 1

        lastrecord = self.iv
        for i in range(times):
            submessage = self.message[i * 64:i * 64 + 64]
            submessage = xor(submessage, lastrecord)
            result = cipher(submessage, self.key, 'encrypt')
            output.extend(result)
            lastrecord = result

        return output
    
    def __CFBencrypt(self):
        """密码反馈模式
           这里采用1字节反馈模式即一次仅加密明文8位，并更新寄存器中保存的密码流8位
        """
        output = []
        length = len(self.message)
        times, mod = length // 8, length % 8 

        if mod:
            space = 8 - mod
            while(space > 0):
                self.message = self.message.append("0")
                space -= 1
            times += 1

        register = self.iv
        for i in range(times):
            submessage = self.message[i * 8:i * 8 + 8]
            code = cipher(register, self.key, 'encrypt')
            result = xor(code[0:8], submessage)
            register = register[8:] + result[0:8]
            output.extend(result)

        return output
    
    def __OFBencrypt(self):
        """输出反馈模式
           与CFB相似，只不过密码流不再依赖明文或者生成的密文
           同样采用1字节反馈模式
        """ 
        output = []
        length = len(self.message)
        times, mod = length // 8, length % 8

        if mod:
            space = 8 - mod
            while(space > 0):
                self.message = self.message.append("0")
                space -= 1
            times += 1

        register = self.iv
        for i in range(times):
            submessage = self.message[i * 8:i * 8 + 8]
            code = cipher(register, self.key, 'encrypt')
            result = xor(code[0:8], submessage)
            register = register[8:] + code[0:8]
            output.extend(result)

        return output


class DES_decrypter:
    """DES解密器"""
    def __init__(self, cipher, key, mean, iv):
        self.cipher = string2bin(cipher)
        self.key = string2bin(key)
        self.mean = mean
        self.iv = string2bin(iv)
    
    @property
    def plaintext(self):
        if(self.mean == "ECB"):
            return bin2string(self.__ECBdecrypt())
        if(self.mean == "CBC"):
            return bin2string(self.__CBCdecrypt())
        if(self.mean == "CFB"):
            return bin2string(self.__CFBdecrypt())
        else:
            return bin2string(self.__OFBdecrypt())
    
    def __ECBdecrypt(self):
        """密码本模式"""
        output = []
        length = len(self.cipher)
        times, mod = length // 64, length % 64
        
        if mod:
            self.cipher = fill(self.cipher)
            times += 1
        
        for i in range(times):
            result = cipher(self.cipher[i * 64:i * 64 + 64], self.key, 'decrypt')
            output.extend(result)

        return output

    def __CBCdecrypt(self):
        """密码块链接模式"""
        output = []
        length = len(self.cipher)
        times, mod = length // 64, length % 64

        if mod:
            self.cipher = fill(self.cipher)
            times += 1

        lastrecord = self.iv
        for i in range(times):
            submessage = self.cipher[i * 64:i * 64 + 64]
            submessage = cipher(submessage, self.key, 'dcrypt')
            result = xor(submessage, lastrecord)
            output.extend(result)
            lastrecord = self.cipher[(i) * 64:(i) * 64 + 64]
            
        return output

    def __CFBdecrypt(self):
        """密码反馈模式
        """
        output = []
        length = len(self.cipher)
        times, mod = length // 8, length % 8

        if mod:
            space = 8 - mod
            while(space > 0):
                self.cipher = self.cipher.append("0")
                space -= 1
            times += 1

        register = self.iv
        for i in range(times):
            subcipher = self.cipher[i * 8:i * 8 + 8]
            code = cipher(register, self.key, 'encrypt')
            result = xor(code[0:8], subcipher)
            register = register[8:] + subcipher[0:8]
            output.extend(result)

        return output

    def __OFBdecrypt(self):
        """密码反馈模式
        """
        output = []
        length = len(self.cipher)
        times, mod = length // 8, length % 8

        if mod:
            space = 8 - mod
            while(space > 0):
                self.cipher = self.cipher.append("0")
                space -= 1
            times += 1

        register = self.iv
        for i in range(times):
            subcipher = self.cipher[i * 8:i * 8 + 8]
            code = cipher(register, self.key, 'encrypt')
            result = xor(code[0:8], subcipher)
            register = register[8:] + code[0:8]
            output.extend(result)

        return output
