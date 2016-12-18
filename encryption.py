import codecs, binascii, zipfile, zlib

TEST_PASSWORD = 'maikhongquen'
TEST_ENCRYPTION_HEADER = b'\xa9\xab\x9e\x84.j]-!\x0b\x95\x9c'
TEST_FILE_DATA = b'\xa1\x9b\xc5H\xf0\x07\xaa\xade\xc0{P\xe7\x06PK\x07\x08\x1e\xc2\x0c&\x1a\x00\x00\x00'
# 6.1.4 The following are the basic steps required to decrypt a file:
#
# 1) Initialize the three 32-bit keys with the password.
# 2) Read and decrypt the 12-byte encryption header, further
#    initializing the encryption keys.
# 3) Read and decrypt the compressed data stream using the
#    encryption keys.

def create_table():
    poly = 0xedb88320
    table = [0] * 256
    for i in range(256):
        crc = i
        for j in range(8):
            if crc & 1:
                crc = ((crc >> 1) & 0x7FFFFFFF) ^ poly
            else:
                crc = ((crc >> 1) & 0x7FFFFFFF)
        table[i] = crc
    return table

crctab = create_table()

def decrypt(password, encryption_header, data):
    keys = [0x12345678, 0x23456789, 0x34567890]

    def crc32(char, crc):
        return ((crc >> 8) & 0xffffff) ^ crctab[(crc ^ char) & 0xff]

    def initialize_encryption_keys(password):
        for p in password:
            update_keys(p)

    def update_keys(char):
        keys[0] = crc32(char, keys[0])
        keys[1] = (keys[1] + (keys[0] & 0xff)) & 4294967295
        keys[1] = (keys[1] * 134775813 + 1) & 4294967295
        keys[2] = crc32((keys[1] >> 24) & 0xff,keys[2])

    def decrypting_encryption_header(buffer):
        res = None
        for i in range(12):
            c = buffer[i] ^ decrypt_byte() & 0xff
            update_keys(c)
            res = c if res is None else res + c
        return res

    def decrypt_byte():
        temp = keys[2] | 2
        return (temp * (temp ^ 1)) >> 8

    def decrypt_compressed_data(data):
        res = ''
        for C in data:
            temp = C ^ decrypt_byte() & 0xff
            update_keys(temp)
            res += chr(temp)
        return res
    # print(password, encryption_header, data)
    initialize_encryption_keys(password)
    encryption_header = decrypting_encryption_header(encryption_header)
    return str.encode(decrypt_compressed_data(data))


# data = decrypt(bytes('nothing', encoding='utf-8'), TEST_ENCRYPTION_HEADER, TEST_FILE_DATA)
# print(data)

