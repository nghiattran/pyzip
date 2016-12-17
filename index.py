import codecs
import binascii


crctab = [
 0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
 0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
 0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
 0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
 0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
 0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
 0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
 0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
 0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
 0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
 0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
 0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
 0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
 0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
 0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
 0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
 0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
 0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
 0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
 0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
 0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
 0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
 0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
 0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
 0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
 0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
 0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
 0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
 0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
 0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
 0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
 0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
]
LOCAL_FILE_HEADER_SIG = 0x04034b50
DATA_DESCRIPTOR_SIG = 0x08074b50
CENTRAL_DIRECTORY_SIG = 0x02014b50
END_CENTRAL_DIRECTORY_SIG = 0x06054b50
ARCHIVE_EXTRA_DATA_SIG = 0x08064b50
DIGITIAL_SIG = 0x05054b50
TEST_PASSWORD = 'maikhongquen'
TEST_ENCRYPTION_HEADER = b'\xa9\xab\x9e\x84.j]-!\x0b\x95\x9c'
TEST_FILE_DATA = b'\xa1\x9b\xc5H\xf0\x07\xaa\xade\xc0{P\xe7\x06PK\x07\x08\x1e\xc2\x0c&\x1a\x00\x00\x00'
versions = ['MS-DOS and OS/2 (FAT / VFAT / FAT32 file systems)',
            'Amiga',
            'OpenVMS',
            'UNIX',
            'VM/CMS',
            'Atari ST',
            'OS/2 H.P.F.S.',
            'Macintosh',
            'Z-System',
            'CP/M',
            'Windows NTFS',
            'MVS (OS/390 - Z/OS)',
            'VSE',
            'Acorn Risc',
            'VFAT',
            'alternate MVS',
            'BeOS',
            'Tandem',
            'OS X (Darwin)',
            'OS/400',
            'unknown'
            ]


def bit_at(value, index):
    if type(value) is bytes:
        value = int.from_bytes(value, byteorder='little')

    if type(value) is not int:
        raise Exception('Integer is required')

    return value >> index & 1


def hex_to_string(hexstring):
    return str(binascii.hexlify(hexstring))[2:-1]


def is_equal(bin_value, hex_value):
    return int.from_bytes(bin_value, byteorder='little') == int(hex_value, 16)


def parse_local_header(f):
    """
    This function takes in a file description and parses only one file data from the compressed file. The process
    follows these steps:

    local file header -> encryption header -> file data - >data descriptor

    :param f:
    :return: file data dictionary
    """

    version = int.from_bytes(f.read(2), byteorder='little') / 10
    flags = f.read(2)
    flags = [bit_at(flags, i) for i in range(16)]
    compression_method = int.from_bytes(f.read(2), byteorder='little')
    last_modification_time = f.read(2)
    last_modification_date = f.read(2)
    crc32 = f.read(4)
    compressed_size = int.from_bytes(f.read(4), byteorder='little')
    uncompressed_size = int.from_bytes(f.read(4), byteorder='little')
    filename_length = int.from_bytes(f.read(2), byteorder='little')
    extra_length = int.from_bytes(f.read(2), byteorder='little')
    filename = f.read(filename_length)
    extra = f.read(extra_length)

    # TODO get encyption header here
    encryption_header = None
    if flags[0] == 1:
        encryption_header = parse_decryption_header(f)

    # Get file data
    filedata = f.read(compressed_size)

    data_descriptor = None
    if flags[3] == 1:
        # Signature for file descriptor is optional
        sig = f.read(4)
        data_descriptor = {
            'crc32': f.read(4) if int.from_bytes(sig, byteorder='little') == DATA_DESCRIPTOR_SIG else sig,
            'compressed_size': f.read(4),
            'uncompressed_size': f.read(4),
        }

    return {
        'version': version,
        'flags': flags,
        'compression_method': compression_method,
        'last_modification_time': last_modification_time,
        'last_modification_date': last_modification_date,
        'last_modification_time_string': parse_time(last_modification_time),
        'last_modification_date_string': parse_date(last_modification_date),
        'crc32': crc32,
        'compressed_size': compressed_size,
        'uncompressed_size': uncompressed_size,
        'filename_length': filename_length,
        'extra_length': extra_length,
        'filename': filename,
        'extra': extra,
        'filedata': filedata,
        'data_descriptor': data_descriptor,
        'encryption_header': encryption_header
    }


def parse_central_directory(f):
    version = int.from_bytes(f.read(2), byteorder='little')
    version_need = int.from_bytes(f.read(2), byteorder='little') / 10
    flags = f.read(2)
    compression_method = int.from_bytes(f.read(2), byteorder='little')
    last_modification_time = f.read(2)
    last_modification_date = f.read(2)
    crc32 = f.read(4)
    compressed_size = int.from_bytes(f.read(4), byteorder='little')
    uncompressed_size = int.from_bytes(f.read(4), byteorder='little')
    filename_length = int.from_bytes(f.read(2), byteorder='little')
    extra_length = int.from_bytes(f.read(2), byteorder='little')
    comment_length = int.from_bytes(f.read(2), byteorder='little')
    disk_number = int.from_bytes(f.read(2), byteorder='little')
    internal_file_attributes = f.read(2)
    external_file_attributes = f.read(4)
    offset = int.from_bytes(f.read(4), byteorder='little')
    filename = f.read(filename_length)
    extra = f.read(extra_length)
    comment = f.read(comment_length)
    return {
        'version': {
            'os': versions[version >> 8 & 0b11111111],
            'version': (version & 0b11111111) / 10
        },
        'version_need': version_need,
        'flags': [
            bit_at(flags, i) for i in range(16)
        ],
        'compression_method': compression_method,
        'last_modification_time': last_modification_time,
        'last_modification_date': last_modification_date,
        'last_modification_time_string': parse_time(last_modification_time),
        'last_modification_date_string': parse_date(last_modification_date),
        'crc32': crc32,
        'compressed_size': compressed_size,
        'uncompressed_size': uncompressed_size,
        'filename_length': filename_length,
        'extra_length': extra_length,
        'comment_length': comment_length,
        'disk_number': disk_number,
        'internal_file_attributes': internal_file_attributes,
        'external_file_attributes': external_file_attributes,
        'offset': offset,
        'filename': filename,
        'extra': extra,
        'comment': comment
    }

def parse_end_central_directory(f):
    num_disk = f.read(2)
    combined_num_disk = f.read(2)
    total_entries = f.read(2)
    combined_total_entries = f.read(2)
    central_directory_size = f.read(4)
    central_directory_offset = f.read(4)
    comment_length = f.read(2)
    comment = f.read(int.from_bytes(comment_length, byteorder='little'))
    return {
        'num_disk': num_disk,
        'combined_num_disk': combined_num_disk,
        'total_entries': total_entries,
        'combined_total_entries': combined_total_entries,
        'central_directory_size': central_directory_size,
        'central_directory_offset': central_directory_offset,
        'comment_length': comment_length,
        'comment': comment
    }


def parse_decryption_header(f):
    # iv_size = f.read(2)
    # iv_data = f.read(int.from_bytes(iv_size, byteorder='little'))
    # print(int.from_bytes(iv_size, byteorder='little'), iv_data)
    # size = f.read(4)
    # format = f.read(2)
    # alg_id = f.read(2)
    # bit_len = f.read(2)
    # flags = f.read(2)
    # erd_size = f.read(2)
    # print(int.from_bytes(erd_size, byteorder='little'))
    # erd_data = f.read(int.from_bytes(erd_size, byteorder='little'))
    # reserve1 = f.read(4)
    # if int.from_bytes(reserve1, byteorder='little') != 0:
    #     reserve2 = {
    #         'hash_alg': f.read(2),
    #         'h_size': f.read(2),
    #         're_list': f.read(2)
    #     }
    # v_size = f.read(2)
    # v_data = f.read(int.from_bytes(v_size, byteorder='little') - 4)
    # v_crc32 = f.read(4)
    return f.read(12)


def parse_time(value):
    if type(value) is bytes:
        value = int.from_bytes(value, byteorder='little')

    if type(value) is not int:
        raise Exception('Integer is required')

    return '{0}:{1}:{2}'.format((value >> 11) & 0b11111,
                                (value >> 5) & 0b111111,
                                value & 0b11111)


def parse_date(value):
    if type(value) is bytes:
        value = int.from_bytes(value, byteorder='little')

    if type(value) is not int:
        raise Exception('Integer is required')

    return '{0}/{1}/{2}'.format(value & 0b11111,
                                (value >> 5) & 0b1111,
                                ((value >> 9) & 0b1111111) + 1980)

# 6.1.4 The following are the basic steps required to decrypt a file:
#
# 1) Initialize the three 32-bit keys with the password.
# 2) Read and decrypt the 12-byte encryption header, further
#    initializing the encryption keys.
# 3) Read and decrypt the compressed data stream using the
#    encryption keys.


def decrypt(password, encryption_header, data):
    keys = [0x12345678, 0x23456789, 0x34567890]

    def crc32(crc, char):
        return ((crc >> 8) & 0xff) ^ crctab[(crc ^ char) & 0xff]

    def initialize_encryption_keys(password):
        password = bytearray(password, encoding='utf-8')
        for i in range(len(password) - 1, -1, -1):
            update_keys(password[i])

    def update_keys(char):
        keys[0] = crc32(keys[0], char)
        keys[1] = keys[1] + (keys[0] & 0x000000ff)
        keys[1] = keys[1] * 134775813 + 1
        keys[2] = crc32(keys[2], keys[1] >> 24)

    def decrypting_encryption_header(buffer):
        res = None
        for i in range(12):
            c = buffer[i] ^ decrypt_byte()
            update_keys(c)
            res = c if res is None else res + c
        return res

    def decrypt_byte():
        temp = keys[2] | 2
        return (temp * (temp ^ 1)) >> 8

    def decrypt_compressed_data(data):
        res = []
        for C in data:
            temp = C ^ decrypt_byte()
            print(C, type(C), decrypt_byte(), C)
            update_keys(temp)
            print(temp)
            temp = chr(temp)
            res.append(temp)
        return res

    initialize_encryption_keys(password)
    print(keys)
    encryption_header = decrypting_encryption_header(encryption_header)
    print(encryption_header)
    res = decrypt_compressed_data(data)
    print(res)

decrypt(TEST_PASSWORD, TEST_ENCRYPTION_HEADER, TEST_FILE_DATA)

def main():
    with open('zips/file.zip', 'rb') as f:
        local_files = []
        sig = f.read(4)
        if int.from_bytes(sig, byteorder='little') != LOCAL_FILE_HEADER_SIG:
            raise Exception('This is not a zip file.')

        while int.from_bytes(sig, byteorder='little') == LOCAL_FILE_HEADER_SIG:
            local_files.append(parse_local_header(f))
            sig = f.read(4)

        central_dir = []
        while int.from_bytes(sig, byteorder='little') == CENTRAL_DIRECTORY_SIG:
            central_dir.append(parse_central_directory(f))
            sig = f.read(4)

        if int.from_bytes(sig, byteorder='little') == END_CENTRAL_DIRECTORY_SIG:
            data = parse_end_central_directory(f)

        for file in local_files:
            print(file['version'])
            print(file['flags'])
            print(file['compression_method'])
            print(file['filedata'])
            print(file['filename'])
            print(file['encryption_header'])
            print()

            # for file in central_dir:
            #     print(file['version'])
            #     print(file['flags'])
            #     print(file['filename'])
            #     print()

        # decrypt('maikhongquen', local_files[1]['encryption_header'], local_files[1]['filedata'])
# main()