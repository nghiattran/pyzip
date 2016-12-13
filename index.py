import codecs
import binascii

LOCAL_FILE_HEADER_SIG = 0x04034b50
DATA_DESCRIPTOR_SIG = 0x08074b50
CENTRAL_DIRECTORY_SIG = 0x02014b50
END_CENTRAL_DIRECTORY_SIG = 0x06054b50
ARCHIVE_EXTRA_DATA_SIG = 0x08064b50

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
    return value >> index & 1


def hex_to_string(hexstring):
    print(type(hexstring))
    return str(binascii.hexlify(hexstring))[2:-1]


def is_equal(bin_value, hex_value):
    return int.from_bytes(bin_value, byteorder='little') == int(hex_value, 16)


def parse_local_header(f):
    '''
    This function takes in a file description and parses only one file data from the compressed file. The process
    follows these steps:

    local file header -> encryption header -> file data - >data descriptor

    :param f:
    :return: file data dictionary
    '''

    version = f.read(2)
    flags = f.read(2)
    compression_method = f.read(2)
    last_modification_time = f.read(2)
    last_modification_date = f.read(2)
    crc32 = f.read(4)
    compressed_size = f.read(4)
    uncompressed_size = f.read(4)
    filename_length = f.read(2)
    extra_length = f.read(2)
    filename = f.read(int.from_bytes(filename_length, byteorder='little'))
    extra = f.read(int.from_bytes(extra_length, byteorder='little'))

    # TODO get encyption header here


    # Get file data
    filedata = f.read(int.from_bytes(compressed_size, byteorder='little'))

    data_descriptor = None
    if bit_at(flags, 3) == 1:
        # Signature for file descriptor is optional
        sig = f.read(4)
        data_descriptor = {
            'crc32': f.read(4) if int.from_bytes(sig, byteorder='little') == DATA_DESCRIPTOR_SIG else sig,
            'compressed_size': f.read(4),
            'uncompressed_size': f.read(4),
        }

    return {
        'version_need': version,
        'flags': [
            bit_at(flags, i) for i in range(16)
        ],
        'compression_method': compression_method,
        'last_modification_time': last_modification_time,
        'last_modification_date': last_modification_date,
        'crc32': crc32,
        'compressed_size': compressed_size,
        'uncompressed_size': uncompressed_size,
        'filename_length': filename_length,
        'extra_length': extra_length,
        'filename': filename,
        'extra': extra,
        'filedata': filedata,
        'data_descriptor': data_descriptor
    }


def parse_central_directory(f):
    version = f.read(2)
    version_need = f.read(2)
    flags = f.read(2)
    compression_method = f.read(2)
    last_modification_time = f.read(2)
    last_modification_date = f.read(2)
    crc32 = f.read(4)
    compressed_size = f.read(4)
    uncompressed_size = f.read(4)
    filename_length = f.read(2)
    extra_length = f.read(2)
    comment_length = f.read(2)
    disk_number = f.read(2)
    internal_file_attributes = f.read(2)
    external_file_attributes = f.read(4)
    offset = f.read(4)
    filename = f.read(int.from_bytes(filename_length, byteorder='little'))
    extra = f.read(int.from_bytes(extra_length, byteorder='little'))
    comment = f.read(int.from_bytes(comment_length, byteorder='little'))
    return {
        'version': version,
        'version_need': version_need,
        'flags': [
            bit_at(flags, i) for i in range(16)
        ],
        'compression_method': compression_method,
        'last_modification_time': last_modification_time,
        'last_modification_date': last_modification_date,
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
    iv_size = f.read(2)
    iv_data = f.read(int.from_bytes(iv_size, byteorder='little'))
    print(int.from_bytes(iv_size, byteorder='little'), iv_data)
    size = f.read(4)
    format = f.read(2)
    alg_id = f.read(2)
    bit_len = f.read(2)
    flags = f.read(2)
    erd_size = f.read(2)
    print(int.from_bytes(erd_size, byteorder='little'))
    erd_data = f.read(int.from_bytes(erd_size, byteorder='little'))
    reserve1 = f.read(4)
    if int.from_bytes(reserve1, byteorder='little') != 0:
        reserve2 = {
            'hash_alg': f.read(2),
            'h_size': f.read(2),
            're_list': f.read(2)
        }
    # v_size = f.read(2)
    # v_data = f.read(int.from_bytes(v_size, byteorder='little') - 4)
    # v_crc32 = f.read(4)


with open('zips/file2.zip', 'rb') as f:
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
