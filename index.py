import codecs, binascii
from encryption import decrypt

LOCAL_FILE_HEADER_SIG = 0x04034b50
DATA_DESCRIPTOR_SIG = 0x08074b50
CENTRAL_DIRECTORY_SIG = 0x02014b50
END_CENTRAL_DIRECTORY_SIG = 0x06054b50
ARCHIVE_EXTRA_DATA_SIG = 0x08064b50
DIGITIAL_SIG = 0x05054b50
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

class Zip:
    password = None

    def bit_at(self, value, index):
        if type(value) is bytes:
            value = int.from_bytes(value, byteorder='little')

        if type(value) is not int:
            raise Exception('Integer is required')

        return value >> index & 1


    def hex_to_string(self, hexstring):
        return str(binascii.hexlify(hexstring))[2:-1]


    def is_equal(self, bin_value, hex_value):
        return int.from_bytes(bin_value, byteorder='little') == int(hex_value, 16)


    def parse_local_header(self, f):
        """
        This function takes in a file description and parses only one file data from the compressed file. The process
        follows these steps:

        local file header -> encryption header -> file data - >data descriptor

        :param f:
        :return: file data dictionary
        """

        version = int.from_bytes(f.read(2), byteorder='little') / 10
        flags = f.read(2)
        flags = [self.bit_at(flags, i) for i in range(16)]
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
            encryption_header = self.parse_decryption_header(f)

        # Get file data
        if flags[0] == 1:
            filedata = decrypt(self.password,
                               encryption_header,
                               f.read(uncompressed_size))
        else:
            filedata = f.read(uncompressed_size)

        data_descriptor = None

        if flags[3] == 1:
            # Signature for file descriptor is optional
            sig = f.read(4)
            data_descriptor = {
                'sig': sig if int.from_bytes(sig, byteorder='little') == DATA_DESCRIPTOR_SIG else None,
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
            'last_modification_time_string': self.parse_time(last_modification_time),
            'last_modification_date_string': self.parse_date(last_modification_date),
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


    def parse_central_directory(self, f):
        version = int.from_bytes(f.read(2), byteorder='little')
        version_need = int.from_bytes(f.read(2), byteorder='little') / 10
        flags = f.read(2)
        flags = [self.bit_at(flags, i) for i in range(16)]
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
            'flags': flags,
            'compression_method': compression_method,
            'last_modification_time': last_modification_time,
            'last_modification_date': last_modification_date,
            'last_modification_time_string': self.parse_time(last_modification_time),
            'last_modification_date_string': self.parse_date(last_modification_date),
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

    def parse_end_central_directory(self, f):
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


    def parse_decryption_header(self, f):
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


    def parse_time(self, value):
        if type(value) is bytes:
            value = int.from_bytes(value, byteorder='little')

        if type(value) is not int:
            raise Exception('Integer is required')

        return '{0}:{1}:{2}'.format((value >> 11) & 0b11111,
                                    (value >> 5) & 0b111111,
                                    value & 0b11111)


    def parse_date(self, value):
        if type(value) is bytes:
            value = int.from_bytes(value, byteorder='little')

        if type(value) is not int:
            raise Exception('Integer is required')

        return '{0}/{1}/{2}'.format(value & 0b11111,
                                    (value >> 5) & 0b1111,
                                    ((value >> 9) & 0b1111111) + 1980)


    def __init__(self, password = None):
        if password is not None:
            if type(password) is str:
                password = bytes(password, encoding='utf-8')

            if type(password) is not bytes:
                raise Exception('Password has to be a string or a bytes type object')

            self.password = password

        with open('zips/file.zip', 'rb') as f:
            local_files = []
            sig = f.read(4)
            if int.from_bytes(sig, byteorder='little') != LOCAL_FILE_HEADER_SIG:
                raise Exception('This is not a zip file.')

            while int.from_bytes(sig, byteorder='little') == LOCAL_FILE_HEADER_SIG:
                local_files.append(self.parse_local_header(f))
                sig = f.read(4)

            central_dir = []
            while int.from_bytes(sig, byteorder='little') == CENTRAL_DIRECTORY_SIG:
                central_dir.append(self.parse_central_directory(f))
                sig = f.read(4)

            if int.from_bytes(sig, byteorder='little') == END_CENTRAL_DIRECTORY_SIG:
                data = self.parse_end_central_directory(f)

            for file in local_files:
                print(file['flags'])
                print(file['filedata'], len(file['filedata']), file['compressed_size'], file['uncompressed_size'])
                print(file['crc32'])
                if file['flags'][3] == 1:
                    print(file['data_descriptor']['crc32'])
                # print(file['filename'])
                # print(file['data_descriptor'])
                # print(file['encryption_header'])
                print()

            # for file in central_dir:
            #     print(file['crc32'])
            #     print(file['version'])
            #     print(file['flags'])
            #     print(file['filename'])
            #     print()


data = Zip(bytes('maikhongquen', encoding='utf-8'))