"""This offsets class is to be used to pull information from the PEFile library
  and format the data into a more workable format.Example of info to be pulled = DOS/OPTIONAL/IMPORT_TABLE/IMAGE_IMPORT_DESCRIPTOR"""
import os
import re
import string
import subprocess
from M2Crypto import SMIME, X509, BIO, m2

try:
    import pefile
except ImportError:
    subprocess.call(['pip', 'install', 'pefile'])


# TODO Could use pefiles inbuilt offset parsing functionality or could use the raw hex data at particular offsets
def main():
    filename = "ViralTest/One"  # REPLACE WITH A FILE
    min_string_length = 8

    create_file_dictionary(min_string_length)


def create_file_dictionary(min_string_length):
    # Gets a list of all the files in the directory
    TEMP_DIRECTORY = "POC/"
    hash_list = os.listdir(TEMP_DIRECTORY)

    # Print path to all filenames.
    path_list = list()

    # Appends the directory name to the filename for the next step
    for filename in hash_list:
        path_list.append(os.path.join(TEMP_DIRECTORY, filename))

    dictionary = dict.fromkeys(path_list, 0)

    # Gets the data from every file in the directory and creates a dictionary
    # Filename is Key and Data is value
    for filename in path_list:
        try:
            pe = pefile.PE(filename, fast_load=True)
            file_obj = get_file_data(pe, filename, min_string_length)
            dictionary[filename] = file_obj
        except pefile.PEFormatError:
            continue

    return dictionary


class FileData:

    def __init__(self):
        self.__set_section_header_data(0)
        self.__set_optional_header_data(0)
        self.__set_import_data(0)
        self.__set_imphash(0)
        self.__set_dos_header_data(0)
        self.__set_rsrc_list(0)
        self.__set_sig_details(0)
        self.__set_string_list(0)

    def __get_section_header_data(self):
        return self.__section_header_data

    def __set_section_header_data(self, input):
        self.__section_header_data = input

    section_header_data = property(__get_section_header_data, __set_section_header_data)

    def __get_optional_header_data(self):
        return self.__optional_header_data

    def __set_optional_header_data(self, input):
        self.__optional_header_data = input

    optional_header_data = property(__get_optional_header_data, __set_optional_header_data)

    def __get_import_data(self):
        return self.__import_data

    def __set_import_data(self, input):
        self.__import_data = input

    import_data = property(__get_import_data, __set_import_data)

    def __get_imphash(self):
        return self.__imphash

    def __set_imphash(self, input):
        self.__imphash = input

    imphash = property(__get_imphash, __set_imphash)

    def __get_dos_header_data(self):
        return self.__dos_header_data

    def __set_dos_header_data(self, input):
        self.__dos_header_data = input

    dos_header_data = property(__get_dos_header_data, __set_dos_header_data)

    def __get_rsrc_list(self):
        return self.__rsrc_list

    def __set_rsrc_list(self, input):
        self.__rsrc_list = input

    rsrc_list = property(__get_rsrc_list, __set_rsrc_list)

    def __get_sig_details(self):
        return self.__sig_details

    def __set_sig_details(self, input):
        self.__sig_details = input

    sig_details = property(__get_sig_details, __set_sig_details)

    def __get_string_list(self):
        return self.__string_list

    def __set_string_list(self, input):
        self.__sig_details = input

    string_list = property(__get_sig_details, __set_sig_details)

def get_file_data(pe, filename, min_string_length):
    temp_file = FileData()

    temp_file.section_header_data = get_section_headers_data(pe)
    temp_file.optional_header_data = get_optional_header_data(pe)
    temp_file.import_data = get_image_entry_import_data(pe)
    temp_file.dos_header_data = get_dos_header_data(pe)
    temp_file.section_header_data = get_section_headers_data(pe)
    temp_file.imphash = pe.get_imphash()
    temp_file.rsrc_list = get_rsrc_data(pe)

    dig_sig = get_cert_data(pe)

    if dig_sig is not None:  # Arbitrary number
        temp_file.sig_details = get_digisig_info(dig_sig)

    temp_file.string_list = set(get_strings(filename, min_string_length))

    return temp_file


# TODO HOW TO TELL IF A STRING IS ASCII OR WIDE??
# TODO FIND A BETTER WAY OF SAVING/STORING STRINGS
def get_strings(filename, min_string_length):
    result = ""

    with open(filename, "rb") as f:  # Python 2.x
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min_string_length:
                yield result
            result = ""
        # if len(result) >= min_string_length:  # catch result at EOF
        #     yield result


"""Returns a list of lists of dictionaries containing the key:value pair of all the info of each of the section headers"""


# TODO RESULTS FROM THE HEADER ARE STORED IN BASE 10 and not HEX for the time being
# TODO MIGHT NEED TO REMOVE THE \x00's from after the section name
def get_section_headers_data(pe):
    section_header_data = list()

    for section in pe.sections:
        # print(section)
        section_header_data.append(section.dump_dict())

    temp_list = []

    for each in section_header_data:
        temp = dict()
        for key in each.keys():
            if type(each[key]) == type(dict()):
                temp[key] = each[key]['Value']
        temp_list.append(temp)

    return temp_list


# TODO GENERIFY THESE FUNCTIONS BY PASSING IN HEADER TYPE
# TODO ADD IN SUPPORT FOR PARSING 64-BIT HEADERS
def get_optional_header_data(pe):
    dos_header_data = pe.OPTIONAL_HEADER.dump_dict()

    temp_list = []

    for key in dos_header_data.keys():
        temp = dict()
        if type(dos_header_data[key]) == type(dict()):
            temp[key] = dos_header_data[key]['Value']  # ERROR BEING THROWN HERE
            temp_list.append(temp)

    return temp_list


def get_image_entry_import_data(pe):
    pe.parse_data_directories()
    import_list = []
    temp = {}

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        temp_imp_list = []
        for imp in entry.imports:
            temp_imp_list.append(imp.name)
        temp[entry.dll] = temp_imp_list
        import_list.append(temp)

    return import_list


def get_dos_header_data(pe):
    dos_header_data = pe.DOS_HEADER.dump_dict()
    temp_list = []

    for key in dos_header_data.keys():
        temp = dict()
        if type(dos_header_data[key]) == type(dict()):
            temp[key] = dos_header_data[key]['Value']
            temp_list.append(temp)

    return temp_list


# TODO Check if DLL and if DLL get this info, might want to check for this anyway - could use this as the check if it is a DLL?
def get_dll_export_data(pe):
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal


# TODO TEST AGAINST A FILE WITH KNOWN RESOURCES IN ITS DIRECTORY
def get_rsrc_data(pe):
    rsrc_list = []

    if pe.DIRECTORY_ENTRY_RESOURCE is not None:
        for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for entry in rsrc.directory.entries:
                if entry.name is not None:
                    rsrc_list.append(entry.name)
                    print(entry)
        return rsrc_list
    else:
        return

# TODO FIX CERT DATA, seems to give me some trouble.
def get_cert_data(pe):
    address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

    if address == 0:
        print 'Not Signed'
        return

    return bytes(pe.write()[address + 8:(address + size)])


def get_digisig_info(dig_sig):  # Taken from TJ's cert_extractor
    """
    Returns a list of dicts of signers information extracted
    out of a certificate. Normally returns just one
    signer.
    """
    buf = BIO.MemoryBuffer(dig_sig)
    smime_object = SMIME.PKCS7(m2.pkcs7_read_bio_der(buf._ptr()))
    signers = smime_object.get0_signers(X509.X509_Stack())
    certs = []
    for cert in signers:
        cert_info = {}
        cert_parts = (cert.as_text()).split("\n")
        for i, line in enumerate(cert_parts):
            if line.startswith("        Subject:"):
                cert_info["subject"] = get_openssl_string(line.lstrip("        Subject:"))
            elif line.startswith("        Issuer:"):
                cert_info["issuer"] = get_openssl_string(line.lstrip("        Issuer:"))
            elif line.startswith("        Serial Number: "):
                cert_hex = cert_parts[i].split(":")[1].split()[1].strip("(0x").strip(")")
                if len(cert_hex) % 2 != 0:
                    cert_hex = "0{}".format(cert_hex)
                c_h = iter(cert_hex)
                serial = ':'.join(a + b for a, b in zip(c_h, c_h))
                cert_info["serial"] = serial
            elif line == "        Serial Number:":
                cert_info["serial"] = cert_parts[i + 1].strip()
            else:
                pass
        certs.append(cert_info)
    return certs  # TODO PROBABLY ONLY WANT TO KEEP THE SERIAL PORTION


def get_openssl_string(input_string):  # Taken from TJ's cert_extractor
    """
    Returns the OpenSSL forward slash format of the
    X509 string of Issuer and Subject
    """
    new_string = "/"
    for i, char in enumerate(input_string):
        try:
            if ((char == "," and input_string[i + 1] == " ") and
                    ((re.match("[A-Z]", input_string[i + 2]) and
                      input_string[i + 3] == "=") or
                     (re.match("[A-Z]", input_string[i + 3]) and
                      input_string[i + 4] == "="))):
                char = "_TOKEN_"
        except:
            pass
        new_string += char
    return new_string.replace("_TOKEN_ ", "/")


if __name__ == "__main__":
    main()
