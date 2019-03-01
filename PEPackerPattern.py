import argparse
import binascii
import csv
import os
import sys
import pefile


def main():
    buffer_size = 40

    args = parse_arguments()

    if args.filename is not None:
        get_data(args.filename, buffer_size)

    if args.dir is not None:
        files_dict = create_file_dictionary(args, buffer_size)
        # check_data_for_matches(files_dict)


def check_data_for_matches(files_dict):

    for value in files_dict.values():
        value = binascii.unhexlify(value)




def create_file_dictionary(args, buffer_size):
    temp_list = list()
    hash_list = os.listdir(args.dir)
    # Print path to all filenames.
    path_list = list()
    for filename in hash_list:
        path_list.append(os.path.join(args.dir, filename))

    dictionary = dict.fromkeys(path_list, 0)
    for filename in path_list:
        try:
            hex_data = get_data(filename, buffer_size)
            if hex_data is not None:
                temp_list = list(hex_data)

            dictionary[filename] = temp_list
        except pefile.PEFormatError:
            continue

    return dictionary


def get_data(filename, buffer_size):
    entry_point = get_entry_point(filename)
    print(entry_point)
    hex_data = read_from_hex_offset(filename, entry_point, buffer_size)

    return hex_data


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Compare a section of bytes in multiple files, located after the entry point, to aid in the creation of packer detection yara rules")

    parser.add_argument("-f", "--file", dest="filename",
                        help="Specify file to be scanned", metavar="<file>")
    parser.add_argument("-b", "--buffer", dest="buffer",
                        help="Specifies how many 0's to look for default is - Default is 40 bytes",
                        # TODO Determine correct buffer size
                        metavar="<buffSize>")
    parser.add_argument("-d", "--dir", metavar="<dir>",
                        help="Specify directory of files to scan")
    parser.add_argument("-i", "--inputcsv", metavar="<path>",
                        help="Specifies input CSV ")
    parser.add_argument("-o", "--outputcsv", metavar="<path>",
                        help="Specifies output CSV ")

    args = parser.parse_args()

    return args


def read_from_hex_offset(filename, hex_offset, buffer_size):
    filename = open(filename, 'rb')
    offset = int(hex_offset, base=16)

    filename.seek(offset, 0)
    data = filename.read(buffer_size)

    hex_data = binascii.hexlify(data)

    binary_data = binascii.unhexlify(hex_data)



    return hex_data


def get_entry_point(filename):
    pe = pefile.PE(filename)  # Takes the filename from command line argument and loads PE file

    ep_section = find_entry_point_section(pe, pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    delta = entry_point - ep_section.VirtualAddress

    actual_entry_point = ep_section.PointerToRawData + delta

    # if pe.sections[0] == ep_section:
    #     actual_entry_point = ep_section.PointerToRawData + delta
    #
    # else:
    #     # EntryPointAddress-VirtualAddressEpSection = OFFSET of how far into section
    #     actual_entry_point = ep_section.PointerToRawData + delta

    entry_point = hex(actual_entry_point)
    return entry_point


def find_entry_point_section(pe, entry_point):
    for section in pe.sections:
        print("Searching")
        if section.contains_rva(entry_point):
            return section

    return None


main()
