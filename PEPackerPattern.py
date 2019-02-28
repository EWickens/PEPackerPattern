import argparse
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
        check_data_for_matches(files_dict)

def check_data_for_matches(files_dict):
    for data in files_dict.items():
        for hex in data:
            if isinstance(hex, str) == True:
                hex = hex.split('x', 1)[-1]
        print(data)

def create_file_dictionary(args, buffer_size):
    hash_list = os.listdir(args.dir)
    # print path to all filenames.
    path_list = list()
    for filename in hash_list:
        path_list.append(os.path.join(args.dir, filename))


    dictionary = dict.fromkeys(path_list, 0)
    for filename in path_list:
        try:
            hex_data = get_data(filename, buffer_size)
            temp_list = list(hex_data)

            dictionary[filename] = temp_list
        except:
            pefile.PEFormatError

    return dictionary


def get_data(filename, buffer_size):
    entry_point = get_entry_point(filename)
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


def get_entry_point(filename):
    pe = pefile.PE(filename)  # Takes the filename from command line argument and loads PE file
    entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    return entry_point


def read_from_hex_offset(filename, hex_offset, buffer_size):
    filename = open(filename)

    offset = int(hex_offset, base=16)
    filename.seek(offset, 0)

    hex_data = filename.read(buffer_size)

    return hex_data


main()
