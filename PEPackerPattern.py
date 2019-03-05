import argparse
import binascii
import csv
import os
import pefile
from difflib import SequenceMatcher


def main():
    buffer_size = 60

    args = parse_arguments()

    if args.filename is not None:
        get_data(args.filename, buffer_size)

    if args.dir is not None:
        files_dict = create_file_dictionary(args, buffer_size)
        # check_data_for_matches(files_dict)
        # round_robin(files_dict)


'''Uses round robin to iterate through each possible match without duplication of matches'''

# def round_robin(files_dict):
#     values = list(files_dict.values())
#
#     matches = list()
#
#     for x in range(len(values)):
#
#         for y in range(x + 1, len(values)):
#             retdict = multiprocess_match(values[x], values[y], x, y)
#             if len(retdict) > 0:
#                 matches.append(retdict)

'''Calculate the occurences of a file at a given index in a file'''  # TODO Implement this


def calculate_occurences(files_dict, buffer_size):
    total_dict = dict.fromkeys(files_dict.keys())



# def occurence_check(retvals):

# retval_dict = dict.fromkeys(retvals, 0)


''' Matches two files and returns a dictionary with which of the hex matches'''


def multiprocess_match(file1, file2, q, e):
    print("COMBINES: " + str(q) + " " + str(e))

    retdict = {}

    if file1 != 0 and file2 != 0:
        for x in range(len(file1)):
            if file1[x] == file2[x]:  # Creates a list with index of number followed by data
                y = str(x)
                retdict.update({x: file1[x]})

            else:
                retdict[x] = False

    return retdict


'''Creates a dictionary of all the hashes in the file with their appropriate hex data as the value'''


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
    hex_data = read_from_hex_offset(filename, entry_point, buffer_size)

    print(hex_data)
    return hex_data

'''Parses the arguments provided on the command line'''

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


'''Reads in file from the given entry point'''


def read_from_hex_offset(filename, hex_offset, buffer_size):
    filename = open(filename, 'rb')
    offset = int(hex_offset, base=16)

    filename.seek(offset, 0)
    data = filename.read(buffer_size)

    hex_data = binascii.hexlify(data)

    return hex_data


'''Calculates the REAL entry point of a file using the formula shown below'''


def get_entry_point(filename):
    pe = pefile.PE(filename)  # Takes the filename from command line argument and loads PE file

    ep_section = find_entry_point_section(pe, pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    delta = entry_point - ep_section.VirtualAddress

    actual_entry_point = ep_section.PointerToRawData + delta

    entry_point = hex(actual_entry_point)
    return entry_point


'''Finds and returns the section that contains the entry point'''


def find_entry_point_section(pe, entry_point):
    for section in pe.sections:
        if section.contains_rva(entry_point):
            return section

    return None


main()
