import argparse
import csv
import os
import sys
import pefile


def main():
    buffer_size = 40

    args = parse_arguments()

    if args.filename is not None:
        get_data(file, buffer_size, args)


def get_data(file, buffer_size, args):
    file = args.filename
    entry_point = get_entry_point(file, buffer_size)
    hex_data = read_from_hex_offset(file, entry_point, buffer_size)

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


def get_entry_point(file, buffer_size):
    pe = pefile.PE(file)  # Takes the filename from command line argument and loads PE file
    entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    return entry_point

def read_from_hex_offset(file, hex_offset, buffer_size):
    file = open(file)

    offset = int(hex_offset, base=16)
    file.seek(offset, 0)

    data = file.read(buffer_size)

    return hex_data


main()
