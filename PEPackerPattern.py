import argparse
import binascii
import os
from collections import Counter
import pefile
from fuzzywuzzy import fuzz

def main():
    args = parse_arguments()
    buffer_size = 40

    print("=========================================================================================")
    print("                 PEPacker YARA Rule Generator - USE WITH CAUTION!")
    print("=========================================================================================")
    print("\tThis Yara rule generator takes the initial first 40 bytes after the Entry Point of a PE file")
    print("\tIt then clusters these Hex Strings in similar clusters, and if a character repeatedly appears")
    print(
        "\tat a given index in over 80% of that cluster it will generate a rule from this data for to generate our own")
    print("\tYARA rules if we know its packed with a certain packer")
    print("\tLarger datasets are definitely preferable, I'll add functionality to allow the user to adjust the weights")
    print("=========================================================================================")

    if args.dir is not None:
        print("\tProcessing data after entry points...\n")
        files_dict = create_file_dictionary(args, buffer_size)
        cluster_lists = round_robin(files_dict)
        print_function(cluster_lists, len(files_dict))
    else:
        print("A directory must be specified for this tool to run, please ensure you have a large enough dataset")
        return


def print_function(cluster_lists, overall_length):
    est_covered = 0
    total_files = 0
    for each in range(len(cluster_lists)):
        total_files += len(cluster_lists[each])
        if len(cluster_lists[each]) > 4:
            final_out = calculate_most_common_at_index(cluster_lists[each])
            yara_output = format_function(final_out)
            print("\n=========================================================================================")
            print("Cluster " + str(each + 1) + " Generated Yara Rule")
            if len(cluster_lists[each]) < 10:
                print("Cluster size under 10 files, might want to increase size of dataset for increased efficacy")
            print("=========================================================================================")
            print("Num files in cluster: " + str(len(cluster_lists[each])) + "\n")
            print(yara_output + "\n")
            est_covered += len(cluster_lists[each])
        else:
            print("=========================================================================================")
            print("Cluster " + str(each + 1) + " was not big enough to create a rule with any accuracy")
            print("=========================================================================================")
            print("Num files in cluster: " + str(len(cluster_lists[each])) + "\n")

    print("Total files given as dataset:" + str(overall_length))
    print("Total files that were in the top 10 cluster: " + str(total_files))
    print("Estimated files covered by generated rules: " + str(est_covered))


def format_function(final_out):
    yara_output = "{ "

    for each in range(0, len(final_out), 2):
        yara_output += final_out[each].upper()
        yara_output += final_out[each + 1].upper()
        yara_output += " "

    yara_output += '}'
    return yara_output


'''Currently this tries to match the first 10 bytes of a file to determine clustering
    I think this is a poor way to cluster and will try to use fuzzywuzzy to replace this function for better clustering'''


def match_function(file1, file2): #TODO ADD IN CMD LINE VARIABLE TO ADJUST THE SIMILARITY RATIO
    if file1 != 0 and file2 != 0:
        val = fuzz.ratio(file1, file2)
        if val > 70:
            return True

        else:
            return False
    else:
        return

'''Calculate the occurences of a file at a given index in a file'''  # TODO Implement this


def calculate_most_common_at_index(cluster_list):
    final_out = list()
    index_list = list()

    for x in range(len(cluster_list[0])):
        index_list = list(zip(*cluster_list))[x]  # TODO MAYBE ADD IN A FEATURE TO IGNORE THE RESULT IF
        # THE INDEX HAS A HIGHER DEGREE OF ENTROPY

        first = Counter(index_list).most_common(1)[0][0]
        first_len = Counter(index_list).most_common(1)[0][1]

        num_clust = len(cluster_list)
        thresh = 0.90
        # Out of total occurrences if first is not a substantially high fraction then ignore it
        if (first_len / num_clust) < thresh:
            final_out.append("?")

        # Could also add in condition here that if first/second are the same then it appends asterix or develops new
        # rule
        else:
            final_out.append(first)

    return final_out


'''Uses round robin to iterate through each possible match without duplication of matches'''


def round_robin(files_dict):
    values = list(files_dict.values())

    # Might have to create an iterable cluster list here
    cluster_lists = [[] for i in range(50)]

    for amount_of_list in range(len(cluster_lists)):

        for x in range(len(values)):
            for y in range(x + 1, len(
                    values)):  # TODO DOUBLE CHECK THIS TO MAKE SURE ITS ITERATING THROUGH THE CORRECT BUFFER SIZE

                if match_function(values[x], values[y]):

                    if len(cluster_lists[amount_of_list]) != 0 and match_function(cluster_lists[amount_of_list][0],
                                                                                  values[y]):
                        cluster_lists[amount_of_list].append(values[y])

                    elif len(cluster_lists[amount_of_list]) == 0:  # If its the first file of the loop
                        cluster_lists[amount_of_list].append(values[y])

                elif not match_function(values[x], values[y]):
                    continue

            values = [x for x in values if x not in cluster_lists[amount_of_list]]

    cluster_lists.sort(key=len, reverse=True)

    ret_list = list()
    for x in range(len(cluster_lists)):
        if len(cluster_lists[x]) > 2:
            ret_list.append(cluster_lists[x])
            print(len(cluster_lists[x]))
    return ret_list


''' Matches two files and returns a dictionary with which of the hex matches'''

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
                dictionary[filename] = hex_data
        except pefile.PEFormatError:
            continue

    return dictionary


def get_data(filename, buffer_size):
    entry_point = get_entry_point(filename)
    hex_data = read_from_hex_offset(filename, entry_point, buffer_size)

    print("\t" + hex_data)
    return hex_data


'''Parses the arguments provided on the command line'''


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Compare a section of bytes in multiple files, located after the entry point, to aid in the creation of packer detection yara rules")

    parser.add_argument("-b", "--buffer", dest="buffer",
                        help="Specifies how many 0's to look for default is - Default is 40 bytes",
                        # TODO Determine correct buffer size
                        metavar="<buffSize>")
    parser.add_argument("-d", "--dir", metavar="<dir>",
                        help="Specify directory of files to scan")
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
