"""This offsets class is to be used to calculate the offsets for the seek command
    Such offsets to be determined will be DOS/OPTIONAL/IMPORT_TABLE/IMAGE_IMPORT_DESCRIPTOR"""
import subprocess

try:
    import pefile
except ImportError:
    subprocess.call(['pip', 'install', 'pefile'])


# TODO Could use pefiles inbuilt offset parsing functionality or could use the raw hex data at particular offsets
def main():
    filename = "Armadillo/0BCED4EBFC8207ED7952FAB04DF579065FB6785AD76902D71184EBD4D70B07B4"

    pe = pefile.PE(filename)

    get_section_headers_data(pe)

    get_optional_header_data(pe)

    get_image_entry_import_data(pe)

def calculate_actual_entry_point(filename):
    pe = pefile.PE(filename)  # Takes the filename from command line argument and loads PE file

    ep_section = find_entry_point_section(pe, pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    if ep_section is not None:
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        delta = entry_point - ep_section.VirtualAddress

        actual_entry_point = ep_section.PointerToRawData + delta

        entry_point = hex(actual_entry_point)
        return entry_point
    else:
        return


def find_entry_point_section(pe, entry_point):
    for section in pe.sections:
        if section.contains_rva(entry_point):
            return section

    return None


"""Returns a list of lists of dictionaries containing the key:value pair of all the info of each of the section headers"""


# TODO RESULTS FROM THE HEADER ARE STORED IN BASE 10 and not HEX for the time being
def get_section_headers_data(pe):
    section_header_data = list()

    for section in pe.sections:
        # print(section)
        section_header_data.append(section.dump_dict())

    temp_list = []

    print section_header_data
    for each in section_header_data:
        print each
        temp = dict()
        for key in each.keys():
            if type(each[key]) == type(dict()):
                temp[key] = each[key]['Value']
        temp_list.append(temp)

    return temp_list

# TODO GENERIFY THESE FUNCTIONS BY PASSING IN HEADER TYPE
def get_optional_header_data(pe):
    dos_header_data = pe.OPTIONAL_HEADER.dump_dict()

    temp_list = []

    for key in dos_header_data.keys():
        temp = dict()
        if type(dos_header_data[key]) == type(dict()):
            temp[key] = dos_header_data[key]['Value'] # ERROR BEING THROWN HERE
            temp_list.append(temp)

    return temp_list

def get_image_entry_import_data(pe):
    print("Hi")

def get_dos_header_data(pe):
    dos_header = pe.DOS_HEADER

    print(dos_header)

if __name__ == "__main__":
    main()
