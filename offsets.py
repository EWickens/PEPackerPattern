"""This offsets class is to be used to calculate the offsets for the seek command
    Such offsets to be determined will be DOS/OPTIONAL/IMPORT_TABLE/IMAGE_IMPORT_DESCRIPTOR"""
import subprocess
try:
    import pefile
except:
    subprocess.call(['pip', 'install', 'pefile'])



# TODO Could use pefiles inbuilt offset parsing functionality or could use the raw hex data at particular offsets
def main():
    filename = "Armadillo/0BCED4EBFC8207ED7952FAB04DF579065FB6785AD76902D71184EBD4D70B07B4"

    pe = pefile.PE(filename)

    # info = pe.Dump()
    get_section_entry_point(pe)


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


# TODO TRUNCATE DICTIONARY OR CREATE MY OWN
def get_section_entry_point(pe):
    section_header_data = list()
    parsed_list = list()

    for section in pe.sections:
        print(section)
        section_header_data.append(section.dump_dict())

    temp = {}

    for each in range(len(section_header_data)):
        for k, v in section_header_data[each].iteritems():
            print(k, v)

            for left in v.iteritems():
                print("TEST LOOP" + str(left))

    print(temp)


main()
