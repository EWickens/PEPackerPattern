"""This offsets class is to be used to pull information from the PEFile library
  and format the data into a more workable format.Example of info to be pulled = DOS/OPTIONAL/IMPORT_TABLE/IMAGE_IMPORT_DESCRIPTOR"""
import subprocess

try:
    import pefile
except ImportError:
    subprocess.call(['pip', 'install', 'pefile'])


# TODO Could use pefiles inbuilt offset parsing functionality or could use the raw hex data at particular offsets
def main():
    filename = "Armadillo/0BCED4EBFC8207ED7952FAB04DF579065FB6785AD76902D71184EBD4D70B07B4"

    pe = pefile.PE(filename)

    section_header_data = get_section_headers_data(pe)

    optional_header_data = get_optional_header_data(pe)

    import_data = get_image_entry_import_data(pe)

    dos_header_data = get_dos_header_data(pe)

    imphash = pe.get_imphash()

    rsrc_list = get_rsc_data(pe)

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

#TODO Check if DLL and if DLL get this info, might want to check for this anyway - could use this as the check if it is a DLL?
def get_dll_export_data(pe):

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal

#TODO TEST AGAINST A FILE WITH KNOWN RESOURCES IN ITS DIRECTORY
def get_rsc_data(pe):

    rsrc_list = []
    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            print(entry)
            if entry.name is not None:
                rsrc_list.append(entry.name)
                print(entry)
    return rsrc_list


if __name__ == "__main__":
    main()
