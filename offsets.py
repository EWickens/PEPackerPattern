"""This offsets class is to be used to pull information from the PEFile library
  and format the data into a more workable format.Example of info to be pulled = DOS/OPTIONAL/IMPORT_TABLE/IMAGE_IMPORT_DESCRIPTOR"""
import string
import subprocess
from pyasn1.codec.native.decoder import decode
from pyasn1_modules import rfc2459, rfc2315

try:
    import pefile
except ImportError:
    subprocess.call(['pip', 'install', 'pefile'])


# TODO Could use pefiles inbuilt offset parsing functionality or could use the raw hex data at particular offsets
def main():
    filename = "ViralTest/One" # REPLACE WITH A FILE
    min_string_length = 8

    pe = pefile.PE(filename, fast_load=True)

    all_files_data = []

    all_files_data.append(get_file_data(pe, filename))

    filename = "Armadillo/JAVA.exe" # REPLACE WITH A SECOND FILE

    pe = pefile.PE(filename, fast_load=True)
    all_files_data.append(get_file_data(pe, filename))
    basic_compare(all_files_data)

def basic_compare(all_files_data):
    for diction in all_files_data:
        for each in diction.values():
            for next in each:
                for i in next:
                    print(i)

def get_file_data(pe, filename):
    file_data = []

    section_header_data = get_section_headers_data(pe)
    # print(section_header_data)
    file_data.append(section_header_data)
    optional_header_data = get_optional_header_data(pe)
    file_data.append(optional_header_data)
    # print(optional_header_data)
    import_data = get_image_entry_import_data(pe)
    file_data.append(import_data)
    # print(import_data)
    dos_header_data = get_dos_header_data(pe)
    file_data.append(dos_header_data)
    # print(dos_header_data)

    imphash = pe.get_imphash()
    # print(imphash)
    rsrc_list = get_rsc_data(pe)
    # print(rsrc_list)

    return_dict = {filename:file_data}
    return return_dict

    # sl = list(get_strings(filename, min_string_length))
    # print(sl)
    # cert_data = get_cert_data(pe)
    # print cert_data
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
def get_rsc_data(pe):
    rsrc_list = []
    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            if entry.name is not None:
                rsrc_list.append(entry.name)
                print(entry)
    return rsrc_list

#TODO FIX CERT DATA, seems to give me some trouble.
def get_cert_data(pe):  # If this gives trouble look at Didier Stevens tool disitool

    address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

    if address == 0:
        print 'Not Signed'
        return

    signature = pe.write()[address + 8:]

    (contentInfo, rest) = decode(signature, asn1Spec=rfc2315.ContentInfo())

    contentType = contentInfo.getComponentByName('contentType')
    print(contentType)
    if contentType == rfc2315.signedData:
        signedData = decode(
            contentInfo.getComponentByName('content'),
            asn1Spec=rfc2315.SignedData())

    for sd in signedData:
        if sd == '':
            continue

        signerInfos = sd.getComponentByName('signerInfos')
        for si in signerInfos:
            issuerAndSerial = si.getComponentByName('issuerAndSerialNumber')
            issuer = issuerAndSerial.getComponentByName('issuer').getComponent()
            for i in issuer:
                for r in i:
                    at = r.getComponentByName('type')
                    if rfc2459.id_at_countryName == at:
                        cn = decode(
                            r.getComponentByName('value'),
                            asn1Spec=rfc2459.X520countryName())
                        print(cn[0])
                    elif rfc2459.id_at_organizationName == at:
                        on = decode(
                            r.getComponentByName('value'),
                            asn1Spec=rfc2459.X520OrganizationName())
                        print(on[0].getComponent())
                    elif rfc2459.id_at_organizationalUnitName == at:
                        ou = decode(
                            r.getComponentByName('value'),
                            asn1Spec=rfc2459.X520OrganizationalUnitName())
                        print(ou[0].getComponent())
                    elif rfc2459.id_at_commonName == at:
                        cn = decode(
                            r.getComponentByName('value'),
                            asn1Spec=rfc2459.X520CommonName())
                        print(cn[0].getComponent())
                    else:
                        print at


if __name__ == "__main__":
    main()
