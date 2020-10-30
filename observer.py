import argparse
import hashlib
import json
import magic
import pefile
import sys
import os
import requests

#Compute MD5 Hash to check against known malicious file signatures
def compute_md5_hash(file_name):
    md5_hash = hashlib.md5()
    file = open(file_name, "rb")
    file_content = file.read()
    md5_hash.update(file_content)
    md5_digest = md5_hash.hexdigest()
    file.close()
    return md5_digest

def compute_sha1_hash(file_name):
    sha1_hash = hashlib.sha1()
    file = open(file_name, "rb")
    file_content = file.read()
    sha1_hash.update(file_content)
    sha1_digest = sha1_hash.hexdigest()
    file.close()
    return sha1_digest

def compute_sha256_hash(file_name):
    sha256_hash = hashlib.sha256()
    file = open(file_name, "rb")
    file_content = file.read()
    sha256_hash.update(file_content)
    sha256_digest = sha256_hash.hexdigest()
    file.close()
    return sha256_digest

def compute_ssdeep_hash(file_name):
    return ssdeep.hash_from_file(file_name)


def virus_total_check(md5_result, file_name):
    url = f'https://www.virustotal.com/api/v3/files/{md5_result}'
    headers = {'x-apikey': ''}
    r = requests.get(url, headers=headers)
    analysis = r.json()

    report_dict={
    "last_analysis_date": analysis["data"]["attributes"]["last_analysis_date"],
    "harmless": analysis["data"]["attributes"]["last_analysis_stats"]["harmless"],
    "malicious": analysis["data"]["attributes"]["last_analysis_stats"]["malicious"],
    "suspicious": analysis["data"]["attributes"]["last_analysis_stats"]["suspicious"],
    "undetected": analysis["data"]["attributes"]["last_analysis_stats"]["undetected"],
    "reputation": analysis["data"]["attributes"]["reputation"],
    }

    return report_dict

def pefunc(filename):
    pe = pefile.PE(filename)
    attribute_list = []
    pe_dll_list = []
    pe_export_list = []
    # Check if it is a 32-bit or 64-bit binary
    if hex(pe.FILE_HEADER.Machine) == '0x14c':
        pe_architecture = "32-bit"
    else:
        pe_architecture = "64-bit"

    attribute_list.append(pe_architecture)

    pe_TimeDateStamp = pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]
    attribute_list.append(pe_TimeDateStamp)
    #Information about each section and its hash
    section_list = []
    for section in pe.sections:
        index = str(section.Name).find('\\')
        section_list.append([str(section.Name)[2:index], "Virtual Address: " + hex(section.VirtualAddress), "Virtual Size: " + hex(section.Misc_VirtualSize), "Raw Size: " + hex(section.SizeOfRawData),section.get_hash_md5()])

    attribute_list.append(section_list)
    #Check the imports against the list of imports in PMA
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            temp_str = (str(entry.dll)[1:]).strip('\'')
            temp_functions_list = []
            pe_dll_list.append(temp_str)
            for imp in entry.imports:
                if imp.name != None:
                    temp_func_str = (str(imp.name)[1:]).strip('\'')
                    temp_functions_list.append(temp_func_str)
            pe_dll_list.append(temp_functions_list)

    attribute_list.append(pe_dll_list)

    #Generate an ImpHash
    pe_imphash = pe.get_imphash()
    attribute_list.append(pe_imphash)

    #List Exports
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        export_list = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            export_list.append(exp.name)
        attribute_list.append(export_list)


    return attribute_list

def pe_generate_report(file_name, file_size, md5_result, sha1_result, sha256_result, pe_attribute_list, virustotal_report_object):
    #Minimum report statistics
    general_dict = {
    'Name': file_name,
    'File Size' : file_size,
    'MD5 Hash' : md5_result,
    'SHA1 Hash' : sha1_result,
    'SHA256 Hash' : sha256_result,
    'Machine Architecture' : pe_attribute_list[0],
    'TimeDateStamp' : pe_attribute_list[1],
    }

    try:
        true_section_dict = {'Section':{}}
        for i in range(len(pe_attribute_list[2])):
            true_section_dict['Section'][pe_attribute_list[2][i][0]] = {}

        for i in range(len(pe_attribute_list[2])):
            index = pe_attribute_list[2][i][3].find(':')
            true_section_dict['Section'][pe_attribute_list[2][i][0]]['VirtualAddress'] = (pe_attribute_list[2][i][1])[17:]
            true_section_dict['Section'][pe_attribute_list[2][i][0]]['VirtualSize'] = (pe_attribute_list[2][i][2])[14:]
            true_section_dict['Section'][pe_attribute_list[2][i][0]]['RawSize'] = (pe_attribute_list[2][i][3])[10:]
            true_section_dict['Section'][pe_attribute_list[2][i][0]]['SectionHash'] = pe_attribute_list[2][i][4]

    except:
        print("Found no Sections.")


    try:
        import_dict = {'Imports':{}}
        for i in range(0, len(pe_attribute_list[3]), 2):
            import_dict['Imports'][pe_attribute_list[3][i]] = [pe_attribute_list[3][i+1]]

    except:
        print("Found no imports.")

    virustotal_dict = {'VirusTotal': {}}
    virustotal_dict['VirusTotal']["last_analysis_date"] = virustotal_report_object["last_analysis_date"]
    virustotal_dict['VirusTotal']['harmless'] = virustotal_report_object["harmless"]
    virustotal_dict['VirusTotal']['malicious'] = virustotal_report_object["malicious"]
    virustotal_dict['VirusTotal']['suspicious'] = virustotal_report_object["suspicious"]
    virustotal_dict['VirusTotal']['undetected'] = virustotal_report_object["undetected"]
    virustotal_dict['VirusTotal']['reputation'] = virustotal_report_object["reputation"]

    final_report_dict = {}
    for d in (general_dict, true_section_dict, import_dict, virustotal_dict):
        final_report_dict.update(d)


    with open(f'{sha256_result}_report.json', 'w') as json_file:
        json.dump(final_report_dict, json_file, indent=4)


if __name__ == "__main__":

    file_name = sys.argv[1]
    file_size = (os.stat(file_name).st_size/(1024*1024))

    md5_result = compute_md5_hash(file_name)
    sha1_result = compute_sha1_hash(file_name)
    sha256_result = compute_sha256_hash(file_name)
    magic_result = magic.from_file(file_name)
    virustotal_report_object = virus_total_check(md5_result, file_name)
    if 'PE32' in magic_result:
        pe_attribute_list = pefunc(file_name)
        pe_generate_report(file_name, file_size, md5_result, sha1_result, sha256_result, pe_attribute_list, virustotal_report_object)
