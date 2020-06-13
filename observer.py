from pymongo import MongoClient
import pprint
import hashlib
import sys
import os
import requests
import json

#Connect to localhost MongoDB instance
client = MongoClient('localhost', 27017)
db = client.localhashes
hash_collection = db.md5hash
magic_number_collection = db.magic_number_data

#Compute MD5 Hash to check against known malicious file signatures
def compute_md5_hash(file_name):
    md5_hash = hashlib.md5()
    file = open(file_name, "rb")
    file_content = file.read()
    md5_hash.update(file_content)
    md5_digest = md5_hash.hexdigest()
    return md5_digest

#Return the purported file extension
def implicit_check(file_name):
    file_extension = (file_name[file_name.find(".")+1:]).upper()
    return file_extension

#Return the true file extension
def magic_check(file_name):
    f = open(file_name, "rb")
    num = f.read(4).hex()
    f.close()
    magic_check_extension = magic_number_collection.find_one({"magic_value":num})
    return magic_check_extension['file_type']

#Check against known malicious file signatures
def local_file_hash_check(md5_result):
    hash_check_result = hash_collection.find_one({"hash_value":md5_result})
    return hash_check_result

def virus_total_check(md5_result, file_name, file_size):
    url = 'https://www.virustotal.com/api/v3/files/52364b11f8cb77d83d6305b061a06e5a865f1eac'
    headers = {'x-apikey': ''}
    r = requests.get(url, headers=headers)
    analysis = r.json()

    report_name = file_name[:file_name.find(".")]+"_report.json"
    report_dict={
    "last_analysis_date": analysis["data"]["attributes"]["last_analysis_date"],
    "harmless": analysis["data"]["attributes"]["last_analysis_stats"]["harmless"],
    "malicious": analysis["data"]["attributes"]["last_analysis_stats"]["malicious"],
    "suspicious": analysis["data"]["attributes"]["last_analysis_stats"]["suspicious"],
    "undetected": analysis["data"]["attributes"]["last_analysis_stats"]["undetected"],
    "reputation": analysis["data"]["attributes"]["reputation"],
    "SHA1": analysis["data"]["attributes"]["sha1"],
    "SHA256": analysis["data"]["attributes"]["sha256"]
    }

    report_json_object = json.dumps(report_dict, indent=4)
    with open(report_name, "w") as outfile:
        outfile.write(report_json_object)




if __name__ == "__main__":
    file_name = sys.argv[1]
    file_size = (os.stat(file_name).st_size/(1024*1024))

    md5_result = compute_md5_hash(file_name)
    implcit_check_value = implicit_check(file_name)
    magic_check_value = magic_check(file_name)

    if implcit_check_value == magic_check_value:
        print('True file extension.')
    else:
        print('File extension masked.')

    local_file_hash_check_value = local_file_hash_check(md5_result)

    if local_file_hash_check_value == None:
        print('No local malicious file signature match found.')
    else:
        print('This is a malicious file! Please use a AV/AM solution to remove.')

    if file_size>32:
        print('Cannot perform VirusTotal verification. File size too large.')
    else:
        print('Performing VirusTotal verification...')
        virus_total_check(md5_result, file_name, file_size)

    print('Generating Report.')
