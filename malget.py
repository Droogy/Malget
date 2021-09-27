# Malget by Droogy
#
# Your own personal malware feed!
#

from apiCreds import MALSHAREKEY, VTKEY
import os
import requests
import json
from time import sleep
import argparse
import sys
import concurrent.futures

def createDir():
    '''
    Check if we have directories to hold the samples
    and their subsequent categories
    '''
    # handle the "FileExistsError" if the dir exists
    folders = ["./pe_file", "./elf_file", "./zip_file", "./misc"]
    for folder in folders:
        try:     
            os.mkdir(folder)
        except OSError:
            print(f"{folder} already exists, skipping...")
            continue

def grabHashes():
    '''
    query Malshare for ALL samples from last 24h
    '''
    # initialize sha1hashes which contains ALL hashes from last 24 hrs
    global sha1hashes
    payload = {"api_key": MALSHAREKEY, "action": "getlist"}
    r = requests.get("https://malshare.com/api.php", params=payload)
    raw_hashlist = r.text
    loadedJSON = json.loads(raw_hashlist)
    sha1hashes = [hash["sha1"] for hash in loadedJSON]

def downloadSamples():
    '''
    download specified amount of samples we just queried from Malshare
    ''' 
    print("""
        ===========================================================
        Downloading samples from Malshare, this may take a while...
        ===========================================================
        """)
    for hash in sha1hashes[:args.number]:
        payload = {"api_key": MALSHAREKEY, "action": "getfile", "hash": hash}
        r = requests.get("https://malshare.com/api.php", params=payload)
        sample = r.content
        with open(hash, "wb") as fh:
            print(f"Downloading {hash}...")
            fh.write(sample)

def first4Bytes(file2read):
    '''
    Returns first four hex-encoded bytes of a file
    '''
    with open(file2read, "rb") as fd:
        return fd.read(4)

def getKey(invalue):
    '''
    Returns a key when given a dictionary value
    '''
    for key, value in magicTypes.items():
        if invalue == value:
            return key

def queryVT(sampleHash):
    '''
    query VT to see if we can get names for each sha1 hash passed to this function
    '''
    header = {"x-apikey":VTKEY}
    url = f"https://www.virustotal.com/api/v3/files/{sampleHash}"
    vtRequest = requests.get(url, headers=header)
    JSONData = vtRequest.json()
    JSONArray.append(JSONData)

def renameSamples():
    '''
    rename the samples if we found anything on VT
    '''
    print("""
        =============================
        Attempting to name samples...
        =============================
        """)
    for file in sha1hashes[:args.number]:
        for fileQuery in JSONArray:
            try:
                fileName = fileQuery["data"]["attributes"]["meaningful_name"]
                if str(file) == fileQuery["data"]["attributes"]["sha1"]:
                    print(f"[*] {file} was identified as {fileName} ")
                    os.replace(file, f"{fileName}")
            except KeyError:
                print(f"[*] {file} was not in VirusTotal results, not naming it...")
                continue

def classifySamples():
    '''
    classify the files based on their filetype and move them
    to their respective folder
    '''
    global magicTypes
    print("""
        ===================================
        Classifying samples by magic bytes
        ===================================
        """)
    # dictionary storing our magic bytes and associated filetype
    magicTypes = { "pe_file": b'\x4d\x5a\x90\x00', 
        "elf_file": b'\x7f\x45\x4c\x46', 
        "zip_file": b'\x50\x4b\x03\x04' }
    # make a list containing ONLY files from current directory
    files = [ file for file in os.listdir(os.curdir) if os.path.isfile(file)]
    for file in files:
        if first4Bytes(file) in magicTypes.values():
            print(f"{file} is a {getKey(first4Bytes(file))}")
            os.replace(f"./{file}", f"{getKey(first4Bytes(file))}/{file}")
        else:
            print(f"{file} is not in our magic dictionary, moving to misc/")
            os.replace(f"./{file}", f"misc/{file}")

if __name__ == '__main__':
    global parser
    global JSONArray
    # all of our VT data will be stored in this array, memory be damned!
    JSONArray = []
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--number", type=int, help="number of samples to download")
    args = parser.parse_args()
    if args.number:
        print("[*] Creating directory structure")
        createDir()
        print("[*] Grabbing list of hashes from Malshare")
        grabHashes()
        print("[*] Looking up these hashes on VirusTotal")  
        
        # slice the global variable "sha1hashes" to grab specified number
        for hash in sha1hashes[:args.number]:
            queryVT(hash)
            sleep(.25)  # sleep to abide by VT's 4/min requests API cap
        
        # debugging print statement to make sure hashes are correct
        #print(f"Printing the hashes we found:\n{sha1hashes[:args.number]}")
        downloadSamples()  
        renameSamples()
        classifySamples()
        
        with open("VTResults.json", "w") as outfile:
            json.dump(JSONArray, outfile)

        with open("sampleHashes.txt", "w") as outfile:
            outfile.write(str(sha1hashes[:args.number]))
    
    elif not len(sys.argv) > 1:
        print("Add --help for usage")

