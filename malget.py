# Malget by Droogy
#
# Get malware really fast
#

from creds import MALSHAREKEY, VTKEY
import os
import requests
import json
from time import sleep

def createDir():
    '''
    Check if we have directories to hold the samples
    and their subsequent categories
    '''
    # handle the "FileExistsError" if the dir exists
    folders = ["./pe_files", "./elf_files", "./zip_file", "./misc"]
    for folder in folders:
        try:     
            os.mkdir(f"{folder}")
        except OSError:
            print(f"{folder} already exists, skipping...")
            continue

def grabHashes():
    '''
    query Malshare for the last 100 samples from the feed
    '''
    global sha1hashes
    payload = {"api_key": f"{MALSHAREKEY}", "action": "getlist"}
    r = requests.get("https://malshare.com/api.php", params=payload)
    raw_hashlist = r.text
    loadedJSON = json.loads(raw_hashlist)
    sha1hashes = [hash["sha1"] for hash in loadedJSON]

def downloadSamples():
    '''
    download the samples we just queried
    ''' 
    for hash in sha1hashes[:5]:
        payload = {"api_key": f"{MALSHAREKEY}", "action": "getfile", "hash": f"{hash}"}
        r = requests.get("https://malshare.com/api.php", params=payload)
        sample = r.content
        with open(f"{hash}", "wb") as fh:
            print(f"Downloading {hash}...")
            fh.write(sample)

def createJSON(firstHash):
    '''
    Initialize the "VTResults.json" file and populate with results from first hash
    '''
    header = {"x-apikey":f"{VTKEY}"}
    url = f"https://www.virustotal.com/api/v3/files/{firstHash}"
    vtRequest = requests.get(url, headers=header)
    with open("VTResults.json", "w") as infile:
        json.dump(vtRequest.json(), infile)

def queryVT(sampleHash):
    '''
    query VT to see if we can get names for sha1 hash passed to this function
    '''
    global JSONArray
    header = {"x-apikey":f"{VTKEY}"}
    url = f"https://www.virustotal.com/api/v3/files/{sampleHash}"
    vtRequest = requests.get(url, headers=header)
    JSONData = vtRequest.json()
    # all of our VT data will be stored in this array, memory be damned!
    JSONArray = []
    JSONArray.append(JSONData)

def renameSamples():
    '''
    rename the samples if we found anything on VT
    '''
    # get list of only files in current directory
    files = [ file for file in os.listdir(os.curdir) if os.path.isfile(file)]
    # load up file for reading
    with open("./VTResults.json", "r") as infile:
        JSON_Data = json.load(infile)
    # extract sha1 hashes from JSON
    VT_Hashes = JSON_Data["data"]["attributes"]["sha1"]
    # extract file-names from JSON
    VT_Filenames = JSON_Data["data"]["attributes"]["names"]
    filesAndHashes = dict(zip(VT_Hashes, VT_Filenames))
    print(f"Printing hashes\n{VT_Hashes}")
    print(f"Printing filenames\n{VT_Filenames}")
    print(f"Printing files+hashes\n{filesAndHashes}")
    """
    for file in files:
        if str(file) in VT_Hashes:
            print(f"{str(file)}: Original name was {JSON_Data['sha1'].__str__()}")     
    """
def classifySamples():
    '''
    classify the files based on their filetype and move them
    to their respective folder
    '''
    # dictionary storing our magic bytes and associated filetype
    magicTypes = { "pe_file": b'MZ\x90\x00', 
        "elf_file": b'\x7fELF', 
        "zip_file": b'PK\x03\x04' }
    # make a list containing ONLY files from current directory
    files = [ file for file in os.listdir(os.curdir) if os.path.isfile(file)]
    for file in files:
        if first4Bytes(file) in magicTypes.values():
            print(f"{file} is a {getKey(first4Bytes(file))}")
            os.rename(f"./{file}", f"{getKey(first4Bytes(file))}/{file}")
        else:
            print(f"{file} is not in our magic dictionary")

def first4Bytes(file2read):
    with open(file2read, "rb") as fd:
        return fd.read(4)

def getKey(invalue):
    for key, value in magicTypes.items():
        if invalue == value:
            return key

    pass

if __name__ == '__main__':
    # if VT file exists, we just need to download and classify samples
    if os.path.exists("VTResults.json"):
        print("""
        VirusTotal results already found...time to name and shame samples
        """)
        #downloadSamples()  
        renameSamples()
        #classifySamples()
    # if the VT file doesn't exist, then we run all of our functions
    else:
        print("[*] Creating directory structure")
        createDir()
        print("[*] Grabbing list of hashes from Malshare")
        grabHashes()
        print("[*] Looking up these hashes on VirusTotal")
        
        #createJSON(sha1hashes[0])
        # slice the global variable "sha1hashes" to grab first 100
        """
        for hash in sha1hashes[:5]:
            queryVT(hash)
            sleep(.25)  # sleep to abide by VT's 4/min requests API cap
        with open("VTResults.json", "w") as outfile:
            json.dump(JSONArray, outfile)
        """
        downloadSamples()  
        #renameSamples()
        #classifySamples()