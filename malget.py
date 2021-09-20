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
    folders = ["./pe-files", "./elf-files", "./archives", "./misc"]
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
    pass

def queryVT(sampleHash):
    '''
    query VT to see if we can get names for sha1 hash passed to this function
    '''
    header = {"x-apikey":f"{VTKEY}"}
    url = f"https://www.virustotal.com/api/v3/files/{sampleHash}"
    vtRequest = requests.get(url, headers=header)
    JSON_File = vtRequest.json()
    with open("VTResults.json", "a") as outfile:
        json.dump(JSON_File, outfile)

def renameSamples():
    '''
    rename the samples if we found anything on VT
    '''
    files = [ file for file in os.listdir(os.curdir) if os.path.isfile(file)]
    JSON_Raw = open("./VTResults.json", "r")
    JSON_Data = json.load(JSON_Raw)
    #JSON_Data = json.loads("VTResults.json")
    VT_Hashes = JSON_Data["data"]["attributes"]["sha1"]
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
        # slice the global variable "sha1hashes" to grab first 100
        for hash in sha1hashes[:50]:
            queryVT(hash)
            sleep(.25)  # sleep to abide by VT's 4/min requests API cap
        #downloadSamples()  
        #renameSamples()
        #classifySamples()