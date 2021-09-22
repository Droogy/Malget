# Malget

Your own personal malware feed!

## Description

Malget is a Python script which downloads, classifies, and names the latest malware samples from Malshare with a little help from the VirusTotal API.

I created this originally because I was practicing creating YARA, Sigma, and Snort rules but I didn't have live samples to work with. While you can get samples from some databases they may not be updated often or it becomes tedious grabbing a sample, dragging it over to a folder, naming it, etc..

## Example Output

[Screenshot](assets/screenshot.png)

## Getting Started

### Dependencies

* You must have VirusTotal and Malshare API keys for this program to work
* Once you have the keys, place them in [apiCreds.py](apiCreds.py) and you are good to go
* all of the libraries used in Malget are in the Python Standard Library 

### Executing program

* the `-n` argument is used the specify the number of samples you want to download (note that Malshare and VirusTotal have daily API limits)
```python
# download and classify 10 samples
python3 malget.py -n 10
```
## To-Do
* multi-thread everything
* need more error handling
* unit testing and profiling sessions are needed to help refactor code
## Help

```
python3 malget.py --help
```

## Authors

[@xDroogy](https://twitter.com/xDroogy)
