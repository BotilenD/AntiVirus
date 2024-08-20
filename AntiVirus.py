import os
import requests

def list_files_in_directory(directory):
    file_paths = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_paths.append(os.path.join(root, file))
    return file_paths

def get_report(file_path, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
    response = requests.post(url, files=files, params=params)
    return response.json()

def main():
    directory_path = input("Enter the path of the directory to scan: ")
    api_key = input("Enter your VirusTotal API key: ")

    files = list_files_in_directory(directory_path)
    for file in files:
        print(f"Scanning {file}...")
        report = get_vt_report(file, api_key)
        print(report)

if __name__ == "__main__":
    main()
