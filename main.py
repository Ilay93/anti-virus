import os
import requests


API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")


def check_file_danger(file_path: str) -> tuple[bool, bool]:
    file_size_in_mb = os.path.getsize(file_path) // (1024 * 1024)

    url = "https://www.virustotal.com/api/v3/files"
    if file_size_in_mb >= 32:
        url = "https://www.virustotal.com/api/v3/files/upload_url"
    
    headers = {"x-apikey": API_KEY}
    with open(file_path, "rb") as file:
        files = {"file": file}
        response = requests.post(url, headers=headers,files=files)
    
    if response.status_code != 200:
        raise Exception(f"uploading file {file_path} to virus total was unsuccessful")

    analysis_link = response.json()["data"]["links"]["self"]
    analysis_response = requests.get(analysis_link, headers=headers)

    if analysis_response.status_code != 200:
        raise Exception("viewing virus total results was unsuccessful")
    
    analysis_data = analysis_response.json()["data"]["attributes"]["stats"]

    return (analysis_data["malicious"] != 0, analysis_data["suspicious"] != 0)



def get_all_files_from_folder_path(folder_path: str) -> list[str]:
    files = []
    for (current_folder, _, files_in_current_folder) in os.walk(folder_path):
        for current_file in files_in_current_folder:
            files.append(current_folder + "\\" + current_file)

    return files


def scan_folder_danger(folder_path: str) -> dict[str, list[str]]:
    files_to_scan_paths = get_all_files_from_folder_path(folder_path)
    
    files_result = {
        "malicious_files": [],
        "suspicious_files": [],
        "good_files": []
    }


    for file_to_scan_path in files_to_scan_paths:
        is_file_mal, is_file_sus = check_file_danger(file_to_scan_path)

        if is_file_mal:
            files_result["malicious_files"].append(file_to_scan_path)
        
        
        if is_file_sus:
            files_result["suspicious_files"].append(file_to_scan_path)


        if not (is_file_mal or is_file_sus):
            files_result["good_files"].append(file_to_scan_path)


    return files_result


def main():
    folder_to_scan_path = input("Enter folder location: ")
    if (not os.path.exists(folder_to_scan_path)):
        raise Exception("Enter a proper folder location")

    results = scan_folder_danger(folder_to_scan_path)
    print(f"Malicious files found: {', '.join(results['malicious_files'])}")
    print(f"Suspicious files found {', '.join(results['suspicious_files'])}")
    print(f"Non dangerous files: {', '.join(results['good_files'])}")


if __name__ == "__main__":
    main()
