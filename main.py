import os
import requests


API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")


def check_is_file_safe_with_virustotal(file_location: str, file_size_in_mb: int) -> bool:
    url = "https://www.virustotal.com/api/v3/files"
    if file_size_in_mb >= 32:
        url = "https://www.virustotal.com/api/v3/files/upload_url"
    
    headers = {"x-apikey": API_KEY}
    with open(file_location, "rb") as file:
        files = {"file": file}
        response = requests.post(url, headers=headers,files=files)
    analysys_link = response.json()["data"]["links"]["self"]
    analysys_response = requests.get(analysys_link, headers=headers)
    analysys_data = analysys_response.json()["data"]["attributes"]["stats"]
    return analysys_data["malicious"] != 0 or analysys_data["suspicious"] != 0


def check_file_danger(file_location: str) -> bool:
    if (not os.path.exists(file_location)):
        raise Exception("Enter a proper file location")
    
    file_size_in_mb = os.path.getsize(file_location) // (1024 * 1024)

    
    return check_is_file_safe_with_virustotal(file_location, file_size_in_mb)


def main():
    file_to_scan_location = input("Enter file location: ")
    print(f'The file "{file_to_scan_location}" is ', end="")
    if (check_file_danger(file_to_scan_location)):
        print("dangerous")
    else:
        print("safe")   


if __name__ == "__main__":
    main()