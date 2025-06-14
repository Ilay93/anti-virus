import os
import requests


API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")



def check_file_danger(location: str, api_key: str) -> bool:
    pass


def get_file_data(location: str) -> str:
    pass


def check_file_with_virustotal(file_data: str, api_key: str):
    pass


def validate_file_location(location: str) -> bool:
    pass


def main():
    file_location = input("Enter file location: ")
    print(f'The file "{file_location}" is ', end="")
    if (check_file_danger(file_location, API_KEY)):
        print("dangerous")
    else:
        print("safe")


if __name__ == "__main__":
    main()