"""
SHIFU: CVE Finder Toolkit
"""

import json
import requests
import re

__version__ = "1.0.0"

# Colorize methods
def red(text):
    return "\033[31m" + text + "\033[0m"

def green(text):
    return "\033[32m" + text + "\033[0m"

def print_banner():
    print("""
    ┌────────────────────────────────────────────┐
    │                  SHIFU                     │
    │           CVE Finder Toolkit               │
    └────────────────────────────────────────────┘
    """)

def search_by_cve_id(cve_id, output_file=None):
    url = f"https://access.redhat.com/labs/securitydataapi/cve.json?ids={cve_id}"
    response = requests.get(url)

    if response.status_code == 200:
        cve_info = json.loads(response.text)[0]
        display_cve_info(cve_info)
        if output_file:
            save_to_file(cve_info, output_file)
    elif response.status_code == 404:
        print(f"CVE '{cve_id}' does not exist.")
    else:
        print(red(f"Error: Failed to retrieve CVE information. HTTP status code: {response.status_code}"))

def display_cve_info(cve_info):
    print("CVE Information:")
    for key, value in cve_info.items():
        print(f"{key.capitalize().replace('_', ' ')}: {value}")

def save_to_file(cve_info, output_file):
    with open(output_file, 'a') as file:
        file.write("CVE Information:\n")
        for key, value in cve_info.items():
            file.write(f"{key.capitalize().replace('_', ' ')}: {value}\n")
        file.write("\n")
    print(green(f"CVE Information has been saved to {output_file}"))

def valid_cve_ids(cve_ids):
    return all(re.match(r'^CVE-\d{4}-\d{4,}$', cve_id.strip()) for cve_id in cve_ids.split(","))

def get_user_input(prompt):
    return input(prompt).strip()

def process_cve_file(file_name):
    try:
        with open(file_name, 'r') as file:
            for line in file:
                search_by_cve_id(line.strip(), 'result-cves.txt')
    except FileNotFoundError:
        print(red(f"Error: File '{file_name}' not found."))

def run():
    print_banner()
    while True:
        input_method = input("Do you want to enter CVE IDs manually or provide a file? (manual/file): ").strip().lower()
        if input_method == 'manual':
            cve_ids = get_user_input("Enter CVE IDs separated by commas (e.g., CVE-2024-3096,CVE-2022-1234): ")
            if not cve_ids:
                print("No CVE IDs provided.")
                save_to_file({}, 'result-cves.txt')
                break
            elif valid_cve_ids(cve_ids):
                for cve_id in cve_ids.split(","):
                    search_by_cve_id(cve_id.strip(), 'result-cves.txt')
            else:
                print(red("Error: Invalid CVE ID format. Please provide valid CVE IDs separated by commas."))
        elif input_method == 'file':
            file_name = get_user_input("Enter the name of the file containing CVE IDs: ")
            process_cve_file(file_name)
        else:
            print(red("Error: Invalid input method. Please choose 'manual' or 'file'."))

        answer = input("Do you want to perform another search? (y/n): ").strip().lower()
        if not answer.startswith('y'):
            break

    print("Thanks for using SHIFU!")

if __name__ == "__main__":
    run()
