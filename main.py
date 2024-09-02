import os
from lxml import etree
import re 
import defusedxml
import defusedxml.ElementTree as DET


def parse_svg(svg_file):
    try:
        # Parse the SVG content using safe lib defusedxml
        tree = DET.parse(svg_file)
        root = tree.getroot()
        
        print(f"\n===================\n[*] Parsing successful. File name: {os.path.basename(svg_file)}")
        print("SVG Metadata:")
        print(f"Title: {root.get('title')}")
        print(f"Width: {root.get('width')}")
        print(f"Height: {root.get('height')}")
        print(f"ViewBox: {root.get('viewBox')}")
        
    except etree.XMLSyntaxError as e:
        print(f"XML Syntax Error: {e}")
    except FileNotFoundError:
        print("The file was not found.")
    except defusedxml.common.EntitiesForbidden:
        print(f'[*] Detecting vulnerabilities:\n>>> Found Entities in file. Due to risk of DoS - skipping parsing process. Please remove !ENTITY and try again')
    except Exception as e:
        print(f"An error occurred: {e}")


def search_entity_in_svg(content):
    '''Search for XXE'''
    print('[+] Step 1. Searching for XXE')
    pattern = r'<!ENTITY[^>]*>([\s\S]*?)>'
    match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)

    if match:  
        print(f'   [!] Found XXE {match}')     
        sanitized_content = re.sub(pattern, '', content)
        print('   [+] Content removed')
        return sanitized_content
    else:
        print('   [-] No XXE found')
        
    print('[+] Step 1. Done')
    return content


def search_dtd_in_svg(content):
    '''Search for DTD'''
    print('[+] Step 2. Searching for DTD')
    pattern = r'<!DOCTYPE[^>]*>([\s\S]*?)>'
    match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)

    
    if match:
        print(f'[!] Found DTD {match}')
        sanitized_content = re.sub(pattern, '', content)
        print('   [+] Content removed')
        return sanitized_content
    else:
        print('   [-] No DTD found')
        
    print('[+] Step 2. Done')
    return content


def search_xss(content):
    '''Search for XSS'''
    print('[+] Step 3. Searching for XSS')
    pattern = r'<script[^>]*>([\s\S]*?)<\/script>'
    pattern1 = r'<(.*)onload(.*)'
    pattern2 = r'<(.*)alert(.*)'
    pattern3 = r'<(.*)script(.*)'
    match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
    match1 = re.search(pattern1, content, re.IGNORECASE | re.DOTALL)
    match2 = re.search(pattern2, content, re.IGNORECASE | re.DOTALL)
    match3 = re.search(pattern3, content, re.IGNORECASE | re.DOTALL)
    
    check = any(i is not None for i in [match, match1, match2, match3])
    if check:
        print(f'   [!] Found XSS {match}')
        sanitized_content = re.sub(pattern, '', content)
        content = sanitized_content
        sanitized_content = re.sub(pattern1, '', content)
        content = sanitized_content
        sanitized_content = re.sub(pattern2, '', content)
        content = sanitized_content
        sanitized_content = re.sub(pattern3, '', content)
        content = sanitized_content
        print('   [+] Content removed')
        return sanitized_content
    
    else:
        print('   [-] No XSS found')
        
    print('[+] Step 3. Done')
    return content


def safe_save_content(filename, content):
    try:
        # Check if the file exists
        if not os.path.exists(filename):
            # Create the file if it doesn't exist
            open(filename, 'x').close()
        # Open the file in write mode
        with open(filename, 'w') as file:
            file.write(content)
        print(f"[+] Content saved successfully to {filename}")
    except IOError as e:
        print(f"[-] An error occurred while saving content: {e}")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")


def add_banner():
    banner_text = r'''
  ______     ______                   _ _   _              
 / ___\ \   / / ___|  ___  __ _ _ __ (_) |_(_)_______ _ __ 
 \___ \\ \ / / |  _  / __|/ _` | '_ \| | __| |_  / _ \ '__|
  ___) |\ V /| |_| | \__ \ (_| | | | | | |_| |/ /  __/ |   
 |____/  \_/  \____| |___/\__,_|_| |_|_|\__|_/___\___|_| 

 version v1.0
 author FIR-UIII
 '''
    print(banner_text)


def main():
    file_path = input("Enter the path to the SVG file: ")
    if os.path.exists(file_path):
        print(f"[+] File loading successful. File name: {os.path.basename(file_path)}")
    else:
        print(f"The file {file_path} does not exist.")    
    
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    first_check = search_entity_in_svg(content)
    second_check = search_dtd_in_svg(first_check)
    third_check = search_xss(second_check)

    safe_save_content('sanitized.svg', third_check)    
    
    # Parsing the sanitized file
    parse_svg('sanitized.svg')


if __name__ == "__main__":
    add_banner()
    main()