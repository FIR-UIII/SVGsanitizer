import os
from lxml import etree
import defusedxml
import defusedxml.ElementTree as DET
import re

def parse_svg(svg_file):
    try:
        # Parse the SVG content using safe lib defusedxml
        tree = DET.parse(svg_file)
        root = tree.getroot()
        
        print(f"[*] Parsing successful. File name: {os.path.basename(svg_file)}")
        
        # Detect and report vulnerabilities
        detect_vulnerabilities(root)
        
        # Print SVG metadata
        print("\n===================\nSVG Metadata:")
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

def detect_vulnerabilities(root):
    print("[*] Detecting vulnerabilities:")

    # Parse child elements
    child = []
    child.append([elem.tag for elem in root.iter()])
    child = child[0]
    
    # Check for DTD XML
    check_dtd(root)

    # Check for XXE vulnerabilities
    check_xxe(root)
    
    # [+] Check for XSS vulnerabilities
    check_xss(root)
    
    # Check for external resource references
    check_external_resources(root)
    
    # Check for malicious attributes
    check_malicious_attributes(root)

def check_dtd(root):
    pass

def check_xxe(element):
    # Look for XML External Entity (XXE) attacks
    if element.tag.endswith('['):
        entity_name = re.search(r'&(\w+;)', element.text).group(1)
        print(f"Potential XXE vulnerability detected: &{entity_name};")

def check_xss(root):
    # Look for Cross-Site Scripting (XSS) attempts
    script_tags = [elem.tag for elem in root.iter() if re.search(r'script', elem.tag, re.IGNORECASE)]
    print(f">>> Potential XSS vulnerability detected in element: {script_tags}")

def check_external_resources(element):
    # Check for external resource references
    if element.attrib.get('href'):
        print(f"External resource referenced: {element.attrib['href']}")

def check_malicious_attributes(element):
    # Check for potentially malicious attributes
    malicious_attrs = ['onmouseover', 'onclick', 'onload']
    for attr in malicious_attrs:
        if attr in element.attrib:
            print(f"Malicious attribute detected: {attr}")

def main():
    # file_path = input("Enter the path to the SVG file: ")
    file_path = '/Users/artem/Projects/SVGsanitizer/samples/Deny Of Service - Billion Laugh Attack.xml'

    if os.path.exists(file_path):
        parse_svg(file_path)
    else:
        print(f"The file {file_path} does not exist.")


def search_dtd_in_svg(svg_file):
    pattern = r'^<\?xml.*<!DOCTYPE.*?>'
    with open(svg_file, 'r', encoding='utf-8') as file:
        content = file.read()
    
    match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
    return print(f'found DTD{match}')

def search_entity_in_svg(svg_file):
    pattern = r'!ENTITY'
    with open(svg_file, 'r', encoding='utf-8') as file:
        content = file.read()
    
    match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
    return print(f'found !ENTITY{match}')

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

if __name__ == "__main__":
    add_banner()
    search_entity_in_svg('/Users/artem/Projects/SVGsanitizer/samples/XXE OOB Attack (Yunusov, 2013).xml')
    search_dtd_in_svg('/Users/artem/Projects/SVGsanitizer/samples/XXE OOB Attack (Yunusov, 2013).xml')
    main()