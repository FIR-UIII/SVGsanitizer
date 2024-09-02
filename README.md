  ______     ______                   _ _   _              
 / ___\ \   / / ___|  ___  __ _ _ __ (_) |_(_)_______ _ __ 
 \___ \\ \ / / |  _  / __|/ _` | '_ \| | __| |_  / _ \ '__|
  ___) |\ V /| |_| | \__ \ (_| | | | | | |_| |/ /  __/ |   
 |____/  \_/  \____| |___/\__,_|_| |_|_|\__|_/___\___|_| 


Hosts that process SVG can potentially be vulnerable to SSRF, LFI, XSS, RCE because of the rich feature set of SVG.
https://github.com/allanlw/svg-cheatsheet

Create malitious SVG https://github.com/surajpkhetani/AutoSmuggle
https://github.com/darylldoyle/svg-sanitizer/tree/master/tests/data

Use samples

Read the SVG file content
Parse the SVG XML structure
    https://pypi.org/project/svgelements/
    https://realpython.com/python-xml-parser/#choose-the-right-xml-parsing-model
Remove potentially malicious elements and attributes
Validate remaining elements against a whitelist
Convert sanitized SVG back to XML string
Save sanitized SVG file

https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html
https://github.com/paulmuenzner/image-malware-detection-and-sanitization/
https://docs.python.org/3/library/xml.html#xml-vulnerabilities

Search for XXE and remove it
Search for DTD and remove it
Search for XSS and remove it