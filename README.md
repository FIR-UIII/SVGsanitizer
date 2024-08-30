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

Best practices:
    Don’t allow DTDs
    Don’t expand entities
    Don’t resolve externals
    Limit parse depth
    Limit total input size
    Limit parse time
    Favor a SAX or iterparse-like parser for potential large data
    Validate and properly quote arguments to XSL transformations and XPath queries
    Don’t use XPath expression from untrusted sources
    Don’t apply XSL transformations that come untrusted sources

