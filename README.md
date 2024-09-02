```
  ______     ______                   _ _   _              
 / ___\ \   / / ___|  ___  __ _ _ __ (_) |_(_)_______ _ __ 
 \___ \\ \ / / |  _  / __|/ _` | '_ \| | __| |_  / _ \ '__|
  ___) |\ V /| |_| | \__ \ (_| | | | | | |_| |/ /  __/ |   
 |____/  \_/  \____| |___/\__,_|_| |_|_|\__|_/___\___|_| 

```

### How to use
```
git clone https://github.com/FIR-UIII/SVGsanitizer.git
cd SVGsanitizer
python -m pip install -r requirements.txt
python main.py
  > input yourfile.svg
```

### What it does 
1. Search for XXE and remove it
2. Search for DTD and remove it
3. Search for XSS and remove it

Create malitious SVG https://github.com/surajpkhetani/AutoSmuggle or use https://github.com/darylldoyle/svg-sanitizer/tree/master/tests/data
