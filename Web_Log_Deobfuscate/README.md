# Web-Log-Deobfuscate
Deobfuscate various encodings that can be found in web logs.


Web-Log-Deobfuscate can be used to deobfuscate files containing hex (0x), ASCII, Unicode percent encoded characters, and interpreted CHAR() commands. The output will contain decoded text further revealing web attacks such as SQL injection. Input the log file and the script will output the deobfuscated log at the specified path.


Options:

  -h, --help            show this help message and exit
  
  -i STRINPUTFPATH, --input=STRINPUTFPATH
                        (Path to log file that will be deobfuscated)
                        
  -o STROUTPUTFPATH, --output=STROUTPUTFPATH
                        (Deobfuscated log output file path)

  -l, --loginteresting  Write interesting log entries identified with encoding
                        to a .interesting file)

Example:

process_logs.py -i .\Example_Logs\access.log -o .\Example_Logs\access.log.processed -l