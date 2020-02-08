# mal2csv
### Malformed Access Log to CSV - Convert Web Server Access Logs to CSV

mal2csv was written to take web server access logs and convert them into CSV. The mal2csv python script can convert logs from popular web servers such as Apache, NGINX, IIS, or similar. A specific effort was made to convert logs in the common log format and the combined log format that may be malformed. The malformation can happen due to a number of reasons, including SQL injection (SQLi), cross-site scripting (XSS), or other web server attacks.

The mal2csv script integrates Web_Log_Deobfuscate that deobfuscates encoding, such as that used in web server attacks, to humanly readable text. The mal2csv script can check log entries against the PHPIDS regex rules to identify known malicious requests. Log entries identified with formatting issues can also be logged for review as those entries may contain suspicious activity that you can review from a security perspective. 

The mal2csv script is recommended to ensure all web server logs can be successfully imported into analysis tools. Often analysis tools will allow for the import of malformed logs, but data may not line up correctly within fields or data is dropped. Leverage mal2csv to help ensure log evidence isn't missed by converting into the CSV format while attempting to format the rows correctly, so column alignment is as accurate as possible.

The script may need to be modified to ensure proper operation with the logs you are trying to format. This is because there are many ways in which web servers log access. For example, some logs may not provide a referrer or user agent field while others do. Edit the config section of the script per the notes for each variable.

Options:
  -h, --help            show this help message and exit
  -i INPUTPATH, --input=INPUTPATH
                        Path to folder containing logs to be formatted
  -o OUTPUTPATH, --output=OUTPUTPATH
                        Formatted log output folder path

Example:
mal2csv.py -i c:\mal2csv\Web_Log_Deobfuscate\Example_Logs\access.log -o c:\processed_logs\output.csv