# Web-Log-Deobfuscate Example Logs
The three files in this directory are as follows:
* access.log - Example web server log file containing SQL injection and a little XSS
* accesslog.processed - Example access.log file after decoding has taken place
* access.log.processed.interesting - Example output for log entiries containing potential suspicious encoding

This script can deobfuscate any web server logs but in this example we use a log file from an Apache web server. 