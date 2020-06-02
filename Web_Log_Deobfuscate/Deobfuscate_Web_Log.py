#Input a log file that contains encoded text
#this script will replace hex (0x), ASCII, Unicode percent encoded characters, and interpreted CHAR() commands. 

#Copyright (c) 2019 Ryan Boyle randomrhythm@rhythmengineering.com.
#Copyright (c) 2012 Jenny Qian.
#All rights reserved.

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import string
import sys
import binascii
inputEncoding = "utf-8"

def build_cli_parser():
    parser = OptionParser(usage="%prog [options]", description="Deobfuscate URL in log file")
    parser.add_option("-i", "--input", action="store", default=None, dest="strinputfpath",
                      help="Path to log file that will be deobfuscated")
    parser.add_option("-o", "--output", action="store", default=None, dest="stroutputfpath",
                      help="Deobfuscated log output file path")
    parser.add_option("-l", "--loginteresting", action="store_true", default=False, dest="boolInteresting",
                      help="True or False value if interesting encoding should be logged")

    return parser

def urldecode(url):
    """
    Decode an encoded url. https://github.com/jennyq/urldecode
    
    Usage: 
    url = 'http://www.example.com/this%20is%20my%20test%20%26%20%23%24'
    decoded_url = urldecode(url)
    """
    if url.find(" ") == -1:
        url = url.replace("+", " ")
        
    p = re.compile("%(?=[0-9A-F]{2})")
    
    plist = p.split(url)
    if len(plist) > 1:
        for i in range(1, len(plist)):
            plist[i] = '%s%s' % (chr(int((plist[i])[:2], 16)), (plist[i])[2:])
        
        decoded_url = ''.join(plist)
        
        return decoded_url
    return url


def replaceUnicodeChar(strUurl):
    boolFirstLine = True
    strReturnWithChars = ""
    if '%u' in strUurl:
        urllist = strUurl.split('%u')
        for s in urllist:
            sTmpUnicode = s[:4]
            if all(c in string.hexdigits for c in sTmpUnicode):
               seq = ('\\u', sTmpUnicode )
               strFunicode = ''.join(seq) 
               if len(s) > 4: #include everything else in string
                 seq = (strReturnWithChars,strFunicode.encode().decode('unicode_escape'), s[len(s)-4:]) 
               else: #string was only the unicode char
                 seq = (strReturnWithChars,strFunicode.encode().decode('unicode_escape'))   
               strReturnWithChars = ''.join(seq) 
            else: #was not hex ... could be the first line or perhaps not a properly formated URL?
              if boolFirstLine == True:
                seq = (strReturnWithChars, s )
                boolFirstLine = False
              else:
                seq = (strReturnWithChars, '%u', s )

              strReturnWithChars = ''.join(seq )
            
    else:
      strReturnWithChars = strUurl
    return strReturnWithChars
    

def HexDecode(strhURL, strHexIdentifier):
    """
    replace hex variable with characters
    """
    boolFirstLine = True
    strHexDecoded = ""
    if 'declare' in strhURL.lower() and '@' in strhURL and '=' in strhURL and 'set' in strhURL.lower() and strHexIdentifier in strhURL:
      strTmpHex = ""
      if strHexIdentifier in strhURL:
        urllist = strhURL.split(strHexIdentifier)
      for strTmpUlistItem in urllist:
        strTmpHex = ""
        if boolFirstLine == True: #first entry has no hex value
          boolFirstLine = False
        else: #check and parse hex value
          for strTmpChar in strTmpUlistItem:
            if all(c in string.hexdigits for c in strTmpChar):
              strTmpHex = strTmpHex + strTmpChar
            else:
              break
        if strTmpHex != "":
          #print (strTmpUlistItem, strTmpHex)
          if len(strTmpHex) > 1:
            strHexDecoded = strHexDecoded + binascii.unhexlify(strTmpHex).decode('unicode_escape') + strhURL.replace(strHexDecoded + strHexIdentifier + strTmpHex, "", 1)
          else:
            strHexDecoded = strHexDecoded + strTmpUlistItem
        else:
          strHexDecoded = strHexDecoded + strTmpUlistItem
    else:
      strHexDecoded = strhURL
    return strHexDecoded
   
    

def replaceChar(strEURL):
    """
    replace CHAR() with character
    """
    strCHARACTER = ""
    if 'CHR(' in strEURL:
        strCHARACTER = 'CHR('
    elif 'CHAR(' in strEURL:
        strCHARACTER = 'CHAR('
    if strCHARACTER != "":
        urllist = strEURL.split(strCHARACTER)
        strReturnWithChars = ""
        for s in urllist:
            strTmpPart = ""
            #print(s)
            if ")" in s or strCHARACTER in s:  
              if len(s) > s.index(')') + 1:
                tmpChrCode = s[:s.index(')')]
                if tmpChrCode.isdigit():
                    if int(s[:s.index(')')]) < 257:
                      seq = (strReturnWithChars, chr(int(s[:s.index(')')])),s[s.index(')') +1 -len(s):])
                      strReturnWithChars = strTmpPart.join( seq )
                    else:
                      #print (s[:s.index(')')] + " is not a valid char number:" + strEURL)
                      seq = (strReturnWithChars,strCHARACTER,s[:s.index(')')] ,s[s.index(')') -len(s):])
                      strReturnWithChars = strTmpPart.join(seq )                        
                else:
                  seq = (strReturnWithChars, s )
                  strReturnWithChars = strTmpPart.join(seq )  
              else:
                  seq = (strReturnWithChars, s )
                  strReturnWithChars = strTmpPart.join(seq )
            else:
                seq = (strReturnWithChars, s )
                strReturnWithChars = strTmpPart.join(seq )                  
    else:
        strReturnWithChars = strEURL
    return strReturnWithChars

def replaceString(strInputLine, strMatchText, strReplace):
    strReplaceReturn = strInputLine
    strManipulate = strInputLine[:-2]#dont match EOL chars
    if strMatchText in strManipulate:
        strReplaceReturn = strManipulate.replace(strMatchText, strReplace)
        strReplaceReturn = strReplaceReturn + strInputLine[-2:] #add back EOL chars
    return strReplaceReturn
