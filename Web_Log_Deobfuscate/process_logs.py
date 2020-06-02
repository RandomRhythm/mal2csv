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

import sys
import io
import os
from optparse import OptionParser
import Deobfuscate_Web_Log
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

parser = build_cli_parser()
opts, args = parser.parse_args(sys.argv[1:])
if not opts.strinputfpath or not opts.stroutputfpath:
  print ("Missing required parameter")
  sys.exit(-1)    
else:
  boolOutputSuspicious = False  
  if opts.boolInteresting:
    boolOutputSuspicious = opts.boolInteresting
      
  fo = open(opts.stroutputfpath,"w", encoding="utf-8") #file output
  if boolOutputSuspicious == True:
    fs = open(opts.stroutputfpath+ ".interesting","w")#log suspicious file input

  
  with open(opts.strinputfpath, encoding=inputEncoding) as fi: #log file input
          for line in fi:
              strOutput = Deobfuscate_Web_Log.replaceChar(Deobfuscate_Web_Log.urldecode(line))
              strOutput = Deobfuscate_Web_Log.urldecode(strOutput)#second pass for things like %2520
              strOutput = Deobfuscate_Web_Log.replaceUnicodeChar(strOutput)
              strOutput = Deobfuscate_Web_Log.HexDecode(strOutput, '0x')
              strOutput = Deobfuscate_Web_Log.HexDecode(strOutput, '0X')
              strTmpCompare = line # used to identify supicious activity
              if boolOutputSuspicious == True and strTmpCompare != strOutput:
                if strTmpCompare.replace("%2520", " ").replace("%20", " ") != strOutput:
                  fs.write(line) #write output
              strOutput = Deobfuscate_Web_Log.replaceString(strOutput, "\n", "\\n") #don't like log entries spaning multiple lines.
              strOutput = Deobfuscate_Web_Log.replaceString(strOutput, "\r", "\\r") 
              if strOutput == "":
                strOutput = "\n"
              fo.write(strOutput) #write output
  fo.close()   
  fi.close()
  if boolOutputSuspicious == True:
      fs.close()
    
