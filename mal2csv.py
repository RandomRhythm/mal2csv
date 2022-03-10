#mal2csv (malformed access log to CSV) - Written by Ryan Boyle randomrhythm@rhythmengineering.com

#This script represents an effort to parse and properly align web logs for import into analysis tools. 
#Caution! While this script tries to not truncate data to make it align; some data truncation may occur due to malformed data (rare but will happen when a return character is included in the last field).
#Preprocessing may not be required but is recommended to avoid parsing errors
#Combined Log Format will break down to the following columns
#RemoteIP,RemoteLogName,RemoteUser,EventTime,TimeZone,Request,StatusCode,Size,Referrer,UserAgent

import csv
import io
import os
import re 
import time
import sys
import json
from optparse import OptionParser
from Web_Log_Deobfuscate import Deobfuscate_Web_Log

#config section
strInputFilePath = "" #Leave blank to process the directory specified in strInputPath. Use to specify a specific log file to process
strInputPath = "" #Path to folder containing log files to format. Separate from Output path
strOutputPath = "" #Folder path to output formated logs. Make sure the folder path exists - script will not create the folder
#Input settings
inputEncoding = "utf-8" #set to "" to use system default
strLineBeginingRE = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" #regex to ensure each line starts with valid value. Set to "" to disable. default regex is for common log format and should be disabled or modfied for other formats
quotecharacter = '\"'
strdateFormat = "%d/%b/%Y:%H:%M:%S";#apache datetime format "%d/%b/%Y:%H:%M:%S"    #IIS format "%Y-%b-%d %H:%M:%S"
outputDateFormat = '%Y-%m-%d %H:%M:%S'
columnCount = 0 #set to zero to have it dynamically identify the number of columns based on header row (first row). Note not all web servers log header rows
boolPreprocess = False #preprocessing may be required. See if you get "Error on Row: " message and if so set to True.
boolExpectDefaultFormat = True #added to improve accuracy of Common/Combined Log Format. Set to False for IIS logs
#Output settings
outputEncoding = "utf-8"
boolSingleFile = True #Create one output file or many
boolOutputInteresting = False #This can be useful for finding potential suspicious anomalies
boolDeobfuscate = False #Use Web_Log_Deobfuscate to decode fields and improve readability
boolOutputSuspicious = False #If deobfuscating entries then output suspicious entries
boolphpids = False #Run log entries against phpids rules
boolOutputIDS = False #Output PHPIDS rule match information
boolOutputUnformatted = False #This is only useful when debugging
boolIIS = True #Use IIS settings (set boolExpectDefaultFormat = False and strdateFormat = "")
#end config section
boolSuspiciousLineFound = False #variable used to track when a line contains encoded data
phpidSignatures = {} #phpids signatures
customSignatures = {} #IDS signatures for deobfuscated log entries
boolHead = False

def build_cli_parser():
    parser = OptionParser(usage="%prog [options]", description="Format malformed access logs to CSV")
    parser.add_option("-i", "--input", action="store", default=None, dest="InputPath",
                      help="Path to folder containing logs to be formatted")
    parser.add_option("-o", "--output", action="store", default=None, dest="OutputPath",
                      help="Formatted log output folder path")
    parser.add_option("-d", "--deobfuscate", action="store_true", default=False, dest="boolDeobfuscate",
                      help="True or False value to deobfuscate log entries for output")
    parser.add_option("-l", "--loginteresting", action="store_true", default=False, dest="boolOutputSuspicious",
                      help="True or False value if interesting deobfuscated entries should be logged")
    parser.add_option("-p", "--phpids", action="store_true", default=False, dest="boolphpids",
                      help="True or False value if PHPIDS rule matching should be performed")
    parser.add_option("-r", "--logrules", action="store_true", default=False, dest="boolOutputIDS",
                      help="True or False value if PHPIDS rule matches should be logged")
    parser.add_option("-f", "--formatlogging", action="store_true", default=False, dest="boolOutputInteresting",
                      help="True or False value if suspicious formatting should be logged")
    parser.add_option("-m", "--MicrosoftIIS", action="store_true", default=False, dest="boolIIS",
                      help="True or False value if Microsoft IIS logs")
    return parser

def phpIDS (strMatchCheck, idsFileHandle):
    global phpidSignatures
    if phpidSignatures == {}:
        with open('default_filter.json') as json_file:
            phpidSignatures = json.load(json_file)
    for filter in phpidSignatures['filters']['filter']:
        if re.search( filter['rule'], strMatchCheck.lower()):
            #print('id: ' + filter['id'])
            #print('rule: ' + filter['rule'])
            #print('description: ' + filter['description'])
            #print('')
            if boolOutputIDS == True:
                outputIDS = filter['id'] + "|" + filter['description'] + "|" + strMatchCheck
                logIDS(idsFileHandle, outputIDS)
            return True

def customIDS (strMatchCheck, idsFileHandle):
    global customSignatures
    if customSignatures == {}:
        with open('custom_filter.json') as json_file:
            customSignatures = json.load(json_file)
    for filter in customSignatures['filters']['filter']:
        if re.search( filter['rule'], strMatchCheck.lower()):
            if boolOutputIDS == True:
                outputIDS = filter['id'] + "|" + filter['description'] + "|" + strMatchCheck
                logIDS(idsFileHandle, outputIDS)
            return True
    #print(strMatchCheck)

def logIDS(fP, logline):
    fP.write("\"" + logline.replace("|", "\",\"") + "\"" + "\n")

def appendQuote(strRow):
    if right(strRow, 1) != '"':
        return strRow + '\"'
    return (strRow)

def right(s, amount):
    return s[-amount:]

def deobfuscateEncoding(line):
    global boolSuspiciousLineFound
    if (line[:1] == "+" and line.replace("+", "").replace("]", "").isnumeric()) == True:
        return line#time zone does not need deobfuscating
    strOutput = Deobfuscate_Web_Log.replaceChar(Deobfuscate_Web_Log.urldecode(line))
    strOutput = Deobfuscate_Web_Log.urldecode(strOutput)#second pass for things like %2520
    strOutput = Deobfuscate_Web_Log.replaceUnicodeChar(strOutput)
    strOutput = Deobfuscate_Web_Log.HexDecode(strOutput, '0x')
    strOutput = Deobfuscate_Web_Log.HexDecode(strOutput, '0X')
    strTmpCompare = line # used to identify supicious activity
    if boolOutputSuspicious == True and strTmpCompare != strOutput:
        if strTmpCompare.replace("%2520", " ").replace("%20", " ") != strOutput:
          boolSuspiciousLineFound = True
    return strOutput

              
def CheckRemainingColumns(row_Check, intCurrentLoc, boolNumeric):#check for special chars followed by numeric
    boolSpecialFound = False
    for intLoopRemaining in range(intCurrentLoc, len(row_Check)):
        if boolSpecialFound == True and boolNumeric == True:
            if str.isnumeric(row_Check[intLoopRemaining]):
                return intLoopRemaining
        elif boolSpecialFound == True:
            return intLoopRemaining
        elif quotecharacter in row_Check[intLoopRemaining]:
            boolSpecialFound = True
        else:
            boolSpecialFound = False
    return -1

def fileProcess(strInputFpath, strFileName, strOutPath):
    global boolSuspiciousLineFound
    global boolHead
    global columnCount
    boolIDSdetection = False
    if boolPreprocess == True:
        
        if not os.path.isfile(strInputFpath):
            return None
        elif not os.path.exists(strInputFpath):
            return None
        tmpFilePath = strOutPath +"_preprocessed.tmp"
        if os.path.isfile(tmpFilePath):
            os.remove(tmpFilePath )
        
        with open(strInputFpath, "rt", encoding=inputEncoding) as inputFile:
            for tmpLineIn in inputFile:
                tmpLineOut = tmpLineIn
                if right(tmpLineOut, 4) == '\\""\n':
                    tmpLineOut = tmpLineOut[:-4] + '\"\n'
                if "  " in tmpLineIn: #encounted with nginx logs
                    tmpLineOut = tmpLineIn.replace("  "," ")
                with io.open(tmpFilePath, "a", encoding=outputEncoding) as outputFile:
                    outputFile.write(tmpLineOut)
        strInputFpath = tmpFilePath
        print("file created for parsing " + tmpFilePath)

        
    
    if os.path.isdir(strInputFpath):
        return None
    elif not os.path.exists(strInputFpath):
        return None    
    if boolSingleFile == True:

        strOutPath = strOutPath + "LogOutput.Formatted"
    else:
        strOutPath = strOutPath + strFileName + ".Formatted"
    
    if boolphpids == True and boolOutputIDS == True:
        fP = io.open(strOutPath + ".IDS", "a", encoding=outputEncoding) #open file handle for logging IDS matches
    if boolphpids == True or boolOutputSuspicious == True or boolOutputInteresting == True:#open file handle for interesting log output
        fi = open(strOutPath + ".interesting","a", encoding=outputEncoding) #suspicious log entry output
    csv.field_size_limit(2147483647) #increase threshold to avoid length limitation errors
    with open(strInputFpath, "rt", encoding=inputEncoding) as csvfile:
        with io.open(strOutPath , "a", encoding=outputEncoding) as f:
            queuedRows = []
            reader = csv.reader(csvfile, delimiter=' ', quotechar='\"')
            for r_row in reader: #loop through each row of input
                queuedRows = [r_row]
                intCheckFirstUserInput = 0
                if strLineBeginingRE != "": #can we validate the row start with regex
                    intListCount = 0
                    boolMatch = re.match(strLineBeginingRE, r_row[0])
                    if not boolMatch: #ensure first item has a valid value
                        for testColumns in r_row:
                            intListCount +=1
                            if re.match(strLineBeginingRE, testColumns):
                                
                                rowSlice = slice(intListCount -1, len(r_row))
                                queuedRows = [r_row[rowSlice]]
                                break
                if '\n' in "".join(r_row) and columnCount > 0: #handle newline in row 
                    if len(r_row) / columnCount >= 2:
                        intListCount = 0
                        for testColumns in r_row:
                            intListCount +=1
                            if '\n' in testColumns:
                                queuedRows = [r_row[:intListCount]]
                                print ("Error on Row: " + "".join(r_row))
                                queuedRows[len(queuedRows)-1][intListCount-1] = testColumns[0:testColumns.find("\n")]
                                break
                                 

                for row in queuedRows:
                    if columnCount == 0 and boolIIS == False:
                        columnCount = len(row)#dynamic row length

                    if "\\" in "".join(row) and boolOutputInteresting == True:
                        boolSuspiciousLineFound = True #Trigger logging suspicious line
                    outputRow = ""
                    boolSkipColumn = False
                    lastColumnEscaped = False
                    intColumnCount = 0
                    intWriteCount = 0
                    skippedColumns = 0
                    boolDateCoverted = False
                    boolExcludeRow = False #IIS headers are dropped
                    boolRequestEnding = False # this was added to track the request column. Set to true once "HTTP/" is encountered. Example: HTTP/1.1"
                    
                    for column in row:
                        intColumnCount += 1
                        boolQuoteRemoved = False
                        boolEscapeChar = False


                        if boolphpids == True and boolSuspiciousLineFound != True:
                            boolIDSdetection = phpIDS(column, fP)
                            boolSuspiciousLineFound  = boolIDSdetection
                        #saniColumn = str.replace(column, "'","") # remove quote chars
                        saniColumn = column
                        if boolIIS == True and intColumnCount == 1 and "#Fields:" in saniColumn:
                            if boolHead == False:
                                saniColumn = ""
                                boolSkipColumn = True
                                if columnCount ==0: #if dynamic header identification
                                    columnCount = len(row) -2 #dynamic row length
                            else:
                                boolExcludeRow = True
                                break #skip header row
                        if boolIIS == True and intColumnCount == 1 and ("#Software:" in saniColumn or "#Version:" in saniColumn or "#Date:" in saniColumn):
                            boolExcludeRow = True
                            break #drop IIS header rows

                            
                        if boolDeobfuscate == True: #perform decoding
                            saniColumn = deobfuscateEncoding(saniColumn)
                            saniColumn = str.replace(saniColumn, quotecharacter,"").replace("\n", "").replace("\rz", "") #remove format characters
                        if boolphpids == True and boolIDSdetection != True:
                            boolIDSdetection = customIDS(saniColumn.lower(),fP)
                            boolSuspiciousLineFound = boolIDSdetection
                        if  'HTTP/' in saniColumn:
                            boolRequestEnding = True
                        
                        if '\"' in saniColumn:
                            saniColumn = str.replace(saniColumn, quotecharacter,"")  # remove quote chars
                            boolQuoteRemoved = True
                        if boolExpectDefaultFormat == True and intColumnCount == 6 and row[6].isnumeric() == True and  row[7].isnumeric() == True: #if this is the request column and next two columns are numeric then 
                            boolRequestEnding = True        #Things line up formatting wise that we don't need to check for escape characters
                        elif boolExpectDefaultFormat == True and intColumnCount == 3 and "[" == row[4][:1]: #if the column after next is the datetime field then we need to merge the next field with this one
                            boolQuoteRemoved = True
                            boolEscapeChar = True
                        elif '\\' in saniColumn:
                            if (boolDateCoverted == True): # if we have made it past the user name and date field (only need escape character checks for fields with user provided input). Example: domainname\x5Cryan.boyle  
                                if right(saniColumn,1) == "\\" and boolDeobfuscate == False:
                                    boolQuoteRemoved = True
                                saniColumn = str.replace(saniColumn, "\\","")  #remove escape character
                                boolEscapeChar = True
                        elif boolExpectDefaultFormat == True and intColumnCount == 6 and ('GET' in saniColumn or 'POST' in saniColumn or 'PUT' in saniColumn  or 'HEAD' in saniColumn  or 'PUT' in saniColumn  or 'DELETE' in saniColumn) and boolRequestEnding == False:
                            boolEscapeChar = True #specific way to identify the request column and combine
                        elif boolExpectDefaultFormat == True and intColumnCount > 6 and boolRequestEnding == False:
                            boolEscapeChar = True #specific way to identify the request column and combine
                        elif boolExpectDefaultFormat == True and intColumnCount == columnCount and len(row) - intColumnCount - skippedColumns != columnCount - intColumnCount:
                            boolEscapeChar = True #This will cause the script to add up all final columns into the last one
                        if boolDateCoverted == False and saniColumn[0:1] == "[":# format date time
                            boolDateCoverted = True
                            logDateTime = time.strptime( saniColumn[1:], strdateFormat)
                            saniColumn = time.strftime(outputDateFormat, logDateTime)


                        if boolEscapeChar == True and len(row) > columnCount and boolSkipColumn == False and boolQuoteRemoved == True:  #escaped character and column mismatch
                        
                            if len(row) - intColumnCount != 0:
                                outputRow = outputRow + ',"' + saniColumn #add new column
                            else:
                                outputRow = outputRow + " " + saniColumn #continue column and add separator char back
                            intWriteCount += 1
                            if len(row) - intColumnCount - skippedColumns != columnCount - intColumnCount: #more columns than what is expected so combine next column
                                boolSkipColumn = True
                        elif boolSkipColumn == True and (len(row) - intColumnCount - skippedColumns != columnCount - intColumnCount): #still more columns than what is expected so combine next column
                            skippedColumns +=1
                            if boolHead == False and boolIIS == True and intColumnCount == 1: #IIS header row manipulation
                                outputRow = "\"" #excluding #Fields: and replacing with a qoute to start our next field
                                continue
                            if intCheckFirstUserInput == 0:
                                intCheckFirstUserInput = CheckRemainingColumns(row, intColumnCount, True) # row, currentColumn, boolCheckNumeric
                            if  intCheckFirstUserInput >= intColumnCount:#check for special chars followed by number (In apache logs this is the first non system/user provided column that is followed by a status code)
                                outputRow = outputRow + " " + saniColumn #continue column and add separator char back
                            elif boolQuoteRemoved == True and CheckRemainingColumns(row, intColumnCount, False) <= intColumnCount and not (intColumnCount - skippedColumns == columnCount and len(row) - intColumnCount != 0):#check for special chars ensuring we don't close the column if there is still items to add 
                                outputRow = outputRow + " " + saniColumn + '"' #Finish and close column
                                boolSkipColumn = False
                                intWriteCount += 1
                            elif boolHead == False and boolIIS == True and intColumnCount == 2: #IIS header row manipulation continuation
                                outputRow = outputRow + saniColumn #this is actually our first output value entry as we skipped #Fields:
                                boolHead = True
                            else:
                                outputRow = outputRow + " " + saniColumn #continue column and add separator char back
                        elif boolSkipColumn == True and len(row) - intColumnCount - skippedColumns == columnCount - intColumnCount: #New columns are just right
                            skippedColumns +=1
                            outputRow = appendQuote(outputRow) + ',"' + saniColumn + '"' #Close column and add new column
                            boolSkipColumn = False
                            intWriteCount += 1



                        elif outputRow == "": # first column in new row
                            outputRow = '"' + saniColumn + '"'
                            intWriteCount += 1
                    
                        else: # add new column
                            if boolEscapeChar == True:
                                lastColumnEscaped = True
                                outputRow = appendQuote(outputRow) + ',"' + saniColumn #start new column
                                boolSkipColumn = True 
                            elif intColumnCount - skippedColumns >= columnCount and len(row) == intColumnCount and columnCount != len(row): #we've got too many columns. Mash last one together
                                outputRow = appendQuote(outputRow) + ',"' + saniColumn + '"' #Close column and add final column
                            elif intWriteCount + 1 == columnCount and len(row) > intColumnCount:
                                outputRow = appendQuote(outputRow) + ',"' + saniColumn #start new column
                            else:
                                outputRow = outputRow + ',"' + saniColumn + '"'#start and close new column
                                intWriteCount += 1

                    if len(row) < columnCount:
                        for x in range(0,columnCount - len(row)):
                            outputRow = appendQuote(outputRow) + ',\"ParseError\"'
                    if right(outputRow, 1) != '\"':
                        #outputRow = outputRow + '\"'
                        if boolOutputUnformatted == True:
                            with io.open(strOutPath + ".Unformatted", "a", encoding=outputEncoding) as fU:#Unformatted output that eluded a final quote
                                fU.write(outputRow + "\n")
                    outputRow = appendQuote(outputRow) 

                    if boolExcludeRow == False:
                        f.write(outputRow + "\n")
                        if boolSuspiciousLineFound == True:
                            boolSuspiciousLineFound = False
                            boolIDSdetection = False
                            fi.write(outputRow + "\n")
    if os.path.isfile(strInputFilePath +".tmp"):
        os.remove(strInputFilePath +".tmp")     
    if boolphpids == True and boolOutputIDS == True:
        fP.close() #close file handle for IDS log output
    if boolphpids == True or boolOutputSuspicious == True or boolOutputInteresting == True:#open file handle for interesting log output
        fi.close() #close file handle for interesting log output

parser = build_cli_parser()
opts, args = parser.parse_args(sys.argv[1:])
if opts.InputPath:
    strInputPath = opts.InputPath
    print (strInputPath)
if opts.OutputPath:
    strOutputPath = opts.OutputPath
    print (strOutputPath)
if (not strInputPath and not strInputFilePath) or not strOutputPath:
    print ("Missing required parameter")
    sys.exit(-1)
if opts.boolDeobfuscate:
    boolDeobfuscate = opts.boolDeobfuscate
if opts.boolOutputSuspicious:
    boolOutputSuspicious = opts.boolOutputSuspicious
if opts.boolphpids:
    boolphpids = opts.boolphpids
if opts.boolOutputInteresting:
    boolOutputInteresting = opts.boolOutputInteresting
if opts.boolOutputIDS:
    boolOutputIDS = opts.boolOutputIDS
if opts.boolOutputIDS:
    boolIIS = opts.boolIIS
if boolIIS == True:
    boolExpectDefaultFormat = False
    strdateFormat = ""
    strLineBeginingRE = ""

if strInputFilePath == "":
    if os.path.isfile(strInputPath):#check if a file path was provided instead of a folder
            strInputFilePath = strInputPath #use file instead of folder
            strInputPath = ""
        
if os.path.isdir(strInputPath):
    for file in os.listdir(strInputPath):
        if os.path.isdir(strInputPath):
            for subfile in os.listdir(os.path.join(strInputPath, file)):
                print(os.path.join(os.path.join(strInputPath, file), subfile))
                fileProcess(os.path.join(os.path.join(strInputPath, file), subfile), subfile, strOutputPath)
        else:
            fileProcess(os.path.join(strInputPath, file), columnCount, file, strOutputPath)
else:
    fileName = os.path.basename(strInputFilePath)
    fileProcess(strInputFilePath, fileName, strOutputPath)#fileProcess(strInputFpath, columnCount, strFileName, strOutPath):


print("Completed!")
