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
strLineBeginingRE = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" #regex to ensure each line starts with valid value. Set to "" to disable. default regex is for common log format and should be disabled or modfied for other formats
quotecharacter = '\"'
strdateFormat = "%d/%b/%Y:%H:%M:%S";#apache datetime format "%d/%b/%Y:%H:%M:%S"    #IIS format "%Y-%b-%d %H:%M:%S"
columnCount = 10 #set to zero to have it dynamically identify the number of columns based on header row (first row). Note not all web servers log header rows
boolPreprocess = False #preprocessing may be required. See if you get "Error on Row: " message and if so set to True.
boolSingleFile = True #Create one output file or many
boolExpectDefaultFormat = True #added to improve accuracy of Common/Combined Log Format. Set to False for IIS logs
boolOutputInteresting = True #This can be useful for finding potential suspicious anomalies
boolDeobfuscate = True #Use Web_Log_Deobfuscate to decode fields and improve readability
boolOutputSuspicious = True #If deobfuscating entries then output suspicious entries
boolphpids = True #Run log entries against phpids rules
boolOutputUnformatted = False #This is only useful when debugging
#end config section
boolSuspiciousLineFound = False #variable used to track when a line contains encoded data
phpidSignatures = {}#phpids signatures

def build_cli_parser():
    parser = OptionParser(usage="%prog [options]", description="Format malformed access logs to CSV")
    parser.add_option("-i", "--input", action="store", default=None, dest="InputPath",
                      help="Path to folder containing logs to be formatted")
    parser.add_option("-o", "--output", action="store", default=None, dest="OutputPath",
                      help="Formatted log output folder path")
    return parser

def phpIDS (strMatchCheck):
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
            return True

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

def fileProcess(strInputFpath, columnCount, strFileName, strOutPath):
    global boolSuspiciousLineFound
    if boolPreprocess == True:
        
        if not os.path.isfile(strInputFpath):
            return None
        elif not os.path.exists(strInputFpath):
            return None
        tmpFilePath = strOutPath +"_preprocessed.tmp"
        if os.path.isfile(tmpFilePath):
            os.remove(tmpFilePath )
        
        with open(strInputFpath, "rt") as inputFile:
            for tmpLineIn in inputFile:
                tmpLineOut = tmpLineIn
                if right(tmpLineOut, 4) == '\\""\n':
                    tmpLineOut = tmpLineOut[:-4] + '\"\n'
                if "  " in tmpLineIn: #encounted with nginx logs
                    tmpLineOut = tmpLineIn.replace("  "," ")
                with io.open(tmpFilePath, "a", encoding="utf-8") as outputFile:
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
    
    with open(strInputFpath, "rt") as csvfile:
        with io.open(strOutPath , "a", encoding="utf-8") as f:
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
                                print (r_row[rowSlice])
                                queuedRows = [r_row[rowSlice]]
                                break
                if '\n' in "".join(r_row): #handle newline in row 
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
                    if columnCount == 0:
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
                    boolRequestEnding = False # this was added to track the request column. Set to true once "HTTP/" is encountered. Example: HTTP/1.1"
                    for column in row:
                        intColumnCount += 1
                        boolQuoteRemoved = False
                        boolEscapeChar = False

                        if boolphpids == True and boolSuspiciousLineFound != True:
                            boolSuspiciousLineFound = phpIDS(column)
                            
                        saniColumn = str.replace(column, "'","") # remove quote chars
                        if boolDeobfuscate == True: #perform decoding
                            saniColumn = deobfuscateEncoding(saniColumn)
                            saniColumn = str.replace(saniColumn, quotecharacter,"").replace("\n", "").replace("\rz", "")

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
                            saniColumn = time.strftime('%Y-%m-%dT%H:%M:%S', logDateTime)


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
                            if intCheckFirstUserInput == 0:
                                intCheckFirstUserInput = CheckRemainingColumns(row, intColumnCount, True) # row, currentColumn, boolCheckNumeric
                            if  intCheckFirstUserInput >= intColumnCount:#check for special chars followed by number (In apache logs this is the first non system/user provided column that is followed by a status code)
                                outputRow = outputRow + " " + saniColumn #continue column and add separator char back
                            elif boolQuoteRemoved == True and CheckRemainingColumns(row, intColumnCount, False) <= intColumnCount and not (intColumnCount - skippedColumns == columnCount and len(row) - intColumnCount != 0):#check for special chars ensuring we don't close the column if there is still items to add 
                                outputRow = outputRow + " " + saniColumn + '"' #Finish and close column
                                boolSkipColumn = False
                                intWriteCount += 1
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
                            with io.open(strOutPath + ".Unformatted", "a", encoding="utf-8") as fU:#Unformatted output that eluded a final quote
                                fU.write(outputRow + "\n")
                    outputRow = appendQuote(outputRow) 

                    f.write(outputRow + "\n")
                    if boolSuspiciousLineFound == True:
                        boolSuspiciousLineFound = False
                        with open(strOutPath + ".interesting","a", encoding="utf-8") as fi: #write suspicious log entry
                            fi.write(outputRow + "\n")
    if os.path.isfile(strInputFilePath +".tmp"):
        os.remove(strInputFilePath +".tmp")     


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
        
if strInputFilePath == "":
        if os.path.isfile(strInputPath):#check if a file path was provided instead of a folder
                strInputFilePath = strInputPath #use file instead of folder
                strInputPath = ""
        
if os.path.isdir(strInputPath):
    for file in os.listdir(strInputPath):
        fileProcess(os.path.join(strInputPath, file), columnCount, file, strOutputPath)
else:
        fileName = os.path.basename(strInputFilePath)
        fileProcess(strInputFilePath, columnCount,fileName, strOutputPath)#fileProcess(strInputFpath, columnCount, strFileName, strOutPath):


print("Completed!")