# MPSGDreamParser

I created this script with the intention of parsing NMAP XML files for various use cases. 

Performs conversion of a valid NMAP .xml output file into into pentesting friendly output files formatted depending on the given options.
- inputFile - input nmap file in xml format
- inputType - inputed nmap file type ('ping', 'port', 'outboundPort')
- outputDirectory - output directory
- outputFile - output file
- outputType - outputed file type ('txt', 'csv')
- v - enable verbose output for debugging (I do not recommend this for normal usage)

Use cases:
- Ping Sweep Parsed into subnets file (TXT)
    
        MPSGDreamParser.py -inputFile nmap.xml -inputType ping -outputDirectory ~/ -outputFile subnets.txt
        
            Input File: .XML (nmap ping scan)
            Input Type: ping
            Output Directory: ___
            Output File: subnets.txt
- Port Scan Parsed into spreadsheet (CSV)
    
        MPSGDreamParser.py -inputFile nmap.xml -inputType port -outputDirectory ~/ -outputFile results.csv -outputType csv

            Input File: .XML (nmap port scan)
            Input Type: port
            Output Directory: ___
            Output File: internalResults.CSV
            Output Type: csv
- Port Scan Parsed into host files (TXT)

        MPSGDreamParser.py -inputFile nmap.xml -inputType port -outputDirectory ~/hosts -outputType txt

            Input File: .XML (nmap port scan)
            Input Type: port
            Output Directory: ___
            Output Type: txt
- Outbound Port Scan Parsed into spreadsheet (CSV)

        MPSGDreamParser.py -inputFile nmap.xml -inputType outboundPort -outputDirectory ~/ -outputFile outboundPortResults.csv -outputType csv
    
            Input File: .XML (nmap port scan against a single host)
            Input Type: outboundPort
            Output Directory: ___
            Output File: outboundResults.CSV
            Output Type: csv
