# MPSGDreamParser

I created this script with the intention of parsing NMAP XML files for various use cases. 

Performs conversion of a valid NMAP .xml output file into into pentesting friendly output files formatted depending on the given options.
- inputFile - input nmap file in xml format
- inputType - inputed nmap file type ('ping', 'port', 'outboundPort', 'smbVersion', 'smbSigning')
- outputDirectory - output directory
- outputFile - output file
- outputType - outputed file type ('txt', 'csv')
- v - enable verbose output for debugging (I do not recommend this for normal usage)
