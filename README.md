iis-shortname-scanner
=====================
latest version of scanners for IIS short filename (8.3) disclosure vulnerability.

Description
-----------
Microsoft IIS contains a flaw that may lead to an unauthorized information disclosure. The issue is triggered during the parsing of a request that contains a tilde character (~). This may allow a remote attacker to gain access to file and folder name information.

This scanner has been moved from https://code.google.com/p/iis-shortname-scanner-poc/ to github for better support.


Research file: http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf

It is possible to detect short names of files and directories which have an 8.3 equivalent in Windows by using some vectors in several versions of Microsoft IIS. For instance, it is possible to detect all short-names of “.aspx” files as they have 4 letters in their extensions. I have written a small scanner as a proof of concept. It seems the latest versions of IIS and .Net version 4 have been secured against this attack. Moreover, some of the websites which use special URL-rewrite rules are also safe. Note that the Basic authentication and Windows authentication cannot stop this attack.

It is not easy to enumerate the short names manually as it will take a long time. Therefore, I have created an open source proof of concept in Java which automates this process. I have used all of the different techniques that I have mentioned above in this code. I have tried to reduce the amount of the requests that it has to send to the server to find the valid files and folders. In order to check the PoC application, you can compare its result with the “Dir /x ~” command on the same directory.


Installation
------------

PS: you need to have Java JDK 6 or 7 to compile the Java file: http://www.oracle.com/technetwork/java/javase/downloads/index.html

To compile the Java file (javac needs to be in your path/it is in JDK Bin directory): /scanner_directory/javac scanner.java

To run the compiled file (java needs to be in your path/it is in JDK/JRE Bin directory): /scanner_directory/java scanner

Usage
-----

### Command line options

  java scanner [ShowProgress] [ThreadNumbers] [URL]

DETAILS:

 [ShowProgress]: 0= Show final results only - 1= Show final results step by step  - 2= Show Progress
 
 [ThreadNumbers]: 0= No thread - Integer Number = Number of concurrent threads [be careful about IIS Denial of Service]
 
 [URL]: A complete URL - starts with http/https protocol


### Sample command line:

Example 1 (uses no thread - very slow - not recommended!):

  java scanner 2 0 http://example.com/folder/new%20folder/

Example 2 (uses 20 threads - recommended):

  java scanner 2 20 http://example.com/folder/new%20folder/

Example 3 (saves output in a text file):

  java scanner 0 20 http://example.com/folder/new%20folder/ > c:\results.txt

Example 4 (bypasses IIS basic authentication):

  java scanner 2 20 http://example.com/folder/AuthNeeded:$I30:$Index_Allocation/

Note: Sometimes it does not work for the first time and you need to try again.

References
------------

Research file: http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf

Website Reference: http://soroush.secproject.com/blog/2012/06/microsoft-iis-tilde-character-vulnerabilityfeature-short-filefolder-name-disclosure/

Video Link: http://www.youtube.com/watch?v=XOd90yCXOP4

http://www.osvdb.org/83771

http://www.exploit-db.com/exploits/19525/

http://securitytracker.com/id?1027223


