iis-shortname-scanner
=====================

Microsoft IIS contains a flaw that may lead to an unauthorized information disclosure. The issue is triggered during the parsing of a request that contains a tilde character (~). This may allow a remote attacker to gain access to file and folder name information.

This exploit has been moved to github for better support from https://code.google.com/p/iis-shortname-scanner-poc/


Research file: http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf

It is possible to detect short names of files and directories which have an 8.3 equivalent in Windows by using some vectors in several versions of Microsoft IIS. For instance, it is possible to detect all short-names of “.aspx” files as they have 4 letters in their extensions. I have written a small scanner as a proof of concept. It seems the latest versions of IIS and .Net version 4 have been secured against this attack. Moreover, some of the websites which use special URL-rewrite rules are also safe. Note that the Basic authentication and Windows authentication cannot stop this attack.

It is not easy to enumerate the short names manually as it will take a long time. Therefore, I have created an open source proof of concept in Java which automates this process. I have used all of the different techniques that I have mentioned above in this code. I have tried to reduce the amount of the requests that it has to send to the server to find the valid files and folders. In order to check the PoC application, you can compare its result with the “Dir /x ~” command on the same directory.

Research file: http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf

Website Reference: http://soroush.secproject.com/blog/2012/06/microsoft-iis-tilde-character-vulnerabilityfeature-short-filefolder-name-disclosure/

Video Link: http://www.youtube.com/watch?v=XOd90yCXOP4

PS: you need to have Java JDK 6 or 7 to compile the Java file: http://www.oracle.com/technetwork/java/javase/downloads/index.html

To compile the Java file (javac needs to be in your path/it is in JDK Bin directory): /scanner_directory/javac scanner.java

To run the compiled file (java needs to be in your path/it is in JDK/JRE Bin directory): /scanner_directory/java scanner
