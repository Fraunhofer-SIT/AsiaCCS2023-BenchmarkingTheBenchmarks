package de.fraunhofer.sit.createspecification;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class CreateSpecificationsAppJuliet extends SpecificationProvider {

	static Map<Integer, String> ignoredCompletely = new HashMap<>();
	static Map<Integer, String> ignoredNistCompletely = new HashMap<>();
	static Map<String, String> ignoredNistWildcard = new HashMap<>();
	static Map<Integer, String> ignoredRun = new HashMap<>();
	static {

		ignoredRun.put(400, "Writes disk full");
		/*
		 * switch (cwe) { case 400: case 190: case 191: case 197: case 129: case 674:
		 * case 390: case 476: // case 835: continue; }
		 */
		String broken = "Broken testcase";
		ignoredNistCompletely.put(605,
				broken + " - setReuseAddress not called/listening on the same application twice does not make sense");
		ignoredNistCompletely.put(378, broken + " - Attacker goal unclear");
		ignoredNistCompletely.put(379, broken + " - Attacker goal unclear");

		ignoredNistCompletely.put(15, broken + " - Nothing happens with the connection");
		ignoredNistCompletely.put(491, broken + " - CWE is not exploitable");
		ignoredNistCompletely.put(486, broken
				+ " - The attacker cannot change anything besides running the code, which does not lead to a security incident");
		ignoredNistCompletely.put(486, broken
				+ " - The attacker cannot change anything besides running the code, which does not lead to a security incident");
		ignoredNistCompletely.put(643, broken + " - Retrieved values not used at all.");
		ignoredNistCompletely.put(134, broken + " - Broken due to good-method closing System.in ");
		/*
		 * ignoredCompletely.put(329, broken + " - Constant being encrypted");
		 * ignoredCompletely.put(328, broken + " - Constant secret being hashed");
		 * ignoredCompletely.put(759, broken + " - Constant secret being hashed");
		 */
		ignoredNistCompletely.put(338, broken + " - PRNG not used in security context");
		ignoredNistCompletely.put(190, broken + " - Not a security issue in this test case");
		ignoredNistCompletely.put(191, broken + " - Not a security issue in this test case");
		ignoredNistCompletely.put(197, broken + " - Not a security issue in this test case");
		ignoredNistCompletely.put(499, broken + " - Serializable class is never instantiated/used");
		ignoredNistCompletely.put(329, broken
				+ " - The IV is constant, but a fresh key is generated, thus an attacker does not gain any information regardless of IV.");
		ignoredNistCompletely.put(321,
				broken + " - The attacker can choose the password in the fix and thus decrypt the hard-coded secret");
		ignoredNistCompletely.put(226, broken
				+ " - Both the fixed and unfixed version store the password in Strings, which cannot be cleared.");
		ignoredNistCompletely.put(566, broken
				+ " - The query based on the id supplied by the attacker does not have any influence on the output.");
		ignoredNistCompletely.put(698, broken
				+ " - Logging a constant string value after redirect statements is neither a flaw nor undefined. The intent of the CWE is different.");
		ignoredNistCompletely.put(535, broken
				+ " - The tests are the same as CWE-534, albeit under the name of CWE-535. This might be due to a copy and paste error in the test generation script.");
		String codeQ = "Code quality issue";
		String codeQSource = "Code quality issue & Source code only";
		ignoredCompletely.put(546, codeQSource);
		ignoredCompletely.put(398, codeQSource);
		ignoredCompletely.put(483, codeQSource);
		ignoredCompletely.put(534, "CWE is deprecated and thus these test cases were omitted.");
		ignoredCompletely.put(533, "CWE is deprecated and thus these test cases were omitted.");

		ignoredNistWildcard.put("CWE319.*_kerberosKey_.*", broken + " - Kerberos key is not used for anything");
		ignoredNistWildcard.put("CWE319.*_passwordAuth_.*", broken
				+ " - Only PasswordAuthentication.toString() is used, which does not reveal sensitive information (does not return user/password information)");
		ignoredNistWildcard.put("CWE510_Trapdoor__network.*",
				broken + " - Opens/accepts a network socket, but no trapdoor logic");
		String CMDI_ARGUMENT = "Command injection not exploitable on linux: runtime.exec() does not evaluate commands, arguments are passed to 'ls' without evaluation.";
		ignoredNistWildcard.put("CWE78_OS_Command_Injection__PropertiesFile_81.*", CMDI_ARGUMENT);
		ignoredNistWildcard.put("CWE78_OS_Command_Injection__getQueryString_Servlet_02.*", CMDI_ARGUMENT);
		String unsupported = "Currently unsupported";
		ignoredNistCompletely.put(539, unsupported
				+ " - Needs support for current time handling and arithmetic/logic expressions (future work).");
		ignoredNistCompletely.put(613, unsupported
				+ " - Needs support for current time handling and arithmetic/logic expressions (future work).");
		ignoredNistCompletely.put(256, broken
				+ " - The fix for using a plain text password is decrypting using a hard-coded password according to the test cases.");

		// TODO: Discuss
		ignoredNistCompletely.put(328,
				broken + " - Using an insecure hash function to hash a non-sensitive hardcoded string");
		ignoredNistCompletely.put(759, broken + " - Using a hash function to hash a non-sensitive hardcoded string");
		ignoredNistCompletely.put(760, broken + " - Using a hash function to hash a non-sensitive hardcoded string");
		ignoredNistCompletely.put(336, broken
				+ " - setSeed JavaDoc: 'The given seed supplements, rather than replaces, the existing seed. Thus, repeated calls are guaranteed never to reduce randomness.'");

		ignoredCompletely.put(476, codeQ);
		ignoredCompletely.put(193, codeQ + " - Not a security issue in Java");
		ignoredCompletely.put(259, "hard coded password not dynamically verifiable");
		ignoredCompletely.put(615, "Source code only");
		ignoredCompletely.put(369, codeQ);
		ignoredCompletely.put(129, codeQ);
		ignoredCompletely.put(764, codeQ);
		ignoredCompletely.put(395, codeQ);
		ignoredCompletely.put(390, codeQ);
		ignoredCompletely.put(477, codeQ);
		ignoredCompletely.put(775, codeQ);
		ignoredCompletely.put(572, codeQ);
		ignoredCompletely.put(765, codeQ);
		ignoredCompletely.put(478, codeQ);
		ignoredCompletely.put(396, codeQ);
		ignoredCompletely.put(570, codeQ);
		ignoredCompletely.put(609, codeQ);
		ignoredCompletely.put(404, codeQ);
		ignoredCompletely.put(690, codeQ);
		ignoredCompletely.put(607, codeQ);
		ignoredCompletely.put(584, codeQ);
		ignoredCompletely.put(561, codeQ);
		ignoredCompletely.put(252, codeQ);
		ignoredCompletely.put(481, codeQ);
		ignoredCompletely.put(563, codeQ);
		ignoredCompletely.put(832, codeQ);
		ignoredCompletely.put(248, codeQ);
		ignoredCompletely.put(597, codeQ);
		ignoredCompletely.put(571, codeQ);
		ignoredCompletely.put(459, codeQ);
		ignoredCompletely.put(482, codeQ);
		ignoredCompletely.put(397, codeQ);
		ignoredCompletely.put(772, codeQ);
		ignoredCompletely.put(484, codeQ);
		ignoredCompletely.put(585, codeQ);
		ignoredCompletely.put(586, codeQ);
		ignoredCompletely.put(681, codeQ);
		ignoredCompletely.put(253, codeQ);
		ignoredCompletely.put(500, codeQ);
		ignoredCompletely.put(667, codeQ);
		ignoredCompletely.put(568, codeQ);
		ignoredCompletely.put(582, codeQ);
		ignoredCompletely.put(580, codeQ);
		ignoredCompletely.put(617, codeQ);
		ignoredCompletely.put(325, codeQ);
		ignoredCompletely.put(581, codeQ);
		ignoredCompletely.put(579, codeQ);
		ignoredCompletely.put(383, codeQ);
		ignoredCompletely.put(614, "not exploited: environment is http-only");
		

		String encHC = "Encrypts hard-coded information available in the app";
		ignoredCompletely.put(327, encHC);
		ignoredCompletely.put(506, "The behavior of good and bad is identical, thus, no real attack can be performed.");

		String notExploitableSessionValid = "Not exploitable: requires several invalid sessions, but never invalidates any sessions";
		ignoredNistWildcard.put("CWE833_Deadlock__synchronized_methods_Servlet_01.*", notExploitableSessionValid);
		ignoredNistWildcard.put("CWE833_Deadlock__synchronized_objects_Servlet_01.*", notExploitableSessionValid);
		String notExploitableTimeBounds = "exploit not verifiable in reasonable time";
		ignoredNistWildcard.put("CWE511_Logic_Time_Bomb__rand.*", notExploitableTimeBounds );
		ignoredNistWildcard.put("CWE89_SQL_Injection.*executeUpdate.*", "not exploitable: neighter sqlite nor hsqldb allow INSERT INTO WHERE statements");
		ignoredNistWildcard.put("CWE789_Uncontrolled_Mem_Alloc.*_HashMap.*", "not exploitable: new HashMap(INTEGER.MAX_SIZE) does not cause memory exhaustion. it just sets parameters");
		ignoredNistWildcard.put("CWE789_Uncontrolled_Mem_Alloc.*_HashSet.*", "not exploitable: new HashMap(INTEGER.MAX_SIZE) does not cause memory exhaustion. it just sets parameters");
		ignoredNistWildcard.put("CWE789_Uncontrolled_Mem_Alloc__random.*", "not exploitable: new HashMap(INTEGER.MAX_SIZE) does not cause memory exhaustion. it just sets parameters");
		ignoredNistWildcard.put("CWE113_HTTP_Response_Splitting__listen_tcp.*", "can't send \r over input stream, readLine uses this as newline terminator");
		ignoredNistWildcard.put("CWE113_HTTP_Response_Splitting__console_readLine.*", "can't send \r to stdin ,  newline terminator");
		ignoredNistWildcard.put("CWE113_HTTP_Response_Splitting__getQueryString_Servlet.*", "output is not urldecoded. can't send \r");
		ignoredNistWildcard.put("CWE400_Resource_Exhaustion__random.*", "not deterministically exploitable");
		ignoredNistWildcard.put("CWE400_Resource_Exhaustion__sleep_random.*", "not deterministically exploitable");
		ignoredNistWildcard.put("CWE833_Deadlock__synchronized_Objects_Servlet_01.*", "not exploitable, repeated requests are not concurrent enough to trigger deadlock");
		ignoredNistWildcard.put("CWE833_Deadlock__ReentrantLock_Servlet_01.*", "not exploitable, repeated requests are not concurrent enough to trigger deadlock");
		ignoredNistWildcard.put("CWE600_Uncaught_Exception_in_Servlet__getParameter_01.*", "not exploitable, no exception is thrown at runtime");
	}

	static class FileCluster {

		private List<File> files = new ArrayList<>();
		public File mainfile;

		public void add(File f) {
			files.add(f);
		}

	}
	
	public void generateModels(DocumentBuilder codBuilder, Element models) throws Exception {
		File testcodeDir = new File("../Input/Juliet/nist/juliet_v1_3/testcases");
		File base = new File("../Input/Juliet");
		
		Collection<File> listFiles = FileUtils.listFiles(base, TrueFileFilter.INSTANCE, TrueFileFilter.INSTANCE);
		
		generateJuliet(testcodeDir, codBuilder, models, listFiles);
		System.out.println("variants: " + String.join("\n", variants));
	}

	/**
	 * try to resolve the value of an int variable by looking for a literal initializer.
	 * if an int literal is returned, return its value
	 * very very basic
	 * @param parameter text (either integer, or varibale name)
	 * 
	 */
	private static Integer resolveIntParam(String param, String program) {
		try {
			return Integer.valueOf(param);
		} catch (NumberFormatException e) {
			
		}
		Pattern p = Pattern.compile("int " + param + "\\s*=\\s*(\\d+);");
		Matcher m = p.matcher(program);
		if (m.find()) {
			return Integer.valueOf(m.group(1));
		}
		return null;
	}
	
	private static int occurences(String str, String subStr) {
		int i = 0;
		int index = 0;
		while ((index = str.indexOf(subStr, index)) != -1) {
			i++;
			index ++;
		}
		return i;
	}
	
	
	
	private static Set<String> variants = new HashSet<>();
	
	private static void generateJuliet(File base, DocumentBuilder docBuilder, Element models,
			Collection<File> listFiles) throws IOException, SAXException {
		int totalCount = 0;
		int successCount = 0;
		
		int ignored = 0, ok =0;
		File testcasesupport = new File(base.getParent(), "testcasesupport");
		
		Map<String, FileCluster> combined = new HashMap<>();
		Pattern p = Pattern.compile(".*_([0-9])+");
		Pattern name = Pattern.compile("CWE([0-9]+)_(.*)__(.*)_([0-9]+)([a-zA-Z]*)(_.*)?");
		
		for (File f : listFiles) {
			if (f.getName().endsWith("_Helper.java"))
				continue;
			if (f.getName().startsWith("CWE") && f.getName().endsWith(".java")) {
				String key = f.getName();// .substring(0, f.getName().lastIndexOf("_"));
				
				Matcher m = p.matcher(key);
				if (m.find())
					key = key.substring(0, key.lastIndexOf(m.group(1)) + m.group(1).length());
				FileCluster g = combined.get(key);
				if (g == null) {
					g = new FileCluster();
					combined.put(key, g);
				}
				g.add(f);
			}

		}
		int modelCount = 0;
		Map<Integer, AtomicInteger> countCWES = new HashMap<>();
		Document doc = models.getOwnerDocument();
		int allsqlvulns = 0;
		nextFile: for (Entry<String, FileCluster> c : combined.entrySet()) {
			FileCluster cluster = c.getValue();
			String cweNum = cluster.files.get(0).getName();
			cweNum = cweNum.substring(cweNum.indexOf("CWE") + 3);
			cweNum = cweNum.substring(0, cweNum.indexOf("_"));
			if (cweNum.equals("89")) {
				allsqlvulns++;
			}

			int cwe = Integer.parseInt(cweNum);
			
			
			for (String sKey : ignoredNistWildcard.keySet()) {
				Pattern pp = Pattern.compile(sKey);
				if (pp.matcher(cluster.files.get(0).getName()).matches())
					continue nextFile;
			}
			if (c.getKey().contains("CWE601_Open_Redirect__Servlet_database_67")) {
				System.out.println();
			}
			
			AtomicInteger a = countCWES.get(cwe);
			if (a == null) {
				a = new AtomicInteger();
				countCWES.put(cwe, a);
			}
			a.incrementAndGet();
			
			
			Matcher fullNameMatcher = name.matcher(c.getKey());
			fullNameMatcher.find();
			String variant = fullNameMatcher.group(3);
			
			variants.add(variant);
			
			if (c.getKey().contains("_Servlet")) {
				// testcase should be hosted in a servlet container
				// and executed through servlet requests
			} else {
				// testcase methods should be executed directly
			}
			String attackInput = "";
			String attackOutput = "";
			String s = "";
			Map<String,String> defaultVars = new HashMap<>();
			for (File i : cluster.files) {
				String r = IOUtils.toString(i.toURL(), "UTF-8");
				if (r.contains("extends AbstractTestCaseServlet"))
					cluster.mainfile = i;
					
				if (r.contains("main(String[]")) {
					cluster.mainfile = i;
					
				}
				
				s += r;
			}
			
			

			if (c.getKey().contains("CWE89_SQL_Injection__getQueryString_Servlet_executeQuery_09")) {
				System.out.println();
			}
			
			
			String osRestriction = null;
			
			
			String servletPath = "/julietservlet_" + c.getKey();

			Pattern packagePattern = Pattern.compile("package ([\\.a-zA-Z0-9_]+);");
			Matcher m = packagePattern.matcher(s);
			
			if (!m.find()) {
				throw new RuntimeException("failed to get package");
			}
			
			String pckg = m.group(1);

			String classes = "";
			for (File f : cluster.files) {
				classes += String.format("<Class file=\"%s\" package=\"%s\" />\n", f.getAbsolutePath(), pckg);
			}
			classes += String.format("<Package dir=\"%s\" package=\"testcasesupport\" />", testcasesupport.getAbsoluteFile());
			File input = base.getParentFile().getParentFile().getParentFile().getParentFile();
			
			File pckg_owasp_helpers = new File(input, "BenchmarkJava/src/main/java/org/owasp/benchmark/helpers");
			
			classes += String.format("<Package dir=\"%s\" package=\"org.owasp.benchmark.helpers\" />\n", pckg_owasp_helpers.getAbsoluteFile());
			classes += String.format("<Package dir=\"%s\" package=\"org.owasp.benchmark.helpers.entities\" />\n", new File(pckg_owasp_helpers, "entities").getAbsoluteFile());
			classes += String.format("<Package dir=\"%s\" package=\"org.owasp.benchmark.helpers.filters\" />\n", new File(pckg_owasp_helpers, "filters").getAbsoluteFile());
			classes += String.format("<Package dir=\"%s\" package=\"org.owasp.benchmark.service.pojo\" />\n", new File(pckg_owasp_helpers.getParentFile(), "service/pojo").getAbsoluteFile());

			
			
			Set<String> profiles = new LinkedHashSet<>();
			boolean isServlet = false;
			String attackPattern = "";
			String clearTable = "DROP TABLE IF EXISTS USERS";

			if (s.contains("select name from users where id=0")) {
				//TODO: 
				profiles.add("ControlDatabase");
				defaultVars.put("InitQuery", "");
				attackInput = "<DatabaseInput connection=\"jdbc:sqlite:sample.db\" >" + clearTable + ";CREATE TABLE IF NOT EXISTS users ( id INTEGER PRIMARY KEY, name TEXT );DELETE FROM users WHERE 1=1;*InitQuery*;INSERT INTO users (id,name) VALUES (0,'*Input*');INSERT INTO users (id,name) VALUES (545454,'B3nchM3rk')</DatabaseInput>" + attackInput;
			} else if (s.contains("select * from users where")) {
				defaultVars.put("InitQuery", "");
				attackInput = "<DatabaseInput connection=\"jdbc:sqlite:sample.db\" >" +  clearTable + ";CREATE TABLE IF NOT EXISTS users ( id INTEGER PRIMARY KEY, name TEXT );DELETE FROM users WHERE 1=1;*InitQuery*;INSERT INTO users (id,name) VALUES (0,'*Input*');INSERT INTO users (id,name) VALUES (545454,'B3nchM3rk'); </DatabaseInput>" + attackInput;
			
			}
			
			if (s.contains("System.in")) {
				profiles.add("ControlStdIn");
				attackInput += "<StdIn reference=\"process0\" >*Input*\n</StdIn>";
			}
			if (s.contains("badSink.txt")) {
				attackOutput += "<WriteToFile path=\"badSink.txt\" "  + (c.getKey().startsWith("CWE400") ? "loadcontents=\"false\"" : "") +  " />";
			} else {
				Pattern fosPattern = Pattern.compile("new FileOutputStream\\((.*)\\)");
				Matcher fosMatcher = fosPattern.matcher(s);
				if (fosMatcher.find()) {
					String filename = resolveStringParam(fosMatcher.group(1), s);
					attackOutput += "<WriteToFile path=\"" + filename + "\" "  + (c.getKey().startsWith("CWE400") ? "loadcontents=\"false\"" : "") +  " />";
					
				}
			}
			
			// TODO: benign fixed string should not be the only writeLine
			// IO.writeLine must occur at least once.
			// if only output is "benign, fixed string", don't add stdout as output
			if (occurences(s, "IO.writeLine(") > occurences(s, "IO.writeLine(\"Benign, fixed string\");")) {
				attackOutput += "<StdOutAsync reference=\"process0\"/>";
			}
			
			
			
			if (s.contains("extends AbstractTestCaseServlet")) {
				isServlet = true;
			} else if (s.contains("extends AbstractTestCase")) {
				isServlet = false;
				attackInput = attackInput + "<Run/>\n";
			} else {
				//throw new RuntimeException("neither servlet nor java executable?");
			}
			
			if (s.contains("extends AbstractTestCaseServlet")) {
				profiles.add("ServletAccessBase");
				isServlet = true;
			} else {
				isServlet = false;
			}
			
			String environmentVars = "";
			if (s.contains("user.home\"")) {
				environmentVars += "<EnvironmentVariable name=\"user.home\" >*Input*</EnvironmentVariable>\n";
			}
			if (s.contains("\"ADD\"")) {
				environmentVars += "<EnvironmentVariable name=\"ADD\" >*Input*</EnvironmentVariable>\n";
			}
			
			if (s.contains("new URL(\"http://www.example.org/\")).openConnection()")) {
				String read = "<ReadFromURL host=\"www.example.org\" url=\"http://www.example.org/\" port=\"80\" >*Input*\n</ReadFromURL> \n";
				attackInput = read + attackInput;
			}
			
			if (s.contains("\"test.dll\"")) {
				attackPattern="dll";
				
				profiles.add("ControlTestDLL");
				attackInput += "<FileRead path=\"test.dll\"  >*Input*</FileRead> ";
			}
			if (s.contains("isRequestedSessionIdValid()")) {
				

			}
			if (c.getKey().contains("CWE833_Deadlock_")) {
				// TODO: ?????/
				attackPattern = "deadlock_timeout";
				
			}
			
			String serverSocketOptions = "";
			Pattern hostnameMatch = Pattern.compile("socket\\.getInetAddress\\(\\)\\.getHostName\\(\\)\\.equals\\(\"(.*)\"\\)");
			Matcher pckgm = hostnameMatch.matcher(s);
			if (pckgm.find()) {
			
				String host = pckgm.group(1);
				serverSocketOptions += "fakehostname=\"" + host + "\" fakeipaddress=\"99.9.9.99\"";
				
			}
			
			Pattern hostaddressMatch = Pattern.compile("socket\\.getInetAddress\\(\\)\\.getHostAddress\\(\\)\\.equals\\(\"(.*)\"\\)");
			Matcher ham = hostaddressMatch.matcher(s);
			if (ham.find()) {
			
				String host = ham.group(1);
				serverSocketOptions += "fakeipaddress=\"" + host + "\"";
				
			}
			
			Pattern newServerSocket = Pattern.compile("new ServerSocket\\((.*)\\)");
			Matcher serverSocket = newServerSocket.matcher(s);
			if (serverSocket.find()){
				String portStr = serverSocket.group(1);
				Integer port = resolveIntParam(portStr, s);
				
				if (port == null) {
					System.err.println("failed to get port");
				}
				if (s.contains(".getOutputStream(")) {
					attackOutput += String.format("<WriteToServerSocket port=\"%d\" %s /> \n", port, serverSocketOptions);
				}
				if (s.contains(".getInputStream(")) {
					//TODO: same as below
					String connect = String.format("<OpenServerSocket socketid=\"socket0\" port=\"%d\" />\n", port);
					String read = null;
					if (s.contains(".readLine(")) {
						read = String.format("<ReadFromServerSocket socketid=\"socket0\" port=\"%d\" >*Input*\n</ReadFromServerSocket> \n", port);
					} else {
						read = String.format("<ReadFromServerSocket socketid=\"socket0\" port=\"%d\" >*Input*</ReadFromServerSocket> \n", port);
					}
					
					attackInput =  attackInput + connect + read;
					
				}
			}
			
			
			

			
			if (s.contains("DriverManager.getConnection(\"data-url\", \"root\", password)")) {
				attackOutput = "<DummyDatabaseCredentialsOutput />";
			}
			
			
			if (s.contains("http://123.123.123.123:80")) {
				
				attackInput += "<HostWebpage url=\"http://123.123.123.123:80\" >*Input*</HostWebpage> \n";
			}
			
			if (s.contains("CWE259_Hard")) {
				profiles.add("AccessCode");
				profiles.add("AccessBinary");
			}

			String interestingOutput = "response=\"*Output*\"";

			if (c.getKey().contains("CWE470_Unsafe_Reflection")) {
				attackPattern = "UnsafeReflection";
				
			}
			
			if (cwe == 549) {
				attackPattern = "MissingPasswordMasking";
			}
			
			if (cwe == 789) {
				attackPattern = "<AttackPattern id=\"ResourceExcaustion\">";
				attackOutput += "<StdErrAsync />";
				if (attackOutput == null || attackOutput.isEmpty()) {
					attackOutput = "<NoOutput />";
				}
			}

			if (c.getKey().startsWith("CWE549_")) {
				// todo
			}
			if (c.getKey().contains("CWE315_")) {
				attackPattern = "HardcodedPassword";
			}
			if (c.getKey().startsWith("CWE319")) {
				attackPattern = "cleartextpassword";
				
			}
			if (c.getKey().startsWith("CWE534_Info_Exposure_Debug_Log_")) {
				attackPattern = "infoExposure";
			}
			
			if (cwe == 510) {
				attackPattern = "CWE510_spoof_src_ip";
			}

			if (cwe == 511) {
				String binary = "c:\\windows\\system32\\evil.exe";
				attackOutput = "<ExecutesBinary binarypath=\"" + binary +  "\" />";
				attackInput = "<Run />";
				attackPattern = "CWE511_check_binary_executed";
			} 
			
			// http response splitting
			// servlet does not explicitly write a response
			if (cwe == 113) {
				attackOutput = "<URLRequestResponse reference=\"request0\" />";
			}
			String successfullExploit = "";
			if (c.getKey().startsWith("CWE89_SQL_Injectio")) {
				attackPattern = "SQLInjection";
				attackOutput += "<DatabaseOutput connection=\"jdbc:sqlite:sample.db\" statement=\"SELECT * FROM users\" />";
				if (!attackInput.contains("DatabaseInput")) {
					if (s.contains("update users set hitcount") || s.contains("insert into users (status) values")) {
						defaultVars.put("InitQuery", "");
						String create = "*InitQuery*";
						// implicit input
						attackInput = "<DatabaseInput connection=\"jdbc:sqlite:sample.db\" >" + clearTable + ";" + create + ";CREATE TABLE IF NOT EXISTS users ( id INTEGER PRIMARY KEY, name TEXT, status TEXT, hitcount int )</DatabaseInput>\n" + attackInput;
	
					}
					
					if (s.contains("select * from users where ")) {
						String create = "*InitQuery*";
						attackInput = "<DatabaseInput connection=\"jdbc:sqlite:sample.db\" >" + clearTable + ";"  + create + ";CREATE TABLE IF NOT EXISTS users ( id INTEGER PRIMARY KEY, name TEXT, status TEXT, hitcount int )</DatabaseInput>\n" + attackInput;
					}
				}
			}
			
			
			/*
			 * if (c.getKey().startsWith("CWE789_Uncontrolled_Mem_Alloc")) {
			 * interestingOutput =
			 * "httpResponseHeaders=\"*Output*\" httpResponseCode=\"302\""; patternInput =
			 * "LargeNumberInput"; patternOutput = ""; }
			 */
			if (c.getKey().startsWith("CWE400_Resource_Exhaustion")) {
				attackPattern = "ResourceExcaustion";
				if (c.getKey().contains("sleep")) {
					attackOutput = "<NoOutput />";
					attackPattern = "LargeNumberInputTimeout";
				}
			}
			
			
			if (s.contains("request.getParameter(\"name\")")) {
				attackInput = attackInput + "<URLRequest url=\"http://*Host*:*Port*" + servletPath + "?name=*Input*\" id=\"request0\" method=\"GET\" />";
			}
			if (s.contains("StringTokenizer tokenizer = new StringTokenizer(request.getQueryString(), \"&\")"))
				attackInput = attackInput + "<URLRequest url=\"http://*Host*:*Port*" + servletPath + "?id=*Input*\" id=\"request0\" method=\"GET\" />";

			if (s.contains("cookieSources[0].getValue()"))
				attackInput = attackInput + "<URLRequest url=\"http://*Host*:*Port*" + servletPath + "\" id=\"request0\"  method=\"GET\"  >\n" + 
			"  <HTTPHeaders><HTTPHeader name=\"Cookie\">c=*Input*</HTTPHeader></HTTPHeaders>\n" + "</URLRequest>";

			
			// the testcase does not use inputs. add  blank inputs to trigger code:
			if (isServlet && !attackInput.contains("URLRequest")) {
				String req = "\n<URLRequest url=\"http://*Host*:*Port*" + servletPath + "\" id=\"request0\" method=\"GET\" />";
				if (c.getKey().startsWith("CWE400_Resource_Exhaustion") && s.contains("getInputStream")) {
					req = "\n<URLRequest url=\"http://*Host*:*Port*" + servletPath + "\" id=\"request0\" method=\"GET\" ><BinaryInputData id=\"Input\" /></URLRequest>";
				}
				if (attackInput.contains("Database") || attackInput.contains("FileRead") || attackInput.contains("ReadFromURL")) {
					attackInput =  attackInput + req;
				} else {

					attackInput =  req + attackInput;
				}
			}
			
			Pattern newSocket = Pattern.compile("new Socket\\((.*),\\s*(.*)\\)");
			m = newSocket.matcher(s);
			if (m.find()) {
				String hostStr = m.group(1);
				String host = resolveStringParam(hostStr, s);
				String portStr = m.group(2);
				Integer port = resolveIntParam(portStr, s);
				if (port == null) {
					System.err.println("failed to get port");
				}
				if (s.contains(".getOutputStream(")) {
					attackOutput += String.format("<WriteToRemoteSocket host=\"%s\" port=\"%d\" /> \n", host, port);
					
				}
				if (s.contains(".getInputStream(")) {
					//TODO: need to specify order somehow.
					String connect = String.format("<ConnectToRemoteSocket socketid=\"socket0\" host=\"%s\" port=\"%d\" />", host, port);
					String read = " <ReadFromRemoteSocket socketid=\"socket0\" >*Input*\n</ReadFromRemoteSocket>\n";
					
					if (attackInput != null && attackInput.contains("<Run")) {
						attackInput = attackInput.replace("<Run/>", "") + connect + "<Run />\n" + read;
					} else {
						attackInput = connect + attackInput + read;
					}
				}
			}
			
			if (s.contains("response.getWriter()")) {
				attackOutput += "<URLRequestResponse reference=\"request0\" />";
			}
			
			if (s.contains("response.addCookie(") && cwe != 113) {
				attackOutput += "<URLRequestResponseCookie reference=\"request0\" />";
			}
			
			
			if (s.contains("C:\\\\data.txt")) {
				attackInput = "<FileRead path=\"C:\\data.txt\" >*Input*</FileRead>" + attackInput;
			} else if (s.contains("new FileInputStream") && !s.contains("../common/config.properties")) {
				attackInput = "<FileRead path=\"*file*\" >*Input*</FileRead>" + attackInput;
			}
			if (s.contains("../common/config.properties")) {
				if (s.contains("properties.getProperty")) {
					Pattern getPropertyName = Pattern.compile("properties.getProperty\\((.*)\\)");
					Matcher paramMatcher = getPropertyName.matcher(s);
					paramMatcher.find();
					String param = paramMatcher.group(1);
					String parameterName = resolveStringParam(param, s);
					attackInput = "<PropertiesFileParameter path=\"../common/config.properties\" key=\"" + parameterName + "\">*Input*</PropertiesFileParameter>\n" + attackInput;
				} else {
					attackInput = "<FileRead path=\"../common/config.properties\" >*Input*</FileRead>\n" + attackInput;
				}
			}
			
			if (!environmentVars.isEmpty()) {
				attackInput = "<EnvironmentVariables>\n" + environmentVars + "</EnvironmentVariables>\n" + (isServlet ? "<RestartEnvironment />" : "") + attackInput;
				
			} else if (isServlet && attackInput.contains("StdIn")) {
				attackInput = "<RestartEnvironment />" + attackInput;
			}
			
			if (s.contains("socket.getOutputStream()")) {
				
				if (!attackOutput.contains("Socket")) {
					System.err.println(String.format("Testcase %s writes to unknown socket", c.getKey()));
					continue;
				}
			}
			if (s.contains("socket.getInputStream()")) {
				if (!attackInput.contains("Socket")) {
					System.err.println(String.format("Testcase %s reads from unknown socket", c.getKey()));
					continue;
				}
			}
			
			
			if (c.getKey().contains("XSS")) {
				attackPattern = "XSS";
			}
			if (s.toString().contains("badSink.txt")) {
				profiles.add("ControlBadSink");
			}
			

			if (c.getKey().startsWith("CWE526")) {
				attackPattern = "ExposedPath";
			}
			if (c.getKey().contains("CWE600_Uncaught_Exception_in_Servlet")) {
				attackPattern = "StackTraceCWE600";
			}
			if (c.getKey().startsWith("CWE113_HTTP_Response")) {
				attackPattern = "HTTPResponseSplitting";
				if (s.contains(".readLine()")) {
					ignoredNistWildcard.put(c.getKey() + ".*", "testcase uses readLine(). can't send \r, readLine uses this as newline terminator");
					continue;
				}
				
				// TODO: ??
			}

			if (c.getKey().startsWith("CWE614_Sensitive_Cookie_")) {
				attackPattern = "InsecureCookie";

			}
			if (c.getKey().startsWith("CWE315")) {
				attackPattern = "HardcodedPassword";
			}

			if (c.getKey().startsWith("CWE36_Absolute_Path_Traversal")) {
				attackPattern = "PathTraversal";
			}
			if (c.getKey().startsWith("CWE23")) {
				attackPattern = "PathTraversal";
			}
			if (c.getKey().startsWith("CWE78_OS_Command_Injectio")) {
				attackPattern = "CommandInjection";			}

			if (c.getKey().startsWith("CWE90_LDAP_Injectio")) {
				attackPattern = "LDAPInjection";
			}
			if (c.getKey().startsWith("CWE523_Unprotected_Cred_Transport__Servlet_")) {
				attackPattern = "FormUnprotectedCredentials";
			}

			if (cwe == 526 || cwe == 789 || cwe == 209 || cwe == 835 || cwe == 833 || cwe == 511 || cwe == 674
					|| cwe == 400 || cwe == 193 || cwe == 476 || cwe == 328 || cwe == 760 || cwe == 336 || cwe == 759) {
				
				//TODO: ????

			}
			if (cwe == 382) {
				attackPattern = "exit_code_1";
			}
			if (cwe == 835) {
				attackPattern = "LargeNumberInputTimeout";
				attackInput = "<Run />";
			}
			if (cwe == 598) {
				attackPattern = "CWE598_Information_Exposure";
			}
			if (s.contains("c:\\\\windows\\\\system32\\\\evil.exe")) {
				//TODO: 
			}

			if (c.getKey().startsWith("CWE209_")) {
				attackPattern = "StackTraceCWE600";
				attackOutput += "<StdErrAsync />";
			}

			if (c.getKey().startsWith("CWE835_Infinite_Loop__")
					|| c.getKey().startsWith("CWE674_Uncontrolled_Recursion__")) {
				//TODO: no output??
			}
			if (c.getKey().startsWith("CWE114_Process_Control__basic")) {
				attackOutput = "<StdOut />";
				attackInput = "<Run /> \n <LoadLibrary path=\"test.dll\" />";
				attackPattern = "LoadLibrary";
			}
			if (c.getKey().startsWith("CWE111_Unsafe_JNI")) {
				attackOutput = "<StdOut />";
				attackInput = " <LoadLibrary path=\"libJNITest.so\" /> \n <Run />\n" + "<StdIn reference=\"process0\" >hello\n20\n</StdIn>";
				attackPattern = "LoadLibrary";
			}

			if (cwe == 598) {
				// TODO
			}
			if (cwe == 674) {
				attackPattern = "exit_code_1";
			}
			if (cwe == 382) {
				// TODO
			}

			if (c.getKey().startsWith("CWE510_Trapdoor__ip_based_logic")) {
				// TODO
			}

			if (c.getKey().toString().contains("CWE789_") || c.getKey().toString().contains("CWE606_")) {
				attackPattern = "ResourceExcaustion";
			}
			
			if (cwe == 601) {
				attackPattern = "URLRedirect";
				attackOutput += "<URLRequestResponseHeader reference=\"request0\" />";
			}
			
			if (c.getKey().startsWith("CWE78_OS_Command_Injection")) {
				attackOutput = "<NoOutput />";
				osRestriction = "\n<SupportedOperatingSystems> <OS type=\"win\" /> </SupportedOperatingSystems>";
			}
			
			if (attackInput.contains("DatabaseInput") || attackOutput.contains("DatabaseOutput")) {
				File pckg_database = new File("../Runtime/src/de/fraunhofer/sit/runexploits/database");
			}
			/*
			 * if (cwe == 526 || cwe == 789 || cwe == 209 || cwe == 835 || cwe == 833 || cwe
			 * == 511 || cwe == 674 || cwe == 400 || cwe == 193 || cwe == 476 || cwe == 328
			 * || cwe == 760 || cwe == 336 || cwe == 759)
			 */
			{
				if (!isServlet)
					profiles.add("Run");
				else if (attackInput == null || !attackInput.contains("<URL")) {
					if (attackInput == null)
						attackInput = "";
					//attackInput += "<!-- Only to trigger the servlet code --> <URLRequest url=\"http://*Host*:*Port*/*TestKey*\" method=\"GET\"/>";
				}
			}

			if (profiles.isEmpty()) {
				// System.out.println(s);
				System.err.println("No profile for " + cluster.files);
				// System.out.println();
			}

			
			// generate one testcase per good() or bad() method
			totalCount += 2;
			String[] testmethods = new String[] {"good", "bad"};
			//TODO: fill this array
			String mainClass ="Rsealdftrpeakdfr";
			for (String testMethod : testmethods) {
			
				String executionProfile = null;
				if (isServlet) {
					executionProfile = String.format("<ServletWrapper classname=\"%s.%s\" methodname=\"%s\" path=\"%s\" processid=\"process0\" />", pckg, mainClass, testMethod, servletPath);
				} else {
					executionProfile = String.format("<JavaMethodExecution processid=\"process0\" classname=\"%s.%s\" methodname=\"%s\" />", pckg, mainClass, testMethod);
					
				}
				
				
				Element testElem = doc.createElement("Test");
	
				testElem.setAttribute("Key", c.getKey() + "_" + testMethod);
				if (!testMethod.contains("bad") && !testMethod.contains("good"))
					throw new RuntimeException(testMethod + " is neither good or bad");
				boolean exploitable = testMethod.contains("bad");
				


				if (ignoredCompletely.get(cwe) != null) {
					ignoreTestcase(exploitable, doc, models, "Juliet", c.getKey(), cweNum, ignoredCompletely.get(cwe));
					continue;
				}
				if (ignoredNistCompletely.get(cwe) != null) {
					ignoreTestcase(exploitable, doc, models, "Juliet", c.getKey(), cweNum, ignoredNistCompletely.get(cwe));
					continue;
				}
				if (s.contains("Runtime.getRuntime().exec(osCommand + data);")) {
					// not exploitable...
			 
					ignoreTestcase(exploitable, doc, models, "Juliet", c.getKey(), cweNum, "not exploitable on linux");
					continue;
						
				}
				
				Pattern insertIntoWhere = Pattern.compile("\"insert into [^\"]* where.*\"");
				if (insertIntoWhere.matcher(s).find()) {
					// invalid sql
					ignoreTestcase(exploitable, doc, models, "Juliet", c.getKey(), cweNum, "insert into where is not a valid sql statement");
					ignored++;
					continue;
				}
				ok++;
				if (s.contains("staticReturnsTrueOrFalse")) {
					ignoreTestcase(exploitable, doc, models, "Juliet", c.getKey(), cweNum, "not deterministically exploitable: uses random function");

					continue;
				}
				testElem.setAttribute("exploitable", exploitable ? "true" : "false");
				if (!exploitable) {
					testElem.setAttribute("reasonNotExploitable", "Not exploitable by design (OWASP)");
				}
				testElem.setAttribute("testsuite", "Juliet");
				testElem.setAttribute("cwe", cweNum);
				for (String pp : profiles) {
					Element r = doc.createElement("ReferenceProfile");
					r.setAttribute("name", pp);
					testElem.appendChild(r);
				}
	
				if (attackOutput.isEmpty()) { // || attackInput == null || attackPattern == null) {
					System.err.println("No output detected for " + c.getKey() + " cwe " + cwe);
					continue;
				}
				
				if (attackInput.isEmpty()) {
					System.err.println("No input detected for " + c.getKey() + " cwe " + cwe);
					continue;
				}
				if (attackPattern.isEmpty()) {
					System.err.println("No attackpattern detected for " + c.getKey() + " cwe " + cwe);
					continue;
				}
				successCount ++;
				if (osRestriction != null)
					appendXmlFragment(docBuilder, testElem, osRestriction);
				if (!defaultVars.isEmpty()) {
					String defaultVarXML = "";
					for (Entry<String, String> kv : defaultVars.entrySet()) {
						defaultVarXML += "<String id=\""+kv.getKey()+"\">"+kv.getValue()+"</String>";
					}
					appendXmlFragment(docBuilder, testElem, "    <DefaultVariables>" + defaultVarXML + "</DefaultVariables>");
					
							
				}
				appendXmlFragment(docBuilder, testElem, "    " + "<AttackPattern id=\"" + attackPattern + "\" />");
				appendXmlFragment(docBuilder, testElem, "    <ExecutionProfile>" + executionProfile + "</ExecutionProfile>");
				appendXmlFragment(docBuilder, testElem, "    <Inputs>" + attackInput + "</Inputs>");
			
				appendXmlFragment(docBuilder, testElem,
						"    <Outputs>" + attackOutput + "</Outputs>");
				appendXmlFragment(docBuilder, testElem, "<Classes>\n" + classes + "</Classes>");
				models.appendChild(testElem);
				
				modelCount ++;
			}
 
		}
		
		int xa = 0;
		for (Entry<Integer, AtomicInteger> l : countCWES.entrySet()) {
			xa += l.getValue().intValue();
		}
		
		for (Entry<String, Integer> c : SpecificationProvider.s.entrySet())
		System.out.println(c.getKey() + "|" + c.getValue());
		System.out.println("generated " + modelCount + " models out of " + totalCount);
	}

	public static void appendXmlFragment(DocumentBuilder docBuilder, Node parent, String fragment)
			throws IOException, SAXException {
		Document doc = parent.getOwnerDocument();
		Node fragmentNode = docBuilder.parse(new InputSource(new StringReader(fragment))).getDocumentElement();
		fragmentNode = doc.importNode(fragmentNode, true);
		parent.appendChild(fragmentNode);
	}

	private static String selectProfile(String profile, String string) {
		if (profile != null)
			throw new IllegalStateException("Previous profile: " + profile + "; " + string);
		return string;
	}
	public static void main(String[] args) throws Exception {
		CreateAllSpecifications.main(args);
	}
}
