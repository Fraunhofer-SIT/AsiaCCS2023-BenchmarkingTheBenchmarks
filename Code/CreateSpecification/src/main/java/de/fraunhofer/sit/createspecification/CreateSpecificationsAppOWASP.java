package de.fraunhofer.sit.createspecification;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.filefilter.SuffixFileFilter;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * 
 * @author naeumann
 *
 */
public class CreateSpecificationsAppOWASP extends SpecificationProvider {

	public static Map<Integer, String> ignoredOWASP;
	public static Map<Integer, String> ignoredOWASPSingleCases;
	static {
		ignoredOWASP = new HashMap<>();
		ignoredOWASP.put(327, "weak crypto");
		ignoredOWASP.put(328, "weak hash");
		ignoredOWASP.put(330, "weak randomness");
		ignoredOWASP.put(501, "sets server-side session attribute: not dynamically verifiable");
		ignoredOWASP.put(614, "insecure cookie not verifiable");
		ignoredOWASPSingleCases = new HashMap<>();
		
		ignoredOWASPSingleCases.put(00743, "Not exploitable: input is passed to vulnerable shellscript as argument, but argument is unused");
		//ignoredOWASPSingleCases.put(196, "sql not exploitable");
		//ignoredOWASPSingleCases.put(1624, "sql not exploitable");
		ignoredOWASPSingleCases.put(1006, "org.springframework.dao.IncorrectResultSizeDataAccessException. program tries to assign 4 values to one var.");
		// 78  - Command Injection Category 
	    // 327 - (Weak Encryption Algorithm Category)
	    // 328 - (Weak Hashing Algorithm Category)
	    // 879 - LDAP Injection Category
	    // 22  - Path Traversal Category
	    // 614 - Insecure Cookie Category ????
	    // 89  - SQL Injection Category
	    // 501 - Trust Boundary Category ????
	    // 330 - (Weak Randomness Category)
	    // 643 - XPath Injection Category
	    // 79  - XSS (Cross-Site Scripting) Category

		
		
	}
	
	public void generateModels(DocumentBuilder codBuilder, Element models) throws Exception {
		File testcodeDir = new File("../Input/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/");
		generateOWASP(testcodeDir, codBuilder, models);
	}


	static class FileCluster {

		private List<File> files = new ArrayList<>();
		public File mainfile;

		public void add(File f) {
			files.add(f);
		}

	}

	private static void generateOWASP(File testcodeDir, DocumentBuilder docBuilder, Element models) throws IOException, SAXException, ParserConfigurationException {
		Document modelsDoc = models.getOwnerDocument();
		// get list of metadata xmls
		Collection<File> xmlfiles = FileUtils.listFiles(testcodeDir, new SuffixFileFilter("xml"), TrueFileFilter.INSTANCE);
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		Pattern servletPathPattern = Pattern.compile("@WebServlet\\(value = \"(.*)\"\\)");
		Pattern servletPathComposition = Pattern.compile("\\/(.*)-(\\d+)\\/(BenchmarkTest\\d+)");
		//Pattern getHeaderPattern = Pattern.compile("request.getHeader\\(\"(.*)\"\\)");
		//Pattern getCookiesPattern = Pattern.compile("javax.servlet.http.Cookie\\(\"([a-zA-Z0-9]*)\""); 
		Pattern getPropertyName = Pattern.compile("request.getHeaders?\\(([\"a-zA-Z0-9_]*)\\)");
		
		String getCookiesPattern = "request.getCookies";
		String getParamsPattern0 = "request.getParameter";
		String getParamsPattern1 = "request.getParameterNames";
		String getParamsPattern2 = "request.getParameterValues";
		String getParamsPattern3 = "request.getParameterMap";
		String getParamsPattern4 = "getTheParameter";
		String getParamsPattern5 = "getTheValue";
		String getQueryPattern = "request.getQueryString";
		
		String printOSCommand = "Utils.printOSCommandResults";
		Pattern responseWriter = Pattern.compile("response\\s*\\n?\\s*.getWriter\\(\\)");
		String setHeader = "response.setHeader";
		String bodyPattern = "request.getInputStream";
		int modelsCount = 0;

		for (File f : xmlfiles) {

			DocumentBuilder db = dbf.newDocumentBuilder();
			Document testModel = db.parse(f);

			NodeList metadata = testModel.getDocumentElement().getChildNodes();
			String testNumberStr = null;
			String cweStr = null;
			boolean vulnerability = false;
			for (int i = 0; i < metadata.getLength(); i++) {
				Node child = metadata.item(i);
				if (child.getNodeType() == Node.ELEMENT_NODE) {
					if ("test-number".equals(child.getNodeName())) {
						testNumberStr = child.getTextContent();
					} else if ("cwe".equals(child.getNodeName())) {
						cweStr = child.getTextContent();
					} else if ("vulnerability".equals(child.getNodeName())) {
						vulnerability = "true".equals(child.getTextContent());
					}
				}

			}

			if (cweStr == null || testNumberStr == null)
				continue;
			
			

			File java = new File(testcodeDir, String.format("BenchmarkTest%s.java",testNumberStr) );



			int cwe = Integer.parseInt(cweStr);
			int testNumber = Integer.parseInt(testNumberStr);

			if (CreateSpecificationsAppJuliet.ignoredCompletely.get(cwe) != null) {
				ignoreTestcase(vulnerability, testModel, models, "OWASP", testNumberStr, cweStr, CreateSpecificationsAppJuliet.ignoredCompletely.get(cwe));
				continue;
			}
			if (ignoredOWASP.get(cwe) != null) {
				ignoreTestcase(vulnerability, testModel, models, "OWASP", testNumberStr, cweStr, ignoredOWASP.get(cwe));
				continue;
			}
			if (CreateSpecificationsAppJuliet.ignoredNistCompletely.get(cwe) != null) {
				ignoreTestcase(vulnerability, testModel, models, "OWASP", testNumberStr, cweStr, CreateSpecificationsAppJuliet.ignoredNistCompletely.get(cwe));
				continue;
			}
			if (ignoredOWASPSingleCases.get(testNumber) != null) {
				ignoreTestcase(vulnerability, testModel, models, "OWASP", testNumberStr, cweStr, ignoredOWASPSingleCases.get(testNumber));
				continue;
			}
			if (ignoredOWASP.get(testNumber) != null) {
				ignoreTestcase(vulnerability, testModel, models, "OWASP", testNumberStr, cweStr, ignoredOWASP.get(testNumber));
				continue;
			}
			
			String s = IOUtils.toString(java.toURL(), "UTF-8");

			if (cwe == 78) {
				// command injection
				if (s.contains("\"echo\"")) {
					// testcase input is concatenated to echo command. this is useless, as arguments are NOT evaluated.
					ignoreTestcase(vulnerability, testModel, models, "OWASP", testNumberStr, cweStr, "Not exploitable on linux. input is passed as argument to shell script, but not evaluated.");

					continue;
				}
			}
			if (cwe == 89) {
				if (s.contains("batchUpdate") || s.contains("executeBatch")) {
					ignoreTestcase(vulnerability, testModel, models, "OWASP", testNumberStr, cweStr, "Exploit not verifiable for batchUpdate and executeBatch. no output is available. drop table can not be injected (java.sql.BatchUpdateException: unexpected token: DROP)");

					continue;
				}
			}
			
			Matcher m = servletPathPattern.matcher(s);
			if (!m.find())
				continue;

			String servletPath = m.group(1);

			Matcher pathComponents = servletPathComposition.matcher(servletPath);

			if (!pathComponents.matches())
				throw new RuntimeException("couldn't find path");
			String category = pathComponents.group(1);
			String subcategoryStr = pathComponents.group(2);
			String testName = pathComponents.group(3);

			

			Set<String> profiles = new LinkedHashSet<>();
			boolean isServlet = false;
			
			String attackInput = null;
			
			String inputs = "";
			String outputs = "";
			String attackPattern = null;
			

			String attackOutput = "";

			profiles.add("ServletAccessBase");
			
			// type of vulnerability
			if (cwe == 78 ) {
				attackPattern = "<AttackPattern id=\"CommandInjection\" />";
			} else if (cwe == 89) {
				attackPattern = "<AttackPattern id=\"SQLInjection\" />";
			} else if (cwe == 79) {
				attackPattern = "<AttackPattern id=\"XSS\" />";
			} else if (cwe == 22) {
				attackPattern = "<AttackPattern id=\"PathTraversal\" />";
			} else if (cwe == 643) {
				attackPattern = "<AttackPattern id=\"XPathInjection\" />";
			} else if (cwe == 90) {
				attackPattern = "<AttackPattern id=\"LDAPInjection\" />";
			} else if (cwe == 614) {
				attackPattern = "<AttackPattern id=\"insecurecookie\" />";
			}
			
			// "vulnerability output"

			boolean outputInResponse = s.contains(printOSCommand) || responseWriter.matcher(s).find();
			boolean outputInHeader = s.contains(setHeader);
			
			if (outputInResponse) {
				attackOutput += "<URLRequestResponse reference=\"request1\"  />";
			}
			if (outputInHeader) {
				attackOutput += "<URLRequestResponseHeader reference=\"request1\" />";
			}
			if (attackOutput.isEmpty()){
				System.err.println("unknown data leak destination in " + testName);
				attackOutput = "";
			}
			
			if (cwe == 89) {
				attackOutput += "<DatabaseOutput connection=\"jdbc:hsqldb:hsql://localhost/benchmarkDataBase\" />";
				
			}
			
			
			
			// names of header/cookie/param are usually equal to name of test
			Matcher paramMatcher = getPropertyName.matcher(s);
			boolean getHeader = paramMatcher.find();
			
			
			boolean getCookie = s.contains(getCookiesPattern);
			boolean getParam = s.contains(getParamsPattern0) || s.contains(getParamsPattern1) || s.contains(getParamsPattern2) || s.contains(getParamsPattern3) || s.contains(getParamsPattern4) || s.contains(getParamsPattern5);
			
			boolean getQuery = s.contains(getQueryPattern);
			boolean inBody = s.contains(bodyPattern);			
			
			
			
			// "vulnerability input"
			if (getHeader) {

				String param = paramMatcher.group(1);
				String parameterName = resolveStringParam(param, s); 
				
				attackInput = String.format(
						"<URLRequest url=\"http://*Host*:*Port*%s\" id=\"request1\" method=\"POST\" >\n" + 
						"  <HTTPHeaders><HTTPHeader name=\"%s\">*Input*</HTTPHeader></HTTPHeaders> \n" +
						"</URLRequest>"
						, servletPath, parameterName);
				if (parameterName == null) {
					// plot twist: header name is input
					attackInput = String.format(
							"<URLRequest url=\"http://*Host*:*Port*%s\" id=\"request1\" method=\"POST\" >\n" + 
							"  <HTTPHeaders><HTTPHeader name=\"*Input*\">Unused</HTTPHeader></HTTPHeaders> \n" +
							"</URLRequest>"
							, servletPath);
					// NOTE: OWASP testcases were modified
					
				}
			} else if (getCookie) {
				attackInput = String.format(
						"<URLRequest url=\"http://*Host*:*Port*%s\" id=\"request1\" method=\"POST\" >\n" + 
						"  <HTTPHeaders><HTTPHeader name=\"Cookie\">%s=*Input*</HTTPHeader></HTTPHeaders>\n" +
						"</URLRequest>"
						, servletPath, testName);
			} else if (getParam || getQuery) {
				attackInput = String.format("<URLRequest url=\"http://*Host*:*Port*%s?%s=*Input*\" id=\"request1\" method=\"POST\"   />", servletPath, testName);
				if (s.contains("value.equals(\"Benchmark")) {
					// PLOT TWIST
					// input is header name...
					attackInput = String.format("<URLRequest url=\"http://*Host*:*Port*%s?*Input*=%s\" id=\"request1\" method=\"POST\"   />", servletPath, testName);
				}
			} else if (inBody) {
				// todo: support string / binary input to urlrequests
				attackInput = String.format("<URLRequest url=\"http://*Host*:*Port*%s\" id=\"request1\" body=\"%s\" method=\"POST\"  > \n"
						+ "						 <StringInputData>*Input*</StringInputData>\n"
						+ "						</URLRequest>", servletPath, testName);
			}  else {
				System.err.println("unknown attack input in " + testName);
			}
			
			if (cwe == 614) {
				attackPattern = "<AttackPattern id=\"insecurecookie\" />";
				attackOutput += "<URLRequestResponseCookie reference=\"request1\" />";
			}
			if (profiles.isEmpty()) {
				// System.out.println(s);
				System.err.println("No profile for " + testNumber);
				// System.out.println();
			}
			HashMap<String, String> defaultVars = new HashMap<String, String>();
			
			if (cwe == 89) {
				defaultVars.put("InitQuery", "");
				attackInput = "<DatabaseInput connection=\"jdbc:hsqldb:hsql://localhost/benchmarkDataBase\" >*InitQuery*</DatabaseInput>" + attackInput;

			}

			Element testElem = modelsDoc.createElement("Test");

			testElem.setAttribute("Key", "OWASP_"+testNumberStr);
			testElem.setAttribute("testsuite", "OWASP");
			testElem.setAttribute("cwe", cweStr);
			for (String pp : profiles) {
				Element r = modelsDoc.createElement("ReferenceProfile");
				r.setAttribute("name", pp);
				testElem.appendChild(r);
			}

			if (attackOutput == null || attackInput == null || attackPattern == null) {
				System.err.println("No exploit model created for " + testName + " cwe " + cwe);
				continue;
			}
			
			
			
			String executionProfile = String.format("<ServletWrapper classname=\"org.owasp.benchmark.testcode.%s\" methodname=\"doGet\" path=\"%s\" processid=\"process0\" />", testName, servletPath);
		
			
			
			testElem.setAttribute("exploitable",  vulnerability ? "true" : "false" );
			if (!vulnerability) {
				testElem.setAttribute("reasonNotExploitable", "Not exploitable by design (OWASP)");
			}

			if (attackOutput.isEmpty()) { // || attackInput == null || attackPattern == null) {
				System.err.println("No output detected for " + testName + " cwe " + cwe);
				continue;
			}
			
			if (attackInput.isEmpty()) {
				System.err.println("No input detected for " + testName + " cwe " + cwe);
				continue;
			}
			if (attackPattern.isEmpty()) {
				System.err.println("No attackpattern detected for " + testName + " cwe " + cwe);
				continue;
			}

			if (!defaultVars.isEmpty()) {
				String defaultVarXML = "";
				for (Entry<String, String> kv : defaultVars.entrySet()) {
					defaultVarXML += "<String id=\""+kv.getKey()+"\">"+kv.getValue()+"</String>";
				}
				appendXmlFragment(docBuilder, testElem, "    <DefaultVariables>" + defaultVarXML + "</DefaultVariables>");
				
						
			}
			
			appendXmlFragment(docBuilder, testElem, attackPattern);
			appendXmlFragment(docBuilder, testElem, "    <ExecutionProfile>" + executionProfile + "</ExecutionProfile>");
			appendXmlFragment(docBuilder, testElem, "    <Inputs>" + attackInput + "</Inputs>");
		
			appendXmlFragment(docBuilder, testElem,
					"    <Outputs>" + attackOutput + "</Outputs>");
			String classes = String.format("<Class file=\"%s\" package=\"org.owasp.benchmark.testcode\" />\n", java.getAbsolutePath());

			File pckg_owasp_helpers = new File(testcodeDir.getParent(), "helpers");
			
			classes += String.format("<Package dir=\"%s\" package=\"org.owasp.benchmark.helpers\" />\n", pckg_owasp_helpers.getAbsoluteFile());
			classes += String.format("<Package dir=\"%s\" package=\"org.owasp.benchmark.helpers.entities\" />\n", new File(pckg_owasp_helpers, "entities").getAbsoluteFile());
			classes += String.format("<Package dir=\"%s\" package=\"org.owasp.benchmark.helpers.filters\" />\n", new File(pckg_owasp_helpers, "filters").getAbsoluteFile());
			classes += String.format("<Package dir=\"%s\" package=\"org.owasp.benchmark.service.pojo\" />\n", new File(testcodeDir.getParent(), "service/pojo").getAbsoluteFile());

			appendXmlFragment(docBuilder, testElem, "<Classes>\n" + classes + "</Classes>");
			models.appendChild(testElem);
			
			modelsCount ++;

		}
		System.out.println("Number of models: " + modelsCount);
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
