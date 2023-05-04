package de.fraunhofer.sit.createspecification;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SpecificationProvider {
	public static CountingMap<String> s = new CountingMap<>();
	
	
	 static void ignoreTestcase(boolean truemodel, Document doc, Element models, String testsuite, String key, String cwe, String reason) {
		if (reason == null) {
			throw new NullPointerException();
		}
		Element test = models.getOwnerDocument().createElement("Test");
		test.setAttribute("Key", key);
		test.setAttribute("exploitable", truemodel ? "true" : "false");
		test.setAttribute("reasonNotExploitable", reason);
		test.setAttribute("testsuite", testsuite);
		test.setAttribute("cwe", cwe);
		
		s.increment(cwe + "|" + reason);
		models.appendChild(test);
	}
	static String resolveStringParam(String param, String program) {
		if (param.charAt(0) == '"') {
			return param.substring(1, param.length()-1);
		}
		Pattern p = Pattern.compile("String" + param + "\\s*=\\s*\"(\\d+)\";");
		Matcher m = p.matcher(program);
		if (m.find()) {
			return m.group(1);
		}
		return null;
	}
}
