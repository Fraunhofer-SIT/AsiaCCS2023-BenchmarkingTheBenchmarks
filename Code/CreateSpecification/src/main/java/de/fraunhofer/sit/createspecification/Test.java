package de.fraunhofer.sit.createspecification;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;

public class Test {
	
	static class ResultsPerCWE {
		Map<String, ResultsPerTestSuite> res = new HashMap<>();
	}
	
	static class ResultsPerTestSuite {
		private String name;
		public int success;
		public int all;

		ResultsPerTestSuite(String name) {
			this.name = name;
		}
	}

	public static void main(String[] args) throws Exception {
		String l = "OWASP;22;false;false;;Not exploitable by design (OWASP);135\n"
				+ "OWASP;22;true;true;Jetty=false Tomcat=false Winstone=true ;null;132\n"
				+ "OWASP;22;true;false;Tomcat=false Winstone=false ;null;1\n"
				+ "OWASP;78;false;false;;Not exploitable by design (OWASP);82\n"
				+ "OWASP;78;false;false;;Not exploitable on linux. input is passed as argument to shell script, but not evaluated.;76\n"
				+ "OWASP;78;true;true;Jetty=false Tomcat=false Winstone=true ;null;87\n"
				+ "OWASP;78;true;true;Jetty=true Tomcat=false Winstone=true ;null;6\n"
				+ "OWASP;79;false;false;;Not exploitable by design (OWASP);209\n"
				+ "OWASP;79;true;true;Jetty=false Tomcat=false Winstone=true ;null;226\n"
				+ "OWASP;79;true;true;Jetty=true Tomcat=false Winstone=true ;null;20\n"
				+ "OWASP;89;false;false;;Exploit not verifiable for batchUpdate and executeBatch. no output is available. drop table can not be injected (java.sql.BatchUpdateException: unexpected token: DROP);62\n"
				+ "OWASP;89;false;false;;Not exploitable by design (OWASP);199\n"
				+ "OWASP;89;false;false;;org.springframework.dao.IncorrectResultSizeDataAccessException. program tries to assign 4 values to one var.;1\n"
				+ "OWASP;89;false;false;;sql not exploitable;2\n" + "OWASP;89;false;false;;weak hash;1\n"
				+ "OWASP;89;false;false;;weak randomness;1\n"
				+ "OWASP;89;true;true;Jetty=false Tomcat=false Winstone=true ;null;221\n"
				+ "OWASP;89;true;true;Jetty=true Tomcat=false Winstone=true ;null;18\n"
				+ "OWASP;90;false;false;;Not exploitable by design (OWASP);32\n"
				+ "OWASP;90;true;true;Jetty=false Tomcat=false Winstone=true ;null;27\n"
				+ "OWASP;327;false;false;;Encrypts hard-coded information available in the app;246\n"
				+ "OWASP;328;false;false;;weak hash;236\n" + "OWASP;330;false;false;;weak randomness;493\n"
				+ "OWASP;501;false;false;;sets server-side session attribute: not dynamically verifiable;126\n"
				+ "OWASP;614;false;false;;insecure cookie not verifiable;67\n"
				+ "OWASP;643;false;false;;Broken testcase - Retrieved values not used at all.;35\n"
				+ "juliet;15;false;false;;Broken testcase - Nothing happens with the connection;444\n"
				+ "juliet;23;false;false;;not deterministically exploitable: uses random function;12\n"
				+ "juliet;23;true;true;MethodExec=true ;null;324\n"
				+ "juliet;23;true;true;Jetty=false Tomcat=false Winstone=true ;null;94\n"
				+ "juliet;23;true;true;Jetty=true Tomcat=false Winstone=true ;null;14\n"
				+ "juliet;36;false;false;;not deterministically exploitable: uses random function;12\n"
				+ "juliet;36;true;true;MethodExec=true ;null;324\n"
				+ "juliet;36;true;true;Jetty=false Tomcat=false Winstone=true ;null;80\n"
				+ "juliet;36;true;true;Jetty=true Tomcat=false Winstone=true ;null;28\n"
				+ "juliet;78;false;false;;not exploitable on linux;442\n"
				+ "juliet;80;false;false;;not deterministically exploitable: uses random function;18\n"
				+ "juliet;80;true;true;Jetty=true Tomcat=false Winstone=true ;null;117\n"
				+ "juliet;80;true;true;Jetty=false Tomcat=false Winstone=true ;null;531\n"
				+ "juliet;81;false;false;;not deterministically exploitable: uses random function;9\n"
				+ "juliet;81;true;true;Jetty=false Tomcat=false Winstone=true ;null;324\n"
				+ "juliet;83;false;false;;not deterministically exploitable: uses random function;9\n"
				+ "juliet;83;true;true;Jetty=false Tomcat=false Winstone=true ;null;295\n"
				+ "juliet;83;true;true;Jetty=true Tomcat=false Winstone=true ;null;29\n"
				+ "juliet;89;false;false;;insert into where is not a valid sql statement;888\n"
				+ "juliet;89;false;false;;not deterministically exploitable: uses random function;24\n"
				+ "juliet;89;true;true;MethodExec=true ;null;648\n"
				+ "juliet;89;true;true;Jetty=false Tomcat=false Winstone=true ;null;195\n"
				+ "juliet;89;true;true;Jetty=true Tomcat=false Winstone=true ;null;21\n"
				+ "juliet;90;false;false;;not deterministically exploitable: uses random function;12\n"
				+ "juliet;90;true;true;MethodExec=true ;null;324\n"
				+ "juliet;90;true;true;Jetty=false Tomcat=false Winstone=true ;null;108\n"
				+ "juliet;111;true;true;MethodExec=true ;null;1\n"
				+ "juliet;113;false;false;;not deterministically exploitable: uses random function;27\n"
				+ "juliet;113;true;true;Jetty=false Tomcat=false Winstone=true ;null;648\n"
				+ "juliet;114;false;false;;not deterministically exploitable: uses random function;1\n"
				+ "juliet;114;true;true;MethodExec=true ;null;16\n"
				+ "juliet;129;false;false;;Code quality issue;2664\n"
				+ "juliet;134;false;false;;Broken testcase - Broken due to good-method closing System.in ;666\n"
				+ "juliet;190;false;false;;Broken testcase - Not a security issue in this test case;4255\n"
				+ "juliet;191;false;false;;Broken testcase - Not a security issue in this test case;3404\n"
				+ "juliet;193;false;false;;Code quality issue - Not a security issue in Java;51\n"
				+ "juliet;197;false;false;;Broken testcase - Not a security issue in this test case;1221\n"
				+ "juliet;209;false;false;;not deterministically exploitable: uses random function;2\n"
				+ "juliet;209;true;true;Jetty=true Tomcat=true Winstone=true ;null;16\n"
				+ "juliet;209;true;true;MethodExec=true ;null;16\n"
				+ "juliet;226;false;false;;Broken testcase - Both the fixed and unfixed version store the password in Strings, which cannot be cleared.;17\n"
				+ "juliet;248;false;false;;Code quality issue;1\n" + "juliet;252;false;false;;Code quality issue;17\n"
				+ "juliet;253;false;false;;Code quality issue;17\n"
				+ "juliet;256;false;false;;Broken testcase - The fix for using a plain text password is decrypting using a hard-coded password according to the test cases.;37\n"
				+ "juliet;259;false;false;;hard coded password not dynamically verifiable;111\n"
				+ "juliet;315;false;false;;not deterministically exploitable: uses random function;1\n"
				+ "juliet;315;true;true;Jetty=false Tomcat=false Winstone=true ;null;32\n"
				+ "juliet;315;true;true;Jetty=true Tomcat=false Winstone=true ;null;4\n"
				+ "juliet;319;false;false;;not deterministically exploitable: uses random function;4\n"
				+ "juliet;319;true;true;MethodExec=true ;null;144\n"
				+ "juliet;321;false;false;;Broken testcase - The attacker can choose the password in the fix and thus decrypt the hard-coded secret;37\n"
				+ "juliet;325;false;false;;Code quality issue;34\n"
				+ "juliet;327;false;false;;Encrypts hard-coded information available in the app;34\n"
				+ "juliet;328;false;false;;Broken testcase - Using an insecure hash function to hash a non-sensitive hardcoded string;51\n"
				+ "juliet;329;false;false;;Broken testcase - The IV is constant, but a fresh key is generated, thus an attacker does not gain any information regardless of IV.;17\n"
				+ "juliet;336;false;false;;Broken testcase - setSeed JavaDoc: 'The given seed supplements, rather than replaces, the existing seed. Thus, repeated calls are guaranteed never to reduce randomness.';17\n"
				+ "juliet;338;false;false;;Broken testcase - PRNG not used in security context;34\n"
				+ "juliet;369;false;false;;Code quality issue;1850\n"
				+ "juliet;382;false;false;;not deterministically exploitable: uses random function;2\n"
				+ "juliet;382;true;true;Jetty=false Tomcat=false Winstone=true ;null;32\n"
				+ "juliet;383;false;false;;Code quality issue;16\n" + "juliet;390;false;false;;Code quality issue;34\n"
				+ "juliet;395;false;false;;Code quality issue;17\n" + "juliet;396;false;false;;Code quality issue;34\n"
				+ "juliet;397;false;false;;Code quality issue;4\n"
				+ "juliet;398;false;false;;Code quality issue & Source code only;137\n"
				+ "juliet;400;false;false;;not deterministically exploitable: uses random function;37\n"
				+ "juliet;400;true;true;MethodExec=true ;null;1080\n"
				+ "juliet;400;true;true;Jetty=true Tomcat=true Winstone=true ;null;123\n"
				+ "juliet;400;true;true;Jetty=false Tomcat=false Winstone=true ;null;89\n"
				+ "juliet;400;true;true;Jetty=true Tomcat=false Winstone=true ;null;20\n"
				+ "juliet;404;false;false;;Code quality issue;5\n" + "juliet;459;false;false;;Code quality issue;34\n"
				+ "juliet;470;false;false;;not deterministically exploitable: uses random function;12\n"
				+ "juliet;470;true;true;MethodExec=true ;null;324\n"
				+ "juliet;470;true;true;Jetty=false Tomcat=false Winstone=true ;null;90\n"
				+ "juliet;470;true;true;Jetty=true Tomcat=false Winstone=true ;null;18\n"
				+ "juliet;476;false;false;;Code quality issue;198\n" + "juliet;477;false;false;;Code quality issue;68\n"
				+ "juliet;478;false;false;;Code quality issue;17\n" + "juliet;481;false;false;;Code quality issue;17\n"
				+ "juliet;482;false;false;;Code quality issue;17\n"
				+ "juliet;483;false;false;;Code quality issue & Source code only;19\n"
				+ "juliet;484;false;false;;Code quality issue;17\n"
				+ "juliet;486;false;false;;Broken testcase - The attacker cannot change anything besides running the code, which does not lead to a security incident;17\n"
				+ "juliet;491;false;false;;Broken testcase - CWE is not exploitable;2\n"
				+ "juliet;499;false;false;;Broken testcase - Serializable class is never instantiated/used;2\n"
				+ "juliet;500;false;false;;Code quality issue;2\n"
				+ "juliet;506;false;false;;The behavior of good and bad is identical, thus, no real attack can be performed.;116\n"
				+ "juliet;510;false;false;;not deterministically exploitable: uses random function;2\n"
				+ "juliet;510;true;true;MethodExec=true ;null;32\n"
				+ "juliet;511;false;false;;not deterministically exploitable: uses random function;2\n"
				+ "juliet;511;true;true;MethodExec=true ;null;32\n"
				+ "juliet;523;false;false;;not deterministically exploitable: uses random function;1\n"
				+ "juliet;523;true;true;Jetty=false Tomcat=false Winstone=true ;null;13\n"
				+ "juliet;523;true;true;Jetty=true Tomcat=false Winstone=true ;null;3\n"
				+ "juliet;526;false;false;;not deterministically exploitable: uses random function;2\n"
				+ "juliet;526;true;true;Jetty=true Tomcat=false Winstone=true ;null;1\n"
				+ "juliet;526;true;true;Jetty=false Tomcat=false Winstone=true ;null;15\n"
				+ "juliet;526;true;true;MethodExec=true ;null;16\n"
				+ "juliet;533;false;false;;CWE is deprecated and thus these test cases were omitted.;17\n"
				+ "juliet;534;false;false;;CWE is deprecated and thus these test cases were omitted.;17\n"
				+ "juliet;535;false;false;;Broken testcase - The tests are the same as CWE-534, albeit under the name of CWE-535. This might be due to a copy and paste error in the test generation script.;17\n"
				+ "juliet;539;false;false;;Currently unsupported - Needs support for current time handling and arithmetic/logic expressions (future work).;17\n"
				+ "juliet;546;false;false;;Code quality issue & Source code only;85\n"
				+ "juliet;549;false;false;;not deterministically exploitable: uses random function;1\n"
				+ "juliet;549;true;true;Jetty=false Tomcat=false Winstone=true ;null;14\n"
				+ "juliet;549;true;true;Jetty=true Tomcat=false Winstone=true ;null;2\n"
				+ "juliet;561;false;false;;Code quality issue;2\n" + "juliet;563;false;false;;Code quality issue;222\n"
				+ "juliet;566;false;false;;Broken testcase - The query based on the id supplied by the attacker does not have any influence on the output.;37\n"
				+ "juliet;568;false;false;;Code quality issue;4\n" + "juliet;570;false;false;;Code quality issue;16\n"
				+ "juliet;571;false;false;;Code quality issue;16\n" + "juliet;572;false;false;;Code quality issue;17\n"
				+ "juliet;579;false;false;;Code quality issue;1\n" + "juliet;580;false;false;;Code quality issue;2\n"
				+ "juliet;581;false;false;;Code quality issue;4\n" + "juliet;582;false;false;;Code quality issue;2\n"
				+ "juliet;584;false;false;;Code quality issue;17\n" + "juliet;585;false;false;;Code quality issue;2\n"
				+ "juliet;586;false;false;;Code quality issue;17\n" + "juliet;597;false;false;;Code quality issue;17\n"
				+ "juliet;598;false;false;;not deterministically exploitable: uses random function;1\n"
				+ "juliet;598;true;true;Jetty=false Tomcat=false Winstone=true ;null;12\n"
				+ "juliet;598;true;true;Jetty=true Tomcat=false Winstone=true ;null;4\n"
				+ "juliet;600;true;false;Jetty=false Tomcat=false Winstone=false ;null;1\n"
				+ "juliet;601;false;false;;not deterministically exploitable: uses random function;9\n"
				+ "juliet;601;true;true;Jetty=false Tomcat=false Winstone=true ;null;285\n"
				+ "juliet;601;true;true;Jetty=true Tomcat=false Winstone=true ;null;39\n"
				+ "juliet;605;false;false;;Broken testcase - setReuseAddress not called/listening on the same application twice does not make sense;17\n"
				+ "juliet;606;false;false;;not deterministically exploitable: uses random function;12\n"
				+ "juliet;606;true;true;MethodExec=true ;null;324\n"
				+ "juliet;606;true;true;Jetty=true Tomcat=true Winstone=true ;null;108\n"
				+ "juliet;607;false;false;;Code quality issue;2\n" + "juliet;609;false;false;;Code quality issue;2\n"
				+ "juliet;613;false;false;;Currently unsupported - Needs support for current time handling and arithmetic/logic expressions (future work).;17\n"
				+ "juliet;614;false;false;;not deterministically exploitable: uses random function;1\n"
				+ "juliet;614;true;false;Jetty=false Tomcat=false Winstone=false ;null;16\n"
				+ "juliet;615;false;false;;Source code only;17\n" + "juliet;617;false;false;;Code quality issue;34\n"
				+ "juliet;643;false;false;;Broken testcase - Retrieved values not used at all.;444\n"
				+ "juliet;667;false;false;;Code quality issue;1\n" + "juliet;674;true;true;MethodExec=true ;null;2\n"
				+ "juliet;681;false;false;;Code quality issue;51\n" + "juliet;690;false;false;;Code quality issue;296\n"
				+ "juliet;698;false;false;;Broken testcase - Logging a constant string value after redirect statements is neither a flaw nor undefined. The intent of the CWE is different.;17\n"
				+ "juliet;759;false;false;;Broken testcase - Using a hash function to hash a non-sensitive hardcoded string;17\n"
				+ "juliet;760;false;false;;Broken testcase - Using a hash function to hash a non-sensitive hardcoded string;17\n"
				+ "juliet;764;false;false;;Code quality issue;2\n" + "juliet;765;false;false;;Code quality issue;2\n"
				+ "juliet;772;false;false;;Code quality issue;2\n" + "juliet;775;false;false;;Code quality issue;2\n"
				+ "juliet;789;false;false;;not deterministically exploitable: uses random function;14\n"
				+ "juliet;789;true;true;MethodExec=true ;null;376\n"
				+ "juliet;789;true;true;Jetty=true Tomcat=true Winstone=true ;null;108\n"
				+ "juliet;832;false;false;;Code quality issue;2\n" + "juliet;833;true;true;MethodExec=true ;null;3\n"
				+ "juliet;835;true;true;MethodExec=true ;null;6\n";

		BufferedReader bf = new BufferedReader(new FileReader("/home/miltenbe/Downloads/fulltable.csv"));
		int c = 0;
		int co  = 0;
		Set<String> ids = new HashSet<>();
		
		Set<String> set = new HashSet<>();
		Map<Integer, ResultsPerCWE> cwemap = new TreeMap<Integer, ResultsPerCWE>();
		while (true) {
			String s = bf.readLine();
			if (s == null)
				break;
			String[] spl = s.split(";");
			String reason = spl[spl.length - 2];
			if (!ids.add(spl[spl.length - 1]))
				System.out.println();
			boolean isVuln = spl[3].equals("true");
			if (!isVuln)
				continue;

			boolean ours = spl[4].equals("true");
			if (isVuln != ours) {
				
				System.out.println();
			}
			
			int cwenum = Integer.parseInt(spl[1]);
			ResultsPerCWE cc = cwemap.get(cwenum);
			if (cc == null) {
				cc = new ResultsPerCWE();
				cwemap.put(cwenum, cc);
			}
			if (cwenum == 89 && spl[0].equals("juliet")) {
				set.add(spl[spl.length - 1]);
			}
			
			ResultsPerTestSuite testsuite = cc.res.get(spl[0]);
			if (testsuite == null) {
				testsuite = new ResultsPerTestSuite(spl[0]);
				cc.res.put(spl[0], testsuite); 
			}
			
			if (ours)
				testsuite.success++;
			testsuite.all++;
			
			
			
			if (true)
			continue;
			int count = Integer.parseInt(spl[spl.length - 1]);
			if (spl[0].equals("juliet") && spl[2].equals("false") && spl[3].equals("false") && !reason.isBlank()) {
				doCount(spl, reason, count);
				c += count;
			}
			if (spl[0].equals("juliet") && spl[2].equals("false") && spl[3].equals("false")) {
				c += count;
			}
		}
		System.out.println("Should be 26318 = " + (co + 649 + 6856 )  );
		System.out.println(c);
		System.out.println(excluded);
		System.out.println(unverified);
		System.out.println(notExploitable);
		CountingMap<Integer> maxCWEs = new CountingMap<>();
		String s = "";
		int ja = 0, owaspa = 0; 
		for (Entry<Integer, ResultsPerCWE> ls : cwemap.entrySet() ) {
			ResultsPerTestSuite juliet = ls.getValue().res.get("juliet");
			ResultsPerTestSuite owasp = ls.getValue().res.get("OWASP");
			if (juliet != null) {
				ja += juliet.all;
				if (juliet.all == 1)
					System.out.println(ls.getKey());
				maxCWEs.increment(ls.getKey(), juliet.all);
			}
			if (owasp != null)
				owaspa += owasp.all;
			String kk = ls.getKey() + " & " + getRes(juliet) + " & " + getRes(owasp);
			System.out.println(kk);
			s += kk + "\n";
		}
		for (Pair<Integer, Integer> x : maxCWEs.sort()) {
			System.out.println(x);
		}
		System.out.println("Juliet all " + ja + ", owasp all " + owaspa);
		}
		private static String getRes(ResultsPerTestSuite t) {
			if (t == null)
				return "- ";
			return t.success + " (" + t.all + ")";
		}
	static int excluded = 0;
	static int unverified = 0;
	static int notExploitable = 0;
	
	static class ExcludeInfo {
		String benchmarkSuite = "";
		public String cwe;
		private int affectedExcluded;
		private int totalOfCWEInSuite;
	}

	private static void doCount(String[] i, String s, int count) {
		ExcludeInfo ex = new ExcludeInfo();
		ex.benchmarkSuite = i[0];
		ex.cwe = i[1];

		switch (s) {
		case "Code quality issue":

		case "Currently unsupported - Needs support for current time handling and arithmetic/logic expressions (future work).":

		case "Code quality issue & Source code only":
		case "Source code only":
		case "not deterministically exploitable: uses random function":
		case "Encrypts hard-coded information available in the app":

		case "The behavior of good and bad is identical, thus, no real attack can be performed.":

		case "hard coded password not dynamically verifiable":

		case "CWE is deprecated and thus these test cases were omitted.":

		case "Code quality issue - Not a security issue in Java":

		case "weak hash":

		case "weak randomness":

			excluded += count; 

			break;

		case "not exploited: environment is http-only":

			unverified += count;

			break;

		default:

			System.out.println(s);
			notExploitable += count;
			break;

		}
	}

}
