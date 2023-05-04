package de.fraunhofer.sit.eval;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import de.fraunhofer.sit.createexploits.CreateExploitsApp;
import de.fraunhofer.sit.specifications.attackpatterns.AttackPattern;
import de.fraunhofer.sit.specifications.attackpatterns.AttackPatternPreset;
import de.fraunhofer.sit.specifications.attackpatterns.Presets;
import de.fraunhofer.sit.specifications.executionprofile.ExecutionProfile;
import de.fraunhofer.sit.specifications.executionprofile.testsuite.Testsuite;
import de.fraunhofer.sit.specifications.testcases.TestCase;
import de.fraunhofer.sit.specifications.util.ParseModels;

public class EvalApp {
	
	static List<TestResult> results = new ArrayList<>();
	private static File outputDir;
	private static boolean strict;

	public static void main(String[] args) throws Exception {

		File outputDir = new File(args[0]);
		File inputLogDir = new File(args[1]);
		File inputContainerDir = new File(args[2]);
		for (int i = 3; i < args.length; i++) {
			switch (args[i].toLowerCase()) {
			case "--strict":
				// Fail if anything goes wrong
				strict = true;
				break;
			}
		}

		EvalApp.outputDir = outputDir;

		System.out.println("Evaluation started on " + new Date());
		File[] logs = inputLogDir.listFiles();
		File[] containers = inputContainerDir.listFiles();
		if (logs.length != containers.length) {
			System.err.println(String.format("Warning: Different number of files. Has %d log and %d container files",
					logs.length, containers.length));
			System.err.println("Logs:");
			System.err.println(Arrays.toString(logs));
			System.err.println("Containers:");
			System.err.println(Arrays.toString(containers));
		}

		readIn(inputContainerDir, logs);
		System.out.println("Evaluation ended on " + new Date());
	}

	private static void readIn(File inputContainerDir, File[] logs)
			throws IOException, FileNotFoundException, SAXException, ParserConfigurationException {
		Presets ppresets = ParseModels.loadPresets();
		System.out.println("About to read in " + logs.length + " files");
		List<TestCase> tc = ParseModels.parseTestCases();
		Map<String, TestCaseInfo> testCase = new HashMap<>();
		
		for (TestCase i : tc) {
			try {
				if (i.exploitable) {
					AttackPattern attackPattern = ppresets.getPattern(i.attackPatternId);
					
					for (AttackPatternPreset attack : attackPattern.presets) {
						for (ExecutionProfile executionProfile : i.executionProfileProvider.getExecutionProfileVariants(i)) {
							String s = i.testsuite.getName() + "_" + i.key+ ";" + attack.id + ";" + executionProfile.getName() ;
							TestCaseInfo info = new TestCaseInfo(i, attack);
							testCase.put(s, info);
						}
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		Map<String, TestResult> testCaseAggregation = new HashMap<>();

		Map<Testsuite, Aggregation> aggregationPerTestSuite = new HashMap<>();
		Aggregation all = new Aggregation();
		
		for (File log : logs) { 
			File container = new File(inputContainerDir, log.getName());
			if (!container.exists()) {
				hasError(new RuntimeException("Container " + container.getAbsolutePath() + " does not exist"));
				continue;
			}
			File finfo = new File(container, "information");
			if (!finfo.exists()) {
				hasError(new RuntimeException("Container " + container.getAbsolutePath() + " does exist, but has NO INFORMATION FILE (information)"));
				continue;
			}

			Properties info = new Properties();
			try (FileInputStream fs = new FileInputStream(finfo)) {
				info.load(fs);
			}

			SingleTestResult testResult;
			try {
				testResult = new SingleTestResult(info, log);
			} catch (Exception e) {
				hasError(e);
				continue;
			}
			String k = testResult.getTestSuiteString() + "_" + testResult.getKey();
			String id = k + ";" + testResult.getAttackPreset() + ";" + testResult.getExecutionProfile();
			TestCaseInfo t = testCase.get(id);
			if (t == null) {
				throw new RuntimeException("No testcase with key " + id + " found");
			}
			testResult.setTestCase(t);
			TestResult r = testCaseAggregation.computeIfAbsent(k, (x) -> new TestResult());
			r.add(testResult);
			
		}
		Map<String, TestResult> testcaseToTestResult = new HashMap<>();
		for (TestResult testResult : testCaseAggregation.values()) {
			Testsuite testSuite = testResult.getTestSuite();
			results.add(testResult);
			testcaseToTestResult.put(testResult.getKey(), testResult);
			all.aggregate(testResult);
			Aggregation s = aggregationPerTestSuite.computeIfAbsent(testSuite, (x) -> new Aggregation());
			s.aggregate(testResult);
		}

		System.out.println("############################");
		System.out.println("## Results per test suite ##");
		System.out.println("############################");
		all.eval();
		for (Entry<Testsuite, Aggregation> i : aggregationPerTestSuite.entrySet()) {
			i.getValue().eval();
			System.out.println();
			System.out.println(i.getKey());
			System.out.println(i.getValue());
		}
		System.out.println();
		System.out.println("############################");
		System.out.println("## Results                ##");
		System.out.println("############################");
		System.out.println(all.toString(true));

		write("TruePositive.txt", all.tpr);
		write("TrueNegative.txt", all.tnr);
		write("FalsePositive.txt", all.fpr);
		write("FalseNegative.txt", all.fnr);
		
		
		System.out.println();
		System.out.println("############################");
		System.out.println("## Results by CWE         ##");
		System.out.println("############################");
		for (Entry<Testsuite, Aggregation> i : aggregationPerTestSuite.entrySet()) {
			i.getValue().eval();
			System.out.println();
			System.out.println(i.getKey());
			System.out.println(i.getValue());
		}
		
		HashMap<EvalTableEntry, List<String>> table = new HashMap<>();
		HashSet<String> filter = null;
		if (CreateExploitsApp.filterList != null) {
			filter = new HashSet<String>(Arrays.asList(CreateExploitsApp.filterList));
		}
		
		// testsuite;cwe;exploitExpected;exploitDetected;exploitableWithExecutionProfiles;notExploitableReason
		for (TestCase testcase : tc) {
			if (filter != null) {
				if (!filter.contains(testcase.key)) {
					continue;
				}
			}
			if (!testcase.exploitable) {
				table.computeIfAbsent(new EvalTableEntry(testcase.testsuite.getName(), testcase.cwe, 0,false, false, -1, null, testcase.reasonNotExploitable),(x) -> new ArrayList<String>()).add(testcase.key);
			} else {
				TestResult result = testcaseToTestResult.get(testcase.key);
				AttackPattern attackPattern = ppresets.getPattern(testcase.attackPatternId);
				if (result == null) {
					table.computeIfAbsent(new EvalTableEntry(testcase.testsuite.getName(), testcase.cwe, attackPattern.presets.size(), true, false, -1, new HashMap<>(), null), (x) -> new ArrayList<String>()).add(testcase.key);
				} else {
					table.computeIfAbsent(new EvalTableEntry(testcase.testsuite.getName(), testcase.cwe, attackPattern.presets.size(), true, result.exploitDetected(), result.getFailedCaseCount(), result.getExploitDetectedForExecutionProfile(), null), (x) -> new ArrayList<String>()).add(testcase.key);
				}
			}
		}
		List<EvalTableEntry> tableKeys = new ArrayList<>();
		tableKeys.addAll(table.keySet());
		Collections.sort(tableKeys);
		System.out.println("testsuite, cwe, attackPatternCount, exploitExpected, exploitDetected,failedCaseCount, executionProfileResults");
		File tableFile = new File(outputDir, "results.csv");
		try (FileWriter pw = new FileWriter(tableFile)) {
			for (EvalTableEntry key : tableKeys) {
				String rowStr = key.toString();
				List<String> testcases = table.get(key);
				System.out.println(rowStr + ";" + testcases.size());
				for (String testcase : testcases) {
					pw.write(rowStr + ";" + testcase + "\n");
				}
			}
		}
		
		
		System.out.println("Results also written to " + outputDir.getCanonicalPath());
	}

	private static void hasError(Exception runtimeException) {
		runtimeException.printStackTrace();
		if (strict)
			System.exit(1);
	}

	private static void write(String name, Rate<?> rate) throws FileNotFoundException {
		File f = new File(outputDir, name);
		try (PrintWriter pw = new PrintWriter(new FileOutputStream(f))) {
			rate.print(pw);
		}

	}

}
