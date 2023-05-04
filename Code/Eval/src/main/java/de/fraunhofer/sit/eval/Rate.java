package de.fraunhofer.sit.eval;

import java.io.PrintWriter;
import java.math.BigDecimal;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

public class Rate<T> implements Iterable<T> {
	private List<T> counted = new ArrayList<T>();
	private int all;
	private boolean fixedAll;

	public Rate() {
		
	}
	
	public Rate(int allCount) {
		this.all = allCount;
		fixedAll = true;
	}
	
	public boolean countedEmpty() {
		return counted.isEmpty();
	}

	public void count(T i) {
		counted.add(i);
		if (!fixedAll)
			all++;
	}
	
	public void notCount() {
		if (!fixedAll)
			all++;
	}
	
	@Override
	public String toString() {

	     DecimalFormat f = new DecimalFormat("##0.00", DecimalFormatSymbols.getInstance(Locale.US));
	     return counted.size() + "/" + all + " (" + f.format(100D * counted.size() / all) + " %)";
	}

	@Override
	public Iterator<T> iterator() {
		return counted.iterator();
	}

	public void print(PrintWriter pw) {
		if (!countedEmpty()) {
			for (T i : this) {
				pw.println(i.toString());
			}
			pw.println();
		}		
	}

}
