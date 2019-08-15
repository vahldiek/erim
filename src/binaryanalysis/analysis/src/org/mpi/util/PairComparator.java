package org.mpi.util;

import java.util.Comparator;

public class PairComparator<T extends Comparable<T>> implements Comparator<Pair<T, Long>>{

	private boolean compFirst = true;
	private int reverse = 1;
	
	public PairComparator() {
		// nothing
	}
	
	public PairComparator(boolean compFirst) {
		this.compFirst = compFirst; 
	}
	
	public PairComparator(boolean compFirst, boolean reverse) {
		this(compFirst);
		if(reverse)
			this.reverse = -1;
	}
	
	@Override
	public int compare(Pair<T, Long> o1, Pair<T, Long> o2) {
	
		if(compFirst)
			return reverse * o1.getFirst().compareTo(o2.getFirst());
		else
			return reverse * o1.getSecond().compareTo(o2.getSecond());
	}
}
