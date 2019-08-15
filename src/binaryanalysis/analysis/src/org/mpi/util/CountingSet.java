package org.mpi.util;

import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Vector;

import org.mpi.erim.AnalyzedWRPKRU;
import org.mpi.util.Pair;

public class CountingSet<T> {
 
	Map<T, Long> counts = new HashMap<>();
	
	public CountingSet(Comparator<AnalyzedWRPKRU> comp) {
		counts = (Map<T, Long>) new TreeMap<AnalyzedWRPKRU, Long>(comp);
	}
	
	public CountingSet() {
	}
	
	public void add(T key) {
		long c = 0;
		if (counts.containsKey(key)) {
			c = counts.get(key);
		}
		counts.put(key, c + 1);
	}

	public long get(T key) {

		Long c = counts.get(key);

		return (c != null) ? c : 0;
	}

	public Vector<Pair<T, Long>> getAll() {
		Set<T> keys = counts.keySet();
		Vector<Pair<T, Long>> results = new Vector<Pair<T, Long>>();
		int it = 0;
		for(T k : keys) {
			
			Pair<T, Long> r = new Pair<>();
			r.setFirst(k);
			r.setSecond(counts.get(k));
			
			results.add(r);
		}
		
		return results;
	}
}
