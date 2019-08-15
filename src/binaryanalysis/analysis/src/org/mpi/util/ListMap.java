package org.mpi.util;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

public class ListMap<T, E> {

	private Map<T, List<E>> container = new HashMap<T, List<E>>();

	public void add(T key, E item) {
		List<E> c = null;
		if((c = container.get(key)) == null) {
			c = new LinkedList<>();
		}
		
		c.add(item);
		container.put(key, c);
	}

	public List<E> get(T t) {
		return container.get(t);
	}

	public Vector<Pair<T, List<E>>> getAll() {
		Set<T> keys = container.keySet();
		Vector<Pair<T, List<E>>> results = new Vector<Pair<T, List<E>>>();
		int it = 0;
		for (T k : keys) {

			Pair<T, List<E>> r = new Pair<>();
			r.setFirst(k);
			r.setSecond(container.get(k));

			results.add(r);
		}

		return results;
	}

}
