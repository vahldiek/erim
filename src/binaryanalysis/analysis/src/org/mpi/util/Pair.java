package org.mpi.util;

public class Pair<T, E> {

	private T t = null;
	private E e = null;
	
	public Pair() {
		
	}

	public T getFirst() {
		return t;
	}

	public void setFirst(T t) {
		this.t = t;
	}

	public E getSecond() {
		return e;
	}

	public void setSecond(E e) {
		this.e = e;
	}
}
