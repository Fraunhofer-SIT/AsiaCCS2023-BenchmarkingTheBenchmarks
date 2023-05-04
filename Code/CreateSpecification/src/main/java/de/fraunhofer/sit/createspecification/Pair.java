package de.fraunhofer.sit.createspecification;

public class Pair<T1, T2> {

	public T1 key;
	public Integer value;

	public Pair(T1 key, Integer value) {
		this.key = key;
		this.value = value;
	}
	
	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return key + "=" + value;
	}

}
