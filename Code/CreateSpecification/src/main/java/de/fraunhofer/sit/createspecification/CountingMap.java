package de.fraunhofer.sit.createspecification;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;


/**
 * A map implementation with a counter as value. This map will implicitly
 * replace all <code>null</code> values with numeric zero values so that users
 * can safely perform arithmetics on the map.
 * 
 * @author Steven Arzt
 *
 * @param <E> The type of keys in the map
 */
public class CountingMap<E> implements Map<E, Integer> {

	protected final Map<E, Integer> innerMap;

	public CountingMap() {
		this.innerMap = new HashMap<>();
	}

	public List<Pair<E, Integer>> sort() {
		return entrySet().stream().map(e -> new Pair<E, Integer>(e.getKey(), e.getValue()))
				.sorted((e1, e2) -> e2.value - e1.value).collect(Collectors.toList());
	}

	public CountingMap(int initialSize) {
		this.innerMap = new HashMap<>(initialSize);
	}

	public CountingMap(Map<E, Integer> original) {
		this.innerMap = new HashMap<>(original);
	}

	@Override
	public int size() {
		return innerMap.size();
	}

	@Override
	public boolean isEmpty() {
		return innerMap.isEmpty();
	}

	@Override
	public boolean containsKey(Object key) {
		return innerMap.containsKey(key);
	}

	@Override
	public boolean containsValue(Object value) {
		return innerMap.containsValue(value);
	}

	@Override
	public Integer get(Object key) {
		Integer i = innerMap.get(key);
		return i == null ? 0 : i;
	}

	@Override
	public Integer put(E key, Integer value) {
		return innerMap.put(key, value);
	}

	@Override
	public Integer remove(Object key) {
		Integer i = innerMap.remove(key);
		return i == null ? 0 : i;
	}

	@Override
	public void putAll(Map<? extends E, ? extends Integer> m) {
		innerMap.putAll(m);
	}

	@Override
	public void clear() {
		innerMap.clear();
	}

	@Override
	public Set<E> keySet() {
		return innerMap.keySet();
	}

	@Override
	public Collection<Integer> values() {
		return innerMap.values().stream().map(i -> i == null ? 0 : i).collect(Collectors.toSet());
	}

	public class Entry implements Map.Entry<E, Integer> {

		private final Map.Entry<E, Integer> parentEntry;

		private Entry(Map.Entry<E, Integer> parentEntry) {
			this.parentEntry = parentEntry;
		}

		@Override
		public E getKey() {
			return parentEntry.getKey();
		}

		@Override
		public Integer getValue() {
			Integer i = parentEntry.getValue();
			return i == null ? 0 : i;
		}

		@Override
		public Integer setValue(Integer value) {
			Integer i = parentEntry.setValue(value);
			return i == null ? 0 : i;
		}

	}

	@Override
	public Set<Map.Entry<E, Integer>> entrySet() {
		return innerMap.entrySet().stream().map(e -> new Entry(e)).collect(Collectors.toSet());
	}

	/**
	 * Increments the value associated with the given key
	 * 
	 * @param key The key for which to increment the value
	 * @return The old value associated with the given key
	 */
	public int increment(E key) {
		return increment(key, 1);
	}

	/**
	 * Increments the value associated with the given key by the given operand
	 * 
	 * @param key The key for which to increment the value
	 * @param op  The operand by which to increment the value
	 * @return The old value associated with the given key
	 */
	public int increment(E key, int op) {
		Integer i = innerMap.get(key);
		if (i == null)
			i = 0;
		innerMap.put(key, i + op);
		return i;
	}

	/**
	 * Increments all values in this map by the given operand
	 * 
	 * @param op The value by which to increment all values in this map
	 */
	public void increment(int op) {
		for (E e : keySet())
			increment(e, op);
	}

	/**
	 * Decrements the value associated with the given key
	 * 
	 * @param key The key for which to decrement the value
	 * @return The old value associated with the given key
	 */
	public int decrement(E key) {
		return decrement(key, 1);
	}

	/**
	 * Decrements the value associated with the given key
	 * 
	 * @param key The key for which to decrement the value
	 * @param op  The operand by which to decrement the value
	 * @return The old value associated with the given key
	 */
	public int decrement(E key, int op) {
		Integer i = innerMap.get(key);
		if (i == null)
			i = 0;
		innerMap.put(key, i - op);
		return i;
	}

	/**
	 * Decrements all values in this map by the given operand
	 * 
	 * @param op The value by which to decrement all values in this map
	 */
	public void decrement(int op) {
		for (E e : keySet())
			decrement(e, op);
	}

	/**
	 * Checks whether the value associated with the given key is zero
	 * 
	 * @param key The key for which to check the value
	 * @return True if the value associated with the given key is zero, false
	 *         otherwise
	 */
	public boolean isZero(E key) {
		Integer i = innerMap.get(key);
		return i == null || i == 0;
	}

	/**
	 * Checks whether the value associated with the given key is positive
	 * 
	 * @param key The key for which to check the value
	 * @return True if the value associated with the given key is positive, false
	 *         otherwise
	 */
	public boolean isPositive(E key) {
		Integer i = innerMap.get(key);
		return i == null || i > 0;
	}

	/**
	 * Checks whether the value associated with the given key is negative
	 * 
	 * @param key The key for which to check the value
	 * @return True if the value associated with the given key is negative, false
	 *         otherwise
	 */
	public boolean isNegative(E key) {
		Integer i = innerMap.get(key);
		return i == null || i < 0;
	}

	/**
	 * Gets the contents of this counting map as a regular map from keys to integer
	 * values
	 * 
	 * @return The contents of this map as a traditional Java map
	 */
	public Map<E, Integer> asMap() {
		Map<E, Integer> map = new HashMap<>();
		for (E e : innerMap.keySet())
			map.put(e, innerMap.get(e));
		return map;
	}

	/**
	 * Adds all entries from the given source map to this map. If a key only exists
	 * in one of the maps, the respective value is assumed to be zero for the other
	 * map.
	 * 
	 * @param sourceMap The map from which to add the values
	 */
	public void addAll(CountingMap<E> sourceMap) {
		if (sourceMap != null) {
			for (E e : sourceMap.keySet()) {
				Integer i = innerMap.get(e);
				if (i == null)
					i = 0;
				innerMap.put(e, i + sourceMap.get(e));
			}
		}
	}

	/**
	 * Gets the values in this map as an ordered array
	 * 
	 * @param comparator The comparator that defines the ordering on the values
	 * @return The ordered array of values in this map
	 */
	public int[] values(Comparator<E> comparator) {
		List<E> ordered = new ArrayList<>(innerMap.keySet());
		ordered.sort(comparator);
		int[] values = new int[ordered.size()];
		for (int i = 0; i < values.length; i++)
			values[i] = get(ordered.get(i));
		return values;
	}

	/**
	 * Gets the sum over all elements in the map
	 * 
	 * @return The sum over all elements in the map
	 */
	public int sum() {
		return innerMap.values().stream().reduce(0, (a, b) -> a + b);
	}

	/**
	 * Gets the minimum value in this map
	 * 
	 * @return The minimum value in this map
	 */
	public int minValue() {
		return innerMap.values().stream().reduce(Integer.MAX_VALUE, (a, b) -> Math.min(a, b));
	}

	/**
	 * Gets the maximum value in this map
	 * 
	 * @return The maximum value in this map
	 */
	public int maxValue() {
		return innerMap.values().stream().reduce(Integer.MIN_VALUE, (a, b) -> Math.max(a, b));
	}

	/**
	 * Computes the average of all values in this map
	 * 
	 * @return The average over all values in this map
	 */
	public double avg() {
		return sum() / size();
	}

	/**
	 * Adds the given map to this one. Each value in the given map is added to this
	 * map using <code>increment()</code>.
	 * 
	 * @param otherMap The map to add
	 */
	public void add(CountingMap<E> otherMap) {
		if (otherMap != null && !otherMap.isEmpty()) {
			for (E e : otherMap.keySet())
				increment(e, otherMap.get(e));
		}
	}


	/**
	 * Prints this given map in human-readable form with one line per entry. The
	 * count is put first, followed by a tab and the string representation of the
	 * element.
	 * 
	 * @return The pretty string
	 */
	public String toPrettyString() {
		StringBuilder sb = new StringBuilder();
		for (E e : keySet()) {
			sb.append(Integer.toString(get(e)));
			sb.append('\t');
			sb.append(e);
			sb.append("\n");
		}
		return sb.toString();
	}

	/**
	 * Subtracts the given map from this one. Each value in the given map is
	 * subtracted from this map using <code>decrement()</code>.
	 * 
	 * @param otherMap The map to subtract
	 */
	public void subtract(CountingMap<E> otherMap) {
		if (otherMap != null && !otherMap.isEmpty()) {
			for (E e : otherMap.keySet())
				decrement(e, otherMap.get(e));
		}
	}

	@Override
	public String toString() {
		return innerMap.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((innerMap == null) ? 0 : innerMap.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		CountingMap<?> other = (CountingMap<?>) obj;
		if (innerMap == null) {
			if (other.innerMap != null)
				return false;
		} else if (!innerMap.equals(other.innerMap))
			return false;
		return true;
	}

}
