package org.mpi.statistics;

import java.util.HashMap;
import java.util.Map;

public class StatisticValue {

	private String name;
	private long count;
	private double sum;
	private double sqrsum;
	private double min;
	private double max;
	private Map<Long, Long> distribution;
	private double buketMin;
	private double buketMax;
	private double buketStepping;
	private long maxStep;

	public StatisticValue(String name, double buketStepping, double buketMin,
			double buketMax) {
		this.name = name;
		this.buketMin = buketMin;
		this.buketMax = buketMax;
		this.buketStepping = buketStepping;
		this.maxStep = (long) Math.ceil((buketMax - buketMin) / buketStepping);
		distribution = new HashMap<Long, Long>(
				(int) Math.ceil((buketMax - buketMin) / buketStepping) * 2);

		this.reset();
	}

	public synchronized void addValue(double x) {
		// handle max min
		this.min = Math.min(this.min, x);
		this.max = Math.max(this.max, x);

		// add to distribution
		long index = (long) Math.floor((x - buketMin) / buketStepping);
		if (index < 0)
			index = 0;
		if (index > maxStep)
			index = maxStep;

		if (distribution.containsKey(index)) {
			distribution.put(index, distribution.get(index) + 1);
		} else {
			distribution.put(index, 1L);
		}

		// handle sums and counts
		sum += x;
		sqrsum += (x * x);
		count++;
	}

	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		double total = sum;
		double avg = total / (double) count;
		double stddev = Math.sqrt((sqrsum - 2 * avg * sum + count * avg * avg)
				/ (double) count);

		sb.append(name + ":\n");
		sb.append(name + " total sum: " + sum);
		sb.append("\n");
		sb.append(name + " total count: " + count);
		sb.append("\n");

		// only print rest, in case there is something to report --> make it a
		// small statistic
		if (sum > 0) {
			sb.append(name + " average: " + avg);
			sb.append("\n");
			sb.append(name + " std.dev.: " + stddev);
			sb.append("\n");
			sb.append(name + " min: " + min);
			sb.append("\n");
			sb.append(name + " max: " + max);
			sb.append("\n");
			sb.append(name + " distribution (" + buketMin + "," + buketMax
					+ "," + buketStepping + "):");
			sb.append("\n");

			long it;
			double acc_percent = 0.0d;
			long acc_count = 0L;
			for (it = 0; it < maxStep && acc_count < this.count; it++) {

				double buket = buketMin + ((double) it) * buketStepping;
				long count = 0;
				if (distribution.containsKey(it)) {
					count = distribution.get(it);
				}

				if (count == 0)
					continue;

				acc_count += count;
				double percent = (double) count / this.count;
				acc_percent += percent;

				sb.append(it + " " + count + " " + buket + " " + acc_count
						+ " " + percent + " " + acc_percent);
				sb.append("\n");

			}
		}

		return sb.toString();
	}

	public String toStringSimple() {
		StringBuffer sb = new StringBuffer();
		double total = sum;
		double avg = total / (double) count;
		double stddev = Math.sqrt((sqrsum - 2 * avg * sum + count * avg * avg)
				/ (double) count);

		sb.append(name + ":\n");
		sb.append(name + " total sum: " + sum);
		sb.append("\n");
		sb.append(name + " total count: " + count);
		sb.append("\n");

		// only print rest, in case there is something to report --> make it a
		// small statistic
		if (sum > 0) {
			sb.append(name + " average: " + avg);
			sb.append("\n");
			sb.append(name + " std.dev.: " + stddev);
			sb.append("\n");
			sb.append(name + " min: " + min);
			sb.append("\n");
			sb.append(name + " max: " + max);
			sb.append("\n");
		}

		return sb.toString();
	}
	
	public void reset() {
		count = 0L;
		sum = 0.0d;
		sqrsum = 0.0d;
		min = Double.MAX_VALUE;
		max = Double.MIN_VALUE;
	}

	public long getCount() {
		return count;
	}

	public double getSum() {
		return sum;
	}

	public double getSqrsum() {
		return sqrsum;
	}

	public double getMin() {
		return min;
	}

	public double getMax() {
		return max;
	}

	public double getStdDev() {
		double avg = sum / (double) count;
		double stddev = Math.sqrt((sqrsum - 2 * avg * sum + count * avg * avg)
				/ (double) count);
		return stddev;
	}

	public double getAvg() {
		double avg = sum / (double) count;
		return avg;
	}
}
