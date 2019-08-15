package org.mpi.erim;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Arrays;
import org.mpi.statistics.StatisticValue;
import org.mpi.util.CountingSet;
import org.mpi.util.ListMap;
import org.mpi.util.Pair;
import org.mpi.util.PairComparator;

import com.thoughtworks.xstream.XStream;

public class AnalyzeBinaryAnalysis {

	private File inputFile;

	private List<AnalyzedBinaryObject> objectSet = new LinkedList<>();
	private List<AnalyzedWRPKRU> wrpkruSet = new LinkedList<>();

	public AnalyzeBinaryAnalysis(File inputFile) {
		this.inputFile = inputFile;
	}

	private void extract() {
		int lineCnt = 0;
		try {
			BufferedReader br = new BufferedReader(new FileReader(inputFile));
			String line = null;
			AnalyzedBinaryObject abo = null;
			while ((line = br.readLine()) != null) {
				lineCnt++;

				if (line.equals(""))
					continue;

				if (line.startsWith("IO:") || line.startsWith("nohup")) {
					continue;
				}

				if (line.startsWith("wrpkru")) {
					// add to existing binary object
					if (abo != null) {
						AnalyzedWRPKRU wrpkru = new AnalyzedWRPKRU(line, abo);
						abo.addWRPKRU(wrpkru);
						wrpkruSet.add(wrpkru);
					}
				} else {
					// new AnalyzedBinaryObject
					abo = new AnalyzedBinaryObject(line);
					objectSet.add(abo);
				}

			}
		} catch (IOException e) {
			System.err.println("Err in line " + lineCnt);
			e.printStackTrace();
		}
	}

	private void extract_from_xml() {
		XStream xstream = new XStream();
		xstream.alias("AnalyzedBinaryObject", AnalyzedBinaryObject.class);
		xstream.alias("AnalyzedWRPKRU", AnalyzedWRPKRU.class);

		int lineCnt = 0;
		try {
			BufferedReader br = new BufferedReader(new FileReader(inputFile));
			String line = null;
			while ((line = br.readLine()) != null) {
				lineCnt++;

				if (line.startsWith("<AnalyzedBinaryObject>")) {
					StringBuffer sb = new StringBuffer();
					sb.append(line + "\n");
					while ((line = br.readLine()) != null) {
						sb.append(line + "\n");
						lineCnt++;
						if (line.equals("</AnalyzedBinaryObject>"))
							break;
					}
					AnalyzedBinaryObject abo = (AnalyzedBinaryObject) xstream
							.fromXML(sb.toString());

					objectSet.add(abo);
				}

			}
		} catch (Exception e) {
			System.err.println("Err in line " + lineCnt);
			e.printStackTrace();
		}

		for (AnalyzedBinaryObject abo : objectSet) {
			for (AnalyzedWRPKRU wrpkru : abo.getWrpkruSet())
				wrpkruSet.add(wrpkru);
		}

	}

	private void analyze() {
		// calculate binary statistics
		StatisticValue segments = new StatisticValue("Inspected Segments", 1.0,
				0.0, 10.0);
		StatisticValue executableBytes = new StatisticValue(
				"Inspected executable bytes", 1024 * 32, 0.0,
				1024 * 1024 * 1024);
		StatisticValue numwrpkru = new StatisticValue("Num WRPKRUs per object",
				1.0, 0.0, 100.0);
		int countObjects = 0, loadFailed = 0, noPhdr = 0;
		LinkedList<AnalyzedBinaryObject> hasWRPKRU = new LinkedList<>();
		List<String> objNames = new LinkedList<>();
		for (AnalyzedBinaryObject abo : objectSet) {
			countObjects++;
			if (abo.isLoadFailed()) {
				loadFailed++;
			} else if (abo.isNoPhdr()) {
				noPhdr++;
			} else {
				segments.addValue(abo.getNumSegments());
				executableBytes.addValue(abo.getExecutableBytes());
				numwrpkru.addValue(abo.getNumWRPKRU());
				if (abo.getNumWRPKRU() > 0) {
					objNames.add(abo.getFilename());
					hasWRPKRU.add(abo);
				}
			}
		}

		System.out.println("Inspected Objects: " + countObjects
				+ "\nFailed to load: " + loadFailed + "\nNo Phdr found: "
				+ noPhdr + "\nObjects successfully inspected: "
				+ (countObjects - loadFailed - noPhdr));
		System.out.println("Objects with WRPRU: " + hasWRPKRU.size());
		System.out.println(segments);
		System.out.println(executableBytes.toStringSimple());
		System.out.println(numwrpkru);

		LinkedList<AnalyzedWRPKRU> notExecutableSection = new LinkedList<>();
		LinkedList<AnalyzedWRPKRU> notExecutableSectionNextInsnFailed = new LinkedList<>();
		LinkedList<AnalyzedWRPKRU> executableSpans = new LinkedList<>();
		LinkedList<AnalyzedWRPKRU> executableSingle = new LinkedList<>();
		LinkedList<AnalyzedWRPKRU> executableDisasFailed = new LinkedList<>();
		LinkedList<AnalyzedWRPKRU> spanBlockInCfg = new LinkedList<>();
		LinkedList<AnalyzedWRPKRU> singleInsnBlockInCfg = new LinkedList<>();
		CountingSet<String> wrpkruBySecName = new CountingSet<>();
		CountingSet<String> wrpkruByInstruction = new CountingSet<>();
		CountingSet<Integer> wrpkruByOperandType = new CountingSet<>();
		ListMap<List<String>, AnalyzedWRPKRU> wrpkruLists = new ListMap<>();
		long fullseqoperand = 0;

		for (AnalyzedWRPKRU wrpkru : wrpkruSet) {

			wrpkruBySecName.add(wrpkru.getSectionName());

			if (wrpkru.isExecutableSection()) {
				
				if (wrpkru.isInsnDisasFailed()) {
					executableDisasFailed.add(wrpkru);
				} else if (wrpkru.spansMultipleInstructions()) {
				    if (wrpkru.isBlockInCfg())
					spanBlockInCfg.add(wrpkru);
				    
				    wrpkruLists.add(wrpkru.getInsns(), wrpkru);
				    wrpkruByInstruction.add(wrpkru.getInsns().toString());
				    executableSpans.add(wrpkru);
				} else {
				    if (wrpkru.isBlockInCfg())
					singleInsnBlockInCfg.add(wrpkru);
				    
				    wrpkruByOperandType.add(wrpkru.getOperandType());
				    fullseqoperand += (wrpkru.isFullSeqOperand()) ? 1 : 0;
				    wrpkruLists.add(wrpkru.getInsns(), wrpkru);
				    wrpkruByInstruction.add(wrpkru.getInsns().toString());
				    executableSingle.add(wrpkru);
				}
				
			} else {
				if (wrpkru.isDisasFailed()) {
					notExecutableSectionNextInsnFailed.add(wrpkru);
				}
				notExecutableSection.add(wrpkru);
			}
		}

		System.out.println("Total WRPKRUs found: " + wrpkruSet.size());
		System.out.println("WRPKRU by section: (<section name> <count>)");

		List<Pair<String, Long>> bySection = wrpkruBySecName.getAll();
		Collections.sort(bySection, new PairComparator<String>(false, true));
		for (Pair<String, Long> secName : bySection) {
			if(secName.getFirst() != null && secName.getSecond() != null) {
				System.out.println(secName.getFirst().replaceFirst(".", "") + "\t"
					+ secName.getSecond());
			}
		}
		System.out
				.println("WRPKRU in executable text section: "
						+ (executableSpans.size() + executableSingle.size() + executableDisasFailed
								.size()));
		System.out.println("WRPKRU spans multiple instructions: "
				+ executableSpans.size());
		System.out.println("WRPKRU in single instruction: "
				+ executableSingle.size());
		System.out.println("WRPKRU executable, but disas failed: "
				+ executableDisasFailed.size());
		System.out.println("WRPKRU spanning rewriteable (in cfg): " + spanBlockInCfg.size());
		System.out.println("WRPKRU single insn rewriteable (in cfg): " + singleInsnBlockInCfg.size());
		System.out.println("WRPKRU in not executable section: "
				+ notExecutableSection.size());
		System.out.println("WRPKRU ines + next insn disas failed: "
				+ notExecutableSectionNextInsnFailed.size());
		System.out
				.println("WRPKRU ines + next instruction valid: "
						+ (notExecutableSectionNextInsnFailed.size() - notExecutableSection
								.size()));

		long rule5sum = 0;
		long rule5incfg = 0;
		long rule46sum = 0;
		long rule46incfg = 0;
		StringBuffer sb5 = new StringBuffer();
		StringBuffer sb46 = new StringBuffer();
		for (AnalyzedWRPKRU w : executableSingle) {
		    if(w.getInsns().toString().contains("RIP")) {
			// rule 5
			rule5sum++;
			if(w.isBlockInCfg())
			    rule5incfg++;
			sb5.append(w.getInsns().toString());
			sb5.append(" " + w.isBlockInCfg());
			sb5.append("\n");
		    } else {
			// rule 4/6
			rule46sum++;
			if(w.isBlockInCfg())
			    rule46incfg++;
			sb46.append(w.getInsns().toString());
			sb46.append(" " + w.isBlockInCfg());
			sb46.append("\n");
		    }
		}
		System.out.println("Num rule 5: " + rule5sum);
		System.out.println("In Cfg: " + rule5incfg);
		System.out.println("Num rule 4/6: " + rule46sum);
		System.out.println("In Cfg: " + rule46incfg);
		System.out.println("Rule 5 Insns:\n" + sb5.toString() + "Rule 4/6 Insns:\n" + sb46.toString());

		System.out
				.println("\nNum of same instruction sequence (<instruction> <count>)");
		List<Pair<String, Long>> bySecName = wrpkruByInstruction.getAll();
		Collections.sort(bySecName, new PairComparator<String>(false, true));
		for (Pair<String, Long> secName : bySecName) {
			System.out.println(secName.getFirst() + "\t" + secName.getSecond());
		}

		System.out.println("\nWRPKRU full seq in operand: " + fullseqoperand);
		System.out.println("WRPKRU by operand type");
		for (Pair<Integer, Long> secName : wrpkruByOperandType.getAll()) {
			System.out.println(secName.getFirst() + "\t" + secName.getSecond());
		}

		System.out.println("\nMap instruction sequence to binary");
		List<Pair<List<String>, List<AnalyzedWRPKRU>>> pkruLists = wrpkruLists
				.getAll();
		Collections.sort(pkruLists,
				new Comparator<Pair<List<String>, List<AnalyzedWRPKRU>>>() {
					@Override
					public int compare(
							Pair<List<String>, List<AnalyzedWRPKRU>> o1,
							Pair<List<String>, List<AnalyzedWRPKRU>> o2) {

						return -Integer.compare(o1.getSecond().size(), o2
								.getSecond().size());
					}
				});
		for (Pair<List<String>, List<AnalyzedWRPKRU>> insns : pkruLists) {
			System.out.println(Arrays.toString(insns.getFirst().toArray())
					+ ": in total " + insns.getSecond().size());
			CountingSet<String> cs = new CountingSet<>();
			for (AnalyzedWRPKRU w : insns.getSecond()) {
				cs.add(w.getAbo().getFilename());
			}
			for (Pair<String, Long> e : cs.getAll()) {
				System.out.println(e.getFirst() + "(" + e.getSecond() + ")");
			}

		}

		System.out.println("\nFull list of rewriteable PKRU:");
		for (AnalyzedWRPKRU w : spanBlockInCfg) {
			System.out.println(w.getAbo().getFilename() + " " + w.getOffset()
					+ " " + w.getInsns().toString());
		}
		for (AnalyzedWRPKRU w : singleInsnBlockInCfg) {
		    System.out.println(w.getAbo().getFilename() + " " + w.getOffset()
				       + " " + w.getInsns().toString());
		}

		Collections.sort(objNames);
		System.out.println("\nFull list of Objects with WRPKRU:");
		for (String name : objNames) {
			System.out.println(name);
		}
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		if (args.length != 1) {
			System.err
					.println("Too few arguments\nPlease specify output file of binary analysis.");
			System.exit(1);
		}

		AnalyzeBinaryAnalysis aba = new AnalyzeBinaryAnalysis(new File(args[0]));

		// aba.extract();
		aba.extract_from_xml();

		aba.analyze();
	}

}
