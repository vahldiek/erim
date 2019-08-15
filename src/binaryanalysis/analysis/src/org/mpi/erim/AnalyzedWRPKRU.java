package org.mpi.erim;

import java.util.LinkedList;
import java.util.List;

import com.thoughtworks.xstream.XStream;

public class AnalyzedWRPKRU {

	private static enum IDX {
		OFFSET(1), SEGMENT(2), SEGOFF(3), SECTION(4), SECNAME(5), SECNOEXEC(6), SECOFF(
				6), LOCOFF(7), DISAS(8), INSN(8);

		private int value;

		private IDX(int value) {
			this.value = value;
		}
	};

	private long offset = 0;
	private int segment = 0;
	private long segoffset = 0;
	private int section = 0;
	private String sectionName = null;
	private long sectionOffset = 0;
	private long vmOffset = 0;
	private long locationOffset = 0;
	private List<String> insns = new LinkedList<>();

	private boolean executableSection = false;
	private boolean disasFailed = true;
	private String binary = null;

	private boolean insnDisasFailed = false;
	private boolean fullSeqOperand = true;
	private boolean blockInCfg = false;
	private int offsetInOperand = 0;
	private int operandIt = 0;
	private int operandType = 0;
	private int nextOpType = 0;

	private AnalyzedBinaryObject abo;
	
	private String afterEquals(String s) {
		if (s.contains("="))
			return s.substring(s.indexOf("=") + 1);
		else
			return "";
	}

	public AnalyzedWRPKRU(String line,  AnalyzedBinaryObject abo) {
		this(line);
		
		this.abo = abo;
	}
	
	public AnalyzedWRPKRU(String line) {

		String items[] = line.split(" ", 9);
		// System.out.println(Arrays.toString(items));

		if (!items[0].equals("wrpkru")) {
			return;
		}

		offset = Integer.valueOf(afterEquals(items[IDX.OFFSET.value]), 16);
		segment = Integer.valueOf(afterEquals(items[IDX.SEGMENT.value]));
		segoffset = Integer.valueOf(afterEquals(items[IDX.SEGOFF.value]), 16);
		section = Integer.valueOf(afterEquals(items[IDX.SECTION.value]));
		sectionName = afterEquals(items[IDX.SECNAME.value]);

		if (items[IDX.SECNOEXEC.value].equals("NOT")) {
			// not executable section
			executableSection = false;

			if (items[IDX.DISAS.value].startsWith("DISAS")) {
				// disas failed
				disasFailed = true;
				binary = items[IDX.DISAS.value]
						.substring(items[IDX.DISAS.value]
								.indexOf("DISAS NOT POSSIBLE")
								+ "DISAS NOT POSSIBLE".length());

			} else {
				// disas possible
				disasFailed = false;

				System.err.println("SHOULD NOT HAPPEN");
			}
		} else {
			// executable section --> should find more info about the actual
			// instruction
			executableSection = true;
			sectionOffset = Integer.valueOf(
					afterEquals(items[IDX.SECOFF.value]), 16);
			locationOffset = Integer.valueOf(
					afterEquals(items[IDX.LOCOFF.value]), 16);

			if (items[IDX.INSN.value].startsWith("spans")) {
				// seq. spans multiple instructions
				String remainder = items[IDX.INSN.value].substring(
						items[IDX.INSN.value].indexOf(" ")).trim();
				String[] strinsns = remainder.split("\\]\\[");

				for (String insn : strinsns) {
					insn = insn.trim();
					while (insn.startsWith("[")) {
						insn = insn.substring(1);
					}
					while (insn.endsWith("]")) {
						insn = insn.substring(0, insn.length() - 1);
					}
					insns.add(insn);
				}

			} else if (items[IDX.INSN.value].startsWith("single")) {

				String remainder = items[IDX.INSN.value].substring(
						items[IDX.INSN.value].indexOf(" ")).trim();
				int endOfInsn = remainder.lastIndexOf("]");
				insns.add(remainder.substring(1, endOfInsn));

				String inspectionInsn = remainder.substring(endOfInsn + 1)
						.trim();

				if (inspectionInsn.startsWith("full seq")) {
					// full seq position=%d operand=%d type=%d
					items = inspectionInsn.split(" ");

					offsetInOperand = Integer.valueOf(afterEquals(items[2]));
					operandIt = Integer.valueOf(afterEquals(items[3]));
					operandType = Integer.valueOf(afterEquals(items[4]));

				} else if (inspectionInsn.startsWith("seq spans")) {
					items = inspectionInsn.split(" ");

					fullSeqOperand = false;
					offsetInOperand = Integer.valueOf(afterEquals(items[2]));
					operandIt = Integer.valueOf(afterEquals(items[3]));
					operandType = Integer.valueOf(afterEquals(items[4]));
					nextOpType = Integer.valueOf(afterEquals(items[6].replaceAll("\\)", "")));
				}

			} else {
				insnDisasFailed = true;
			}
		}

	}

	@Override
	public String toString() {
//
//		StringBuffer sb = new StringBuffer();
//
//		sb.append("wrpkru");
//		sb.append(" offset=" + offset);
//		sb.append(" segment=" + segment);
//		sb.append(" segoffset=" + segoffset);
//		sb.append(" section=" + section);
//		sb.append(" sectionName=" + sectionName);
//
//		if (executableSection) {
//			sb.append(" sectionOffset=" + sectionOffset);
//			sb.append(" locationOffset=" + locationOffset);
//
//			if (insnDisasFailed) {
//				sb.append(" instruction disassemble failed");
//			} else {
//				if (insns.size() > 1) {
//					// spans
//					sb.append(" spans");
//					for (String insn : insns) {
//						sb.append("[");
//						sb.append(insn);
//						sb.append("]");
//					}
//				} else {
//					// single insn
//					sb.append(" single");
//					sb.append(insns.get(0));
//					if (fullSeqOperand) {
//						// seq in single operand
//						sb.append(" offsetInOperand=" + offsetInOperand);
//						sb.append(" operandIt=" + operandIt);
//						sb.append(" operandType=" + operandType);
//					} else {
//						// seq spans more operands
//						sb.append(" offsetInOperand=" + offsetInOperand);
//						sb.append(" operandIt=" + operandIt);
//						sb.append(" operandType=" + operandType);
//						sb.append(" nextOpType=" + nextOpType);
//					}
//				}
//			}
//		} else {
//			sb.append(" SECTION NOT EXECUTABLE");
//			if (disasFailed) {
//				sb.append(" DISAS FAILED ");
//				sb.append(binary);
//			} else {
//				// disas possible
//				sb.append(" DISAS POSSIBLE !!!ATTENTION!!!");
//			}
//		}
//
//		return sb.toString();
		
		XStream xstream = new XStream();
		xstream.alias("AnalyzedBinaryObject", AnalyzedBinaryObject.class);
		xstream.alias("AnalyzedWRPKRU", AnalyzedWRPKRU.class);
		
		return xstream.toXML(this);
	}

	public boolean isExecutableSection() {
		return executableSection;
	}

	public boolean isDisasFailed() {
		return disasFailed;
	}

	public boolean isInsnDisasFailed() {
		return insnDisasFailed;
	}

	public boolean isFullSeqOperand() {
		return fullSeqOperand;
	}
	
	public boolean spansMultipleInstructions() {
		return (this.insns.size() > 1);
	}

	public long getOffset() {
		return offset;
	}

	public int getSegment() {
		return segment;
	}

	public long getSegoffset() {
		return segoffset;
	}

	public int getSection() {
		return section;
	}

	public String getSectionName() {
		return sectionName;
	}

	public long getSectionOffset() {
		return sectionOffset;
	}

	public long getLocationOffset() {
		return locationOffset;
	}

	public List<String> getInsns() {
		return insns;
	}

	public String getBinary() {
		return binary;
	}

	public int getOffsetInOperand() {
		return offsetInOperand;
	}

	public int getOperandIt() {
		return operandIt;
	}

	public int getOperandType() {
		return operandType;
	}

	public int getNextOpType() {
		return nextOpType;
	}

	public AnalyzedBinaryObject getAbo() {
		return abo;
	}

	public void setAbo(AnalyzedBinaryObject abo) {
		this.abo = abo;
	}

	public boolean isBlockInCfg() {
		return blockInCfg;
	}

	public void setBlockInCfg(boolean blockInCfg) {
		this.blockInCfg = blockInCfg;
	}

}
