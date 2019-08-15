package org.mpi.erim;

import java.util.LinkedList;
import java.util.List;
import java.util.Arrays;

import com.thoughtworks.xstream.XStream;

public class AnalyzedBinaryObject {
	
	private String filename = null;
	private boolean loadFailed = false;
	private boolean noPhdr = false;
	private int failureCode = 0;
	private List<AnalyzedWRPKRU> wrpkruSet = new LinkedList<>();
	private int numSegments = 0;
	private long executableBytes = 0;
	private int numWRPKRU = 0;
			
	public int getNumSegments() {
		return numSegments;
	}

	public long getExecutableBytes() {
		return executableBytes;
	}

	public int getNumWRPKRU() {
		return numWRPKRU;
	}

	
	private String afterEquals(String s) {
		if(s.contains("="))
			return s.substring(s.indexOf("=") + 1);
		else 
			return "";
	}

	public AnalyzedBinaryObject(String line) {
	
		String items[] = line.split(" ");
		filename = items[0];
		
		// check if binary was loaded correctly
		if(items[1].startsWith("couldn't")) {
			loadFailed = true;
			try {
			    failureCode = Integer.valueOf(afterEquals(items[5]));
			} catch (Exception e) {
			    System.err.println("Line: " + line);
			    e.printStackTrace();
			    System.exit(1);
			}
			return;
		} else if (items[1].startsWith("NO")) {
			noPhdr = true;
			return;
		}
		
		// extract variables from output format numseg=%d executablebytes=%lld numwrpkru=%d
		try {
		    numSegments = Integer.valueOf(afterEquals(items[1]));
		    executableBytes = Integer.valueOf(afterEquals(items[2]));
		    numWRPKRU = Integer.valueOf(afterEquals(items[3]));
		} catch (Exception e) {
		    System.err.println("Line: " + line + "Array: " + Arrays.toString(items));
		    e.printStackTrace();
		    System.exit(1);
		}
	}
	
	public void addWRPKRU(AnalyzedWRPKRU wrpkru) {

		wrpkruSet.add(wrpkru);
	}

	public String getFilename() {
		return filename;
	}

	public boolean isLoadFailed() {
		return loadFailed;
	}

	public int getFailureCode() {
		return failureCode;
	}

	public List<AnalyzedWRPKRU> getWrpkruSet() {
		return wrpkruSet;
	}
	
	@Override
	public String toString() {
//		if(loadFailed) 
//			return filename + " load failed ret=" + failureCode;
//		else if (noPhdr) 
//			return filename + " no Phdr found";
//		else {
//			StringBuffer sb = new StringBuffer();
//			sb.append(filename +" numsegs=" + numSegments + " executableBytes=" + executableBytes + " numWRPKRU=" + numWRPKRU + "\n");
//			
//			for(AnalyzedWRPKRU aw : wrpkruSet)
//				sb.append(aw.toString());
//			
//			return sb.toString();
//		}
		XStream xstream = new XStream();
		xstream.alias("AnalyzedBinaryObject", AnalyzedBinaryObject.class);
		xstream.alias("AnalyzedWRPKRU", AnalyzedWRPKRU.class);
		
		return xstream.toXML(this);
	}

	public boolean isNoPhdr() {
		return noPhdr;
	}
}
