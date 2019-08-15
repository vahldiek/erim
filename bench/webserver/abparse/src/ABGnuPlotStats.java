import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedList;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.Arrays;
import java.util.Map;


public class ABGnuPlotStats implements Cloneable {

    private TreeMap<Long, Long> dataset = null;
    private long removedStart = 0;
    private long removedEnd = 0;
    private long expsize = 0;
    private int numInputs = 0;

    private void reportDataSetSize() {
	//System.out.println("Dataset size " + dataset.size());
    }

    private ABGnuPlotStats(ABGnuPlotStats abgps) {
	this.dataset = (TreeMap<Long, Long>) abgps.dataset.clone();
	this.expsize = this.dataset.size();
	this.numInputs = abgps.numInputs;
	this.removedStart = abgps.removedStart;
	this.removedEnd = abgps.removedEnd;
    }

    public ABGnuPlotStats(String [] filenames) throws IOException{
		this.dataset = new TreeMap<>();
		long cur = 0L;
		long ts = 0L;
		for (String fname : filenames) {
//			System.out.println("printing " + fname);
		    this.numInputs++;
		    //	    System.out.println("processing file: " + fname);
		    BufferedReader br = new BufferedReader(new FileReader(fname));
		    
		    br.readLine(); // remove header
		    
		    String line = null;
		    for(long lcnt = 0; (line = br.readLine()) != null; lcnt++) {
				String[] columns = line.split("\t");
//						System.out.println(Arrays.toString(columns));
				try {
				    ts = Long.parseLong(columns[4]);
//					System.out.println("time stamp " + ts);
				} catch (java.lang.ArrayIndexOutOfBoundsException e) {
				    //System.out.println("aiobe at line " + lcnt);
				    continue;
				}
		
				if(dataset.containsKey(ts)) {
				    cur = dataset.get(ts);
				    dataset.put(ts, cur+1);
				} else {
				    dataset.put(ts, 1L);
				}
		    }
		}

//		System.out.println("ds " + dataset.size());
	
		while(dataset.size() > 0 && dataset.firstKey() + 1L != dataset.higherKey(dataset.firstKey())) {
		    //	    System.out.println(dataset.firstKey() + " "+ dataset.higherKey(dataset.firstKey()));
		    //	    System.out.println("removing first entry");
		    dataset.pollFirstEntry();
		}
		
		while(dataset.size() > 0 && dataset.lastKey() - 1L != dataset.lowerKey(dataset.lastKey())) { 
		    //    System.out.println("removing last entry");
		    dataset.pollLastEntry();
		}
		
	
		this.expsize = dataset.size();
	       
		reportDataSetSize();
    }

    public void removeStartSec(Long sec) {
	if(dataset.size() < 1 || sec < 1)
	    return;

	reportDataSetSize();

	long firstSecond = dataset.firstKey();
	while(dataset.size() > 0 && dataset.firstKey() < firstSecond + sec) {
	    dataset.pollFirstEntry();
	}
	
	removedStart += sec;

	reportDataSetSize();
    }

    public void removeAfterSec(Long sec) {
        if(dataset.size() < 1 || sec < 1) 
            return;
        
        reportDataSetSize();
        long secondAfter = dataset.firstKey() + sec;
        while (dataset.lastKey() >= secondAfter) {
            dataset.pollLastEntry();
        }
        
        reportDataSetSize();
        
    }

    public void removeEndSec(Long sec) {
	if(dataset.size() < 1 || sec < 1)
	    return;

	reportDataSetSize();

	long lastSecond = dataset.lastKey();
	while(dataset.size() > 0 && dataset.lastKey() > lastSecond - sec) {
	    dataset.pollLastEntry();
	}

	removedEnd += sec;

	reportDataSetSize();
    }
    
    public void printReqps() {
	if(dataset.size() < 1)
	    return;

	Long firstSecond = dataset.firstKey();
	Long lastSecond = dataset.lastKey();
	long time = lastSecond - firstSecond + 1;
	long count = 0;
	for(Map.Entry<Long,Long> entry : dataset.entrySet()) {
	    count += entry.getValue();
//	    System.out.println(entry.getKey() + " " + entry.getValue());
	}
	float reqps = ((float) count) /  ((float) time);
	System.out.println(time + " " + count + " " + reqps);
    }

    public Object clone() {
	return new ABGnuPlotStats(this);
    }
    
    public void printWindowReqps(long exptime, long interval) {
	long windowStart = 0;
	long windowEnd = exptime - interval;

	//	System.out.println("running with exp " + exptime + " int " + interval);
	//	System.out.println("windows start " + windowStart + " end " + windowEnd);
	System.out.println("# of Inputs\tTime\tFirst\tLast\tCount\tReq/s");

	for(;windowStart < exptime && windowEnd >= 0; windowStart += interval, windowEnd -= interval) {
	    ABGnuPlotStats tmp = (ABGnuPlotStats) this.clone();
       //       if(exptime - windowEnd > windowStart + 30)
       //    windowEnd--;
	    tmp.removeStartSec(windowStart);
	    tmp.removeAfterSec(interval); 
	    System.out.print(numInputs + " " + windowStart + " " + (windowStart+interval) + " ");
	    tmp.printReqps();
	}
    }


    /**
     * @param args
     */
    public static void main(String[] args) throws IOException{
	Long removeStartSec = 20L;
	Long removeEndSec = 10L;



	
	if(args.length < 1) {
	    System.out.println("please provide input - starting with 3 inputs: remove start sec, remove end sec, files...");
	    System.exit(1);
	}
	
	try {
	    removeStartSec = Long.parseLong(args[0]);
	    removeEndSec = Long.parseLong(args[1]);
	    args = Arrays.copyOfRange(args, 2, args.length);
	} catch (NumberFormatException takeDefaultValues) {
	    // do nothing
	}
	
	System.out.println("ABGPS with start sec " + removeStartSec + " end sec " + removeEndSec + " files " + Arrays.toString(args));
	
	ABGnuPlotStats abps = new ABGnuPlotStats(args);
	
	abps.removeStartSec(removeStartSec);
	abps.removeEndSec(removeEndSec);
						
	abps.printReqps();
    }
}
