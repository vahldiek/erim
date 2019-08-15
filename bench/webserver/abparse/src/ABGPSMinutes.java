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

public class ABGPSMinutes {
    
    public static void main(String[] args) throws IOException {

	long exptime = 0;
	long interval = 60;
	
	if(args.length < 1) {
	    System.out.println("please provide input - exp length, interval, files...");
	    System.exit(1);
	}

	try {
	    exptime = Long.parseLong(args[0]);
	    interval = Long.parseLong(args[1]);
	    args = Arrays.copyOfRange(args, 2, args.length);
	} catch (NumberFormatException notused) {
	}
	
	ABGnuPlotStats abps = new ABGnuPlotStats(args);

	//	System.out.println("req/s\ttime\ttotal req\tstart\tend");
	abps.printWindowReqps(exptime, interval);
	
    }

}
