import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * This class analyzes a memory dump file from a Linux system (in this case challenge.mem)
 * and outputs the process identifier(PID), the Parent's process identifier (PPID),
 * the user identifier(UID), the total size (in kb) of virtual memory areas (VMZ),
 * the memory address where the process descriptor of the process starts (TASK), and
 * the name of the process(COMM).
 * 
 * @author Kendall Weistroffer
 * Assignment #3
 * Computer Forensics- Dewri
 * Due: 11:59pm 10/20/2014
 */

public class RamPreview {
	
	/**
	 * This method parses through the file, and extracts information about the file
	 * using various helper-methods and then prints the information to the screen.
	 * @throws IOException
	 */
	public static void parse() throws IOException{
		RandomAccessFile file = new RandomAccessFile("challenge.mem","r" );
		
		byte[] b = new byte [1024];
		byte[] PPIDArray = new byte[1024];
		byte[] MMSArray = new byte[1024];
		byte[] VMAArray = new byte[1024];
		long startPD = 0x00660BC0;
		long nextPD = 0x00660BC0;
		long pointer = 0;
		
		System.out.println("PID"  +"\t" + "PPID"+ "\t" + "UID"+ "\t"+"VMZ"+ "\t"+"TASK"+"\t"+ "\t"+"COMM"); //prints the header
	
		while (true){  //used to parse until the next process des. address is the same as the first process des.
			file.seek(nextPD);
			
			pointer = file.getFilePointer();
			file.read(b,0,1024);
			nextPD = (byteArray2Long(b,0x7C,0x7C+3)-0x7C-0xC0000000L);
			
			//Code used to extract PPID
			long PPIDAddress =  byteArray2Long(b,0xB0,0xB0+3)-0xC0000000L;
			file.seek(PPIDAddress);
			file.read(PPIDArray,0,1024);
			
			//Code used to extract the VMZ
			
			//first we have to get to the Memory Mapping Structure
			int MMSAddress = (int) ((int)byteArray2Long(b,0x84,0x84+4)-0xC0000000L);
			file.seek(MMSAddress);
			file.read(MMSArray,0,4);
			
			if(MMSAddress != 0){ //if there is no MMSAddress, then there is no VMZ
			//if there is a corresponding MMSAddress, then we are able to access the VMZ
			int VMAAddress = (int) ((int)byteArray2Long(MMSArray,0x00, 0x00+4)-0xC0000000L);
			file.seek(VMAAddress);
			file.read(VMAArray,0,1024);
			}
			
			//Print out the results:
			System.out.println(extractPID(b,0xA8, 0xA8+4) + "\t"+ extractPID(PPIDArray,0xA8, 0xA8+4)+"\t"+extractUID(b,0x14C,0x14C+4)+ "\t"+extractVMASize(file,VMAArray)+ "\t"+Long.toHexString(pointer+0xC0000000L)+"\t"+extractName(b,0x194,0x194+16));
		
			//if the next Process des. equals the first Process des. then we are done
			if(nextPD == startPD){
				break;
			}
		
		}
		file.close();
		
	}
	
	/**
	 * This takes in a byte array and converts it to a Long
	 * @param byte [] b
	 * @param int start
	 * @param int end
	 * @return the Long representation of a byte array
	 */
	public static long byteArray2Long (byte b[], int start, int end) {
		long value = 0;
		for (int i=start; i<=end; i++) {
			value += (b[i] & 0x000000FF) * Math.pow(16,2*(i-start));
			//or, value += (b[i] & 0x000000FF) << (8*(i-start));
		}
		return value;
	}
	
	/**
	 * This method extracts the next process descriptor
	 * @param byte[] b
	 * @param int start
	 * @param int end
	 * @return the int value of the next Process Descriptor 
	 */
	public static int extractNextPD(byte [] b, int start, int end){
		byte [] NPD = new byte [4];  
		for(int i = 0; i< NPD.length; i++){  //extract the address of the Next Process descriptor
			NPD[i] = b[start+i];  //store it in the NPD array
		}
		return (int)byteArray2Long(NPD,0,NPD.length-1); // convert NPD to integer and return
	}
	
	/**
	 * This method extracts the Process Id.
	 * @param byte[] b
	 * @param int start
	 * @param int end
	 * @return the int value of the Process Id.
	 */
	public static int extractPID(byte[] b, int start, int end){
		byte [] PID = new byte[4];
		for(int i = 0; i< PID.length; i++){ //extract the address of the PID
			PID[i] = b[start+i];	 //store it in the PID array
		}
		return (int) byteArray2Long(PID,0,PID.length-1); // convert PID to integer and return
	}
	
	/**
	 * This method extracts the User Id.
	 * @param byte[] b
	 * @param int start
	 * @param int end
	 * @return the int. value of the User Id.
	 */	
	public static int extractUID(byte[] b, int start, int end){
		byte [] UID = new byte[4];
		for(int i = 0; i<UID.length; i++){	//extract the address of the UID
			UID[i] = b[i+start];	//store it in the UID array
		}
		return (int) byteArray2Long(UID,0, UID.length-1); // convert UID to integer and return
	}
	

	/**
	 * This method extracts the name of the process
	 * @param byte[] b
	 * @param int start
	 * @param int end
	 * @return the String format of the process name
	 */
	public static String extractName(byte [] b,int start, int end){ 
		byte[] name = new byte[end-start];
		String s = "";
		
		
			for(int i = 0; i<name.length; i++){   //extract the name 
				if(b[start+i] == 0x00){ //only print the available name
					break;
				}
			name[i] = b[start+i]; //store it in the name array
		}
		s = new String (name);	//convert the byte[] to string and return it
		return s;	
	}
	
	/**
	 * This method extracts the size of the virtual memory areas.
	 * @param RandomAccessFile file
	 * @param byte [] b
	 * @return the int vale of the total size of the virtual memory areas (in kb)
	 * @throws IOException
	 */
	public static int extractVMASize(RandomAccessFile file, byte [] b) throws IOException{
		int counter = 0;
		int nextAddress = 0;
		
		while(true){	
			int beginningAddress = (int) (byteArray2Long(b,0x04,0x04+3)-0xC0000000L); //the beginning address of the VMA
			int endAddress = (int) (byteArray2Long(b,0x08,0x08+3)-0xC0000000L); //the end address of the VMA
			
			counter = counter + ((endAddress-beginningAddress)); //get the size of the VMA and add it to the counter
			 
			nextAddress = (int) (byteArray2Long(b,0x0C,0x0C+3)-0xC0000000L); //calculate the address of the next VMA

			if(b[0x0C]== 0x00 && b[0x0C+1]== 0x00 && b[0x0C+2]== 0x00 && b[0x0C+3]== 0x00){ //if the address of the next VMA is all zeros then we are done
				break;
			}
			
			file.seek(nextAddress);  //if the next VMA address is not all zeros, then we need to get to its location
			file.read(b,0,1024);	//then we must read from it.
		}
		
		return (counter/1024); //converts the value to kb and returns
	}
	
	
	/**
	 * This is where the program is run from.
	 * @param args
	 * @throws IOException
	 */
	public static void main(String [] args) throws IOException{
		parse(); //calls the parse method
	}
		
}