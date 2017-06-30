import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * This class outputs some basic information about the files contained within a disk image, such as
 * the name of the File, the cluster number where the MFT record for each file is located,
 * the cluster number where the file contents begin, the offset in the file contents' cluster number
 * to the first byte of the cluster, and the number of alternate data streams for the file (if any).
 * 
 * @author Kendall Weistroffer 
 * Assignment #2
 * Computer Forensics- Dewri
 * Due: 11:59pm 10/4/2014 (Originally due: 11:59pm 10/1/2014)
 */
public class DiskPreview {
	
	
	/**
	 * This method is where we read in the records and extract the necessary data.
	 * @throws IOException
	 */
 	public static void read() throws IOException{
		InputStream in = new FileInputStream("USB1.dd");
		DataInputStream dis = new DataInputStream(in);
		
		byte[] b = new byte[1024];
		
		dis.read(b,0,1024);
		//Used to calculate the start of the MFT
		int MFTStartCluster = byteArray2Int(b,0x30,0x37);
		int bytesPerSector = byteArray2Int(b, 0x0B, 0x0C);
		int sectorsPerCluster = byteArray2Int (b, 0x0D, 0x0D);
		
		//calcuclate the MFTStart
		int MFTStart = (MFTStartCluster * bytesPerSector* sectorsPerCluster);
		
		int SC = MFTStartCluster;
		int SCCounter = 0;
		
		//Skip to the start of the MFT
		dis.skip(MFTStart-1024);
		 
		
	while(dis.read(b,0,1024) != -1){ 
		
	 //System.out.println(dis.read(b,0,1024));
		
		int HL = byteArray2Int(b, 0x14,0x14); // beginning of the attributes
		int AttributeSize = 0;
		int offset = 0;
		int FBCN = 0;
		int NDS = 0;
		int HasAttributes = 0;
		
	
		if((b[0] &0xFF) == 0x46 && (b[1] &0xFF) == 0x49 && (b[2] &0xFF) == 0x4C && (b[3] &0xFF) == 0x45){ //check for the "magic number"
		
		while(((b[HL] & 0xFF) != 0xFF) &&(b[HL+1] & 0xFF) != 0xFF){
			
			//if we reach the end of the record, we break from this loop, and switch to the next record
			if(((b[HL] & 0x000000FF) == 0xFF) && ((b[HL +1] &0x000000FF) == 0xFF) && ((b[HL+2] & 0x000000FF) == 0xFF) &&((b[HL+3] & 0x000000FF) == 0x000000FF)){
			
				break;		
			}
			
			HL = HL+AttributeSize; //Update the HL with new Attribute Size
			
			AttributeSize = byteArray2Int(b,HL+0x04, HL+0x05); //update the Attribute Size
			
			if(b[HL] == 0x30){ // if we are at Attribute 30
				HasAttributes++; // this will be used to only print the records with Att30 and Att80
				
				byte [] Att30 = new byte[AttributeSize];
				
				for(int i = 0; i< Att30.length ; i++){ // read in Attribute30 into an array for processing
					Att30[i] = b[HL+i];	
				}
			
			int Att30Size = AttributeSize;
			HL = HL +Att30Size; //update HL to get it to the start of next Attribute
			AttributeSize = byteArray2Int(b,(HL+0x04), (HL+0x05)); //set attribute size to size of next Attribute
			
			if(b[HL] == 0x30){ //check to see if we have 2 Attribute 30s
			 int Att2nd30Size = AttributeSize;
			 HL = HL +Att2nd30Size; //update the HL
			 AttributeSize = byteArray2Int(b,(HL+0x04), (HL+0x05)); //get the size of the next Attribute
			}
			
			if(b[HL] == 0x40){ //Check to see if we have an Attribute 40, follows the same process as above
				int Att40Size = AttributeSize;
				HL = HL + Att40Size;
				AttributeSize = byteArray2Int(b, (HL +0x04), (HL + 0x05));
			}
			
			if(b[HL] == 0x50){//Check to see if we have an Attribute 50, follows the same process as above
				int Att50Size = AttributeSize;
				HL = HL + Att50Size;
				AttributeSize = byteArray2Int(b, (HL +0x04), (HL + 0x05));
			}
			
			if(b[HL] == 0x60){//Check to see if we have an Attribute 60, follows the same process as above
				int Att60Size = AttributeSize;
				HL = HL + Att60Size;
				AttributeSize = byteArray2Int(b, (HL +0x04), (HL + 0x05));
			}
			
			if(b[HL] == 0x70){//Check to see if we have an Attribute 70, follows the same process as above
				int Att70Size = AttributeSize;
				HL = HL + Att70Size;
				AttributeSize = byteArray2Int(b, (HL +0x04), (HL + 0x05));
			}
			
			int Att80Size = AttributeSize; 
			
			 if((b[HL] &0x000000FF) == 0x80){ // if we are at Attribute 80
				HasAttributes++; //Increment this as Att80 is one of the desired Attributes
				System.out.println(extractName(Att30, 0x5A, Att30Size)+ ":"); // Print out the record name
			
			    byte[] Att80 = new byte[Att80Size];
				 
				 for(int i = 0; i< Att80.length; i++){ //Store the contents of Att80 in a byte array
					 Att80[i] = b[HL +i]; 
				 }
				 
				 if(Att80[0x08] == 0x00){ // if resident file
					
					 FBCN = SC; //if we have a resident file, FBCN will equal the Start Cluster
				
					 SC = SC+SCCounter;  // increment the Start Cluster
					 offset = HL +0x18;  // get the offset based on the start of Att80
					 
				
				 }
				 else if (Att80[0x08] == 0x01){ // if non resident file
					
					 byte [] dataRun = new byte [(HL+ 0x40) - AttributeSize]; // this is used to process the data run
					 
					 for(int i = 0; i< dataRun.length; i++){ // load the dataRun into a byte array
						 dataRun[i] = b[HL+0x40+i];
					 }
					
					 String start = Integer.toHexString(dataRun[0]);
					 String upperHalf = (start.substring(0,1)); // upper half of first number, bytes in 3rd component
					 int lowerHalf = 0;
					 
					 if(start.length() > 1){ // if the starting number has 2 digits
						 String lowerHalfString = (start.substring(1,2)); // lower half of first number
						 lowerHalf = Integer.parseInt(lowerHalfString);
					 }
				 
					 byte [] dataCN = new byte[Integer.parseInt(upperHalf)]; //this will store the Cluster Number of the data run
					 
						for(int i = 0; i< Integer.parseInt(upperHalf); i++){ //read in the desired cluster number
						 dataCN[i] = dataRun[lowerHalf+i+1];
						 }
				
					FBCN = hexToIntConversion(toLittleEndian(dataCN)); 
			 }
					HL = HL + Att80Size; //update the HL
					AttributeSize = byteArray2Int(b, (HL +0x04), (HL + 0x05)); //get the next AttributeSize
			}
			
			 for(int i = 0; i< 1024-HL ; i++){ // this is so the following will run until the end of the record
				
				 if((b[HL]&0x000000FF ) == 0x80){ // check to see if we have a second Att80
					
					 NDS++; // if so, count it as a data stream
					
					 int Att802Size = AttributeSize;
						HL = HL + Att802Size; //update the HL accordingly
						AttributeSize = byteArray2Int(b, (HL +0x04), (HL + 0x05)); //get the next Att. size
						
				 }
			 }
			
			 print(SC,offset,NDS,FBCN, HasAttributes); //use the print method to print out the data
			 
			}
		
		}
		
		
		SC = SC+ (1024 / bytesPerSector); //update the Start Cluster
		//System.out.println("second: " + dis.read(b,0,1024));
		}
		}
	
	
	dis.close(); 
	}
 	
 	
 	/**
 	 * This takes in the necessary information that we will print and puts it into the desired format.
 	 * @param int SC - the Start Cluster
 	 * @param int offset - the data offset
 	 * @param int NDS - the number of data streams
 	 * @param int FBCN - the cluster where the file begins
 	 * @param HasAttributes
 	 */
 	public static void print(int SC,int offset, int NDS, int FBCN, int HasAttributes){
 		
 	if(HasAttributes == 2 ){ //checks to make sure we have both Att30 and Att80
 		
 		if(NDS == 0){ // if no data streams are present
 			
 			System.out.println("     "+SC+ " :: "+ FBCN+"(+"+offset+")" );
 			System.out.println();
 		}
 		else{ //if there are data streams, print with NDS included
 			System.out.println("    "+SC+ " :: "+ FBCN+"(+"+offset+")"+ " :: "+ NDS  );
 			System.out.println();
 		}
 	}
 	}
	
 	/**
 	 * This takes in a byte array and flips the values so that it is in little Endian format
 	 * @param byte [] s
 	 * @return converted byte array
 	 */
	public static byte[] toLittleEndian(byte[] s){
		
		for(int i = 0; i< s.length/2; i++){
			 byte temp = s[i];
		        s[i] = s[s.length - i - 1];
		        s[s.length - i - 1] = temp;
		}
		return s;
	}
	
	
 /**
  * Converts a byte array to hexidecimal notation
  * @param byte [] b
  * @return a String of the converted byte [] in hexidecimal notation.
  */
	public static String hexConversion(byte[] b){
		
		String s = "";
		StringBuffer hex = new StringBuffer();
		
			for(int i = 0; i<b.length; i++){
				String h = Integer.toHexString(0xff & b[i]); // stores the converted element at b[i] in h
				
				if(h.length() == 1){  //if the length is 1, add padding
					hex.append('0');
					}
						hex.append(h);  // append the hex string to the stringbuffer
					s =  hex.toString(); //convert the stringbuffer to string format
				}
				
	       return s;     
	   
	}
	
	/**
	 * This takes in a byte array and converts it to an Integer
	 * @param byte [] b
	 * @param int start
	 * @param int end
	 * @return the int representation of a byte array
	 */
	public static int byteArray2Int (byte b[], int start, int end) {
		int value = 0;
		for (int i=start; i<=end; i++) {
			value += (b[i] & 0x000000FF) * Math.pow(16,2*(i-start));
			//or, value += (b[i] & 0x000000FF) << (8*(i-start));
		}
		return value;
	}
	
	/**
	 * This converts an array from hex to decimal notation
	 * @param byte [] b
	 * @return the int representation of a hexidecimal number
	 */
	public static int hexToIntConversion(byte[] b){
		
		String s = "";
		int x = 0;
		StringBuffer hex = new StringBuffer();
		//runs through the byte array
			for(int i = 0; i<b.length; i++){
				String h = Integer.toHexString(0xff & b[i]); // stores the converted element at b[i] in h
				
				//checks to see if the length is equal to 1, if so append 0 to the string buffer
				if(h.length() == 1){ 
					hex.append('0');
					}
						hex.append(h);  // append the hex string to the string buffer
					s =  hex.toString(); //convert the string buffer to string format
		
				}	
			if(s.equals( "")){
				return x;
			}
			int i = Integer.parseInt(s, 16); // change hex to integer/decimal format
	       return i;      
	}

	/**
	 * This converts the name of a record from bytes to String
	 * @param byte [] b
	 * @param int start
	 * @param int end
	 * @return This returns the name of the record as a String (so that it can be read by a human)
	 */
	public static String extractName(byte [] b,int start, int end){ // look at offsets
		byte[] name = new byte[end-start];
		String s = "";
		
		for(int i = 0; i<name.length; i++){
			name[i] = b[start+i];// get name[i] based on the start of the name attribute of b
		}
		
		s = new String (name);
		return s;
		
		
	}
	
	/**
	 * This is the main method, where the program is run.
	 * @param args
	 * @throws IOException
	 */
	public static void main(String [] args) throws IOException{
		
		read(); //calls the read method.
	}

	
}
