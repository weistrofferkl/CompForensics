import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Stack;
/**
 * This class extracts JPEG images from a file using header/footer carving to carve out the possible
 * JPEG images from unalloc.img. Please note that this program takes around a minute to run as we read
 * 1 byte from the file at a time.
 * @author Kendall Weistroffer
 * Assignment #4
 * Computer Forensics- Dewri
 * Due: 11:59pm 10/31/2014
 */
public class ImageCarver {
	
	/**
	 * This method uses header/footer carving to extract the images from a file by
	 * reading in one byte at a time and seeing if the byte matches the Header Signature (FFD8FF)
	 * or the Footer Signature (FFD9).
	 * @throws IOException
	 */
	public static void read() throws IOException{	
		RandomAccessFile file = new RandomAccessFile("unalloc.img","r" );
		byte[] h = new byte[1]; 
		long OffsetH = 0;
		long OffsetF = 0;
		int counter = 0;; //counts how many bytes read
		
		int i = 0; //header counter, used for naming files
		Stack<Long> offsetStack = new Stack<Long>(); //used to keep track of the headers
		
	while(true){ 
		file.read(h,0,1); //read in a byte
		counter = counter + 1;
		
		if((h[0]&0xFF) == 0xFF){ // if the byte we have = 0xFF, we need to check if the next 2 bytes equal D8FF or D9
			file.read(h,0,1);
			counter++;
			
			//First Header Check: If the next byte = 0xD8, we still need to check the next byte
			if((h[0]&0xFF) == 0xD8){ 
				file.read(h,0,1);
				counter++;
				
				if((h[0]&0xFF) == 0xFF){ // If the next byte = 0xFF, then we have a header
					OffsetH = file.getFilePointer()-3; //get the header offset
					offsetStack.add(OffsetH); //used to keep track of the header addresses
					file.seek(OffsetH+1); // Go to to the next byte in the File to start reading in again, (look for footer)
				}
			}
			//Footer check:  if the next byte = 0xD9, we have a footer
			else if((h[0]&0xFF) == 0xD9){ 
				OffsetF = file.getFilePointer()-1; // get the footer offset
				
				if(offsetStack.size() > 0){ // if we have come across a header...:
					i++; //used to increment file name
					FileOutputStream output = new FileOutputStream(i + ".jpeg"); //create the file
					Long headerOffset = offsetStack.peek(); // get the header offset
					offsetStack.pop(); 
					
					//Print out required data: 
					System.out.println("File Name:" +"\t"+ i+".jpeg");
					System.out.println("Header Offset:"+ "\t" +"0x"+ Long.toHexString(headerOffset));
					System.out.println("Footer Offset:"+ "\t" + "0x" + Long.toHexString(OffsetF));
					System.out.println();
					
					//Create the image file:
					byte[] b = new byte[(int) ((OffsetF+1)-(headerOffset-1))];
					file.seek(headerOffset); // seek to the header
					file.read(b,0,b.length-2);
					output.write(b);
					output.close();
				}
			}
		}
		//end condition: if we hit the end of the file
		if(file.getFilePointer()  == file.length()){
			break;
		}
		//Read in a byte and reset the seek address before we loop through again:
		file.read(h,0,1); 
		file.seek((file.getFilePointer()-1));
	} 
	
	file.close();
}
	/**
	 * This is the main method, where the program is run.
	 * @param args
	 * @throws IOException
	 */
	public static void main(String [] args) throws IOException{
		read();
	}
}