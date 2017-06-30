/**
 * This class calculates the MD5 and SHA-1 hash code for a line of user input and 
 * the MD5 and SHA-1 hash code of the contents of a file.
 * 
 * @author Kendall Weistroffer
 * Assignment #1
 * Computer Forensics - Dewri
 * Due 11:59pm - 9/18/2014
 */

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.Scanner;



public class Hash {
	
	/**
	 * This method takes in an array of bytes and converts it to hexidecimal notation
	 * 
	 * @param b
	 * @return converted string
	 */
	public static String hexConversion(byte[] b){
	
		String s = "";
		StringBuffer hex = new StringBuffer();
			
		//runs through the byte array
			for(int i = 0; i<b.length; i++){
				String h = Integer.toHexString(0xff & b[i]); // stores the converted element at b[i] in h
				
				//checks to see if the length is equal to 1, if so append 0 to the stringbuffer
				if(h.length() == 1){ 
					hex.append('0');
					}
						hex.append(h);  // append the hex string to the stringbuffer
					s =  hex.toString(); //convert the stringbuffer to string format
				}
				
	       return s;     
	   
	}
	
  /**
   * This method takes in a algorithm (either MD5 or SHA-1 in this case), and input from the program
   * user (via Scanner in the main method) and uses both and the hexConversion method to convert the text
   * to hash
   * 
   * @param algorithm
   * @param text
   * @return returns the converted byte array
   */
	public static String calculateTextHash(MessageDigest algorithm, String text){
	
		algorithm.update(text.getBytes()); //updates the digest using the bytes from the user input
		byte b[] = algorithm.digest(); // uses byte array b to store the completed byte-hash 
	
		return hexConversion(b); // convert byte b[] to hexidecimal notation and return
   
			
		
		}
		
	/**		
	 * This method also takes in a specified algorithm (MD5 or SHA-1), but in this case takes in the name
	 * of a file. Using the algorithm and file name, the method reads in the file converts it from
	 * a byte array to a hex array
	 * 
	 * @param algorithm
	 * @param fileName
	 * @return returns the converted byte array in hexidecimal format
	 * @throws IOException
	 */
	public static String calculateFileHash(MessageDigest algorithm, String fileName) throws IOException{
		
		try(InputStream stream = Files.newInputStream(Paths.get(fileName))){ // read in the desired file
			@SuppressWarnings("unused")
			DigestInputStream dis = new DigestInputStream(stream, algorithm); 
		
			
	        byte b[] =  new byte[algorithm.getDigestLength()]; // the byte array is set to the length of the file input
	        int y = 0;
	        
	        while((y= stream.read(b)) >= 0){ //used to make sure we don't hit the end of the file
	        	algorithm.update(b,0,y); //updates the digest based on byte array, offset 0, length of the byte array 
	        }
	        byte x[] = algorithm.digest(); // uses byte x[] to store completed digest
		
		return hexConversion(x); // convert byte x[] to hexidecimal and return
		}
		
}
	/**
	 * The Main method- where the program is run
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args)throws Exception{
		
		//create 2 MessageDigest objects, one for each algorithm
		MessageDigest md1 = MessageDigest.getInstance("MD5");
		MessageDigest md2 = MessageDigest.getInstance("SHA-1");
	
		//get the user input for caclulateTextHash and run the method based input and each algorithm
		Scanner s = new Scanner(System.in);
		System.out.println("Enter a line of text: ");
		String t = s.nextLine();
		System.out.println("SHA-1: "+ calculateTextHash(md2, t));
		System.out.println("MD5:   " + calculateTextHash(md1, t));
	
		//get the desired file name and run caclucateFileHash method based on the input and each algorithm
		System.out.println("Enter a file name in the current directory: ");
		String fileName = s.nextLine();
		System.out.println("SHA-1: " + calculateFileHash(md2, fileName));
		System.out.println("MD5:   " + calculateFileHash(md1, fileName));
		
		s.close();
		
	}

}
