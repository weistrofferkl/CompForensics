import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import javax.imageio.ImageIO;
/**
 * This class takes in the name of a file (args[0]) and examines the image for hidden data using LSB
 * substitution by examining the image's color channels.
 * @author Kendall Weistroffer
 * Assignment #5
 * Computer Forensics- Dewri
 * Due: 11:59pm 11/13/2014
 *
 */
public class Sample {

	public static String extension = "";
	/**
	 * This is the main method, where the program is run.
	 * @param args
	 * @throws IOException
	 */
	public static void main(String[] args) throws IOException{
	
			BufferedImage image = ImageIO.read(new File(args[0]));
			String s = args[0];
			s = s.substring(0,s.indexOf('.'));
			int width = image.getWidth();
			int height = image.getHeight();
			
			extractChannels(image, width, height, s);
	}
	
	/**
	 * In this method the red, green, and blue channels are extracted and tested
	 * to see if there is a hidden image on any color combination (ex: r,b,g,rb,gb, etc.)
	 * @param BufferedImage img - The desired image
	 * @param int width - the width of the image
	 * @param int height - the height of the image
	 * @param String fileName - the name of the passed-in image
	 * @throws IOException
	 */
	public static void extractChannels(BufferedImage img, int width, int height, String fileName) throws IOException{
	
		byte[][]b = new byte[3][width*height];
		int channelNumber = 0;
		int channelNumber2 = 0;
		int channelNumber3 = 0;
										//array of 1s and 0s
		for(int x = 0; x < width; x++){
			for(int y = 0; y < height; y++){
				
			int rgb = img.getRGB(x,y);
		
			//formula is because we want a single column, so we need to "flatten" the array.
			//that way we can iterate row-by-row.
			b[2][(y*height)+x] = (byte)(((rgb)&0xFF) &0x01); //blue    
			b[1][(y*height)+x] = (byte)(((rgb>>8)& 0xFF) &0x01); //green
			b[0][(y*height)+x] = (byte)(((rgb>>16)& 0xFF)&0x01);//red
			}
		}
		
		for(int i = 0; i<=2; i++){
			channelNumber = i;
			testSingleChannel(b[i],fileName, channelNumber); //First Channel
			for(int j = 0; j<= 2; j++){	
				channelNumber = i;
				channelNumber2 = j;
				testDoubleChannel(b[i],b[j], fileName, channelNumber, channelNumber2); //Double Channel
				for(int k = 0; k<=2;k++){
					channelNumber = i;
					channelNumber2 = j;
					channelNumber3 = k;
					testTripleChannel(b[i],b[j],b[k], fileName, channelNumber, channelNumber2, channelNumber3); //Triple Channel
				}
			}
		}
	}
	
	/**
	 * This method tests a single channel for hidden files
	 * @param byte[] aleph - the channel
	 * @param String inputFile - the input file name
	 * @param int channelNumber - the number corresponding to the pixel array color
	 * @throws IOException
	 */
	public static void testSingleChannel(byte[] aleph, String inputFile, int channelNumber) throws IOException{
		byte temp = 0;
		int counter = 0;
		ArrayList<Byte> bet = new ArrayList<>(); //used to store the bytes once created
		String channel = "";
		
		//following is the bit-shifting and or-ing
		for(int i = 0; i < aleph.length; i++){
			temp |=  aleph[i];
			if(counter == 7){
				bet.add(temp);
				counter = 0;
				temp = 0;
			}else{
			counter++;
			}
			temp = (byte)(temp<<1);
		}
		
		byte[] gimmel = new byte[bet.size()]; //used to store the bytes so we can write to a file
		
		for(int j = 0; j < gimmel.length; j++){
			gimmel[j] = bet.get(j).byteValue(); //convert into a byte array
		}
		extension = nameExtension(gimmel);
		channel = getTheLetter(channelNumber);
		
		if (!extension.equals("")){
		FileOutputStream output = new FileOutputStream(new File(inputFile+"-"+channel+ extension));
		output.write(gimmel);
		output.close();
		}
	}
	
	/**
	 * This method tests two channels for hidden files, most of this code is the same as in the
	 * single channel extraction method (above)
	 * @param byte[] aleph- the first channel
	 * @param byte [] bet - the second channel
	 * @param String inputName- the input file name
	 * @param int channelNumber - the number corresponding to the first channel array color
	 * @param channelNumber2 - the number corresponding to the second channel array color
	 * @throws IOException
	 */
	public static void testDoubleChannel(byte[] aleph, byte[] bet, String inputName, int channelNumber, int channelNumber2) throws IOException{	
		byte temp = 0;
		int counter = 0;
		ArrayList<Byte> array = new ArrayList<>();
		String channel = "";
		String channel2 = "";
		
		for(int i = 0; i < aleph.length; i++){
			temp |=  aleph[i];
			temp = (byte)(temp<<1);
			temp |= bet[i];
			
			if(counter == 3){ //instead of 7 because we get 2 bites from each channel
				array.add(temp);
				counter = 0;
				temp = 0;
			}else{
				counter++;
			}
			temp = (byte)(temp<<1);			
		}
		
		byte[] gimmel = new byte[array.size()];
		
		for(int j = 0; j < gimmel.length; j++){
			gimmel[j] = array.get(j).byteValue();
		}
		extension = nameExtension(gimmel);
		channel = getTheLetter(channelNumber);
		channel2 = getTheLetter(channelNumber2); //used because now we have 2 channels to check for

		if (!extension.equals("")) {
			FileOutputStream output = new FileOutputStream(new File(inputName+"-"+channel+channel2+ extension));
			output.write(gimmel);
			output.close();
		}
	
	}
	/**
	 * This method tests three channels for hidden images
	 *  most of this code is the same as in the single channel extraction method (above)
	 * @param byte [] aleph - the first channel
	 * @param byte [] bet - the second channel
	 * @param byte [] gimmel - the third channel
	 * @param String inputName - the name of the input file
	 * @param int channelNumber - the number corresponding to the first channel array color
	 * @param int channelNumber2 - the number corresponding to the second channel array color
	 * @param int channelNumber3 - the number corresponding to the third channel array color
	 * @throws IOException
	 */
	public static void testTripleChannel(byte[] aleph, byte[] bet, byte[] gimmel, String inputName, int channelNumber, int channelNumber2, int channelNumber3) throws IOException{
		byte temp = 0; //used to store the bits
		int counter = 0;
		ArrayList<Byte> array = new ArrayList<>();
		String channel = "";
		String channel2 = "";
		String channel3 = "";
		
		
		for(int i = 0; i < aleph.length; i++){
		
			temp |=  aleph[i];
			if(counter == 7){  //used to determine if we have a full byte of bits
				array.add(temp);
				counter = 0;
				temp = 0;
			}else{
				counter++;
			}
			
			temp = (byte)(temp<<1);
			temp |= bet[i];
			
			if(counter == 7){
				array.add(temp);
				counter = 0;
				temp = 0;
			}else{
				counter++;
			}	
			temp = (byte)(temp<<1);
			temp |= gimmel[i];
			
			if(counter == 7){
				array.add(temp);
				counter = 0;
				temp = 0;
			}else{
				counter++;
			}
			temp = (byte)(temp << 1);	
		}
		
		byte[] dalet = new byte[array.size()];
	
		for(int j = 0; j < dalet.length; j++){
			dalet[j] = array.get(j).byteValue(); 
		}
	
		extension = nameExtension(dalet);
		channel = getTheLetter(channelNumber);
		channel2 = getTheLetter(channelNumber2);
		channel3 = getTheLetter(channelNumber3); //used because now we have 3 channels to check for
		
		if (!extension.equals("")){
		FileOutputStream output = new FileOutputStream(new File(inputName+"-"+channel+channel2+channel3+ extension));
		output.write(dalet);
		output.close();
		}
	}
	
	/** 
	 * This method converts the color representation of the array (red = 0, green = 1, blue = 2) 
	 * to match the desired output file name.
	 * @param int inputNumber - the color number (0,1, or 2)
	 * @return String letter - the letter corresponding the the color channel
	 */
	public static String getTheLetter(int inputNumber){
		String letter = "";
		if(inputNumber == 0){
			letter = "r";
		}
		if(inputNumber == 1){
			letter = "g";
		}
		if(inputNumber == 2){
			letter = "b";
		}
		return letter;
	}
	
	/**
	 * This method tests the header of each file to determine how it should be named
	 * @param byte[] aleph - the array that stores the file's bytes
	 * @return String str - the proper file extension
	 */
	public static String nameExtension(byte[] aleph){
		String str = "";
		if((aleph[0] &0x000000FF) == 0xFF && (aleph[1] &0x000000FF) == 0xD8 && (aleph[2] &0x000000FF) == 0xFF){ //jpeg
			str = ".jpg";
		}
		if((aleph[0] &0x000000FF) == 0x42 && (aleph[1]&0x000000FF) == 0x4D){
			str = ".bmp";
		}
		if((aleph[0] &0x000000FF) == 0x50 && (aleph[1] &0x000000FF) == 0x4B && (aleph[2] &0x000000FF) == 0x03 && (aleph[3] &0x000000FF) == 0x04 &&(aleph[4] &0x000000FF)==0x14 && (aleph[5]&0x000000FF) == 0x00 && (aleph[6]&0x000000FF) == 0x06 && (aleph[7]&0x000000FF) == 0x00){
			str = ".docx";
		}
		if((aleph[0] &0x000000FF) == 0x25 && (aleph[1] &0x000000FF) == 0x50 && (aleph[2] &0x000000FF) == 0x44 && (aleph[3] &0x000000FF) == 0x46){
			str = ".pdf";
		}
		if((aleph[0] &0x000000FF) == 0x49 && (aleph[1] &0x000000FF) == 0x44 && (aleph[2] &0x000000FF) == 0x33){
			str = ".mp3";
		}
		return str;
	}
	
	
}
