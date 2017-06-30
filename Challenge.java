import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;


public class Challenge {

	public static void parse() throws IOException{
		RandomAccessFile file = new RandomAccessFile("challenge.mem","r" );
		
		byte[] b = new byte[1024];
		long currentA = 0;
		long nextA = 0;
		
		while(true){ //6687680
			currentA = (byteArray2Long(b,0x7C,0x7C+3)-0x7C-0xC0000000L);
			
			file.read(b,0,1024);
			nextA = (byteArray2Long(b,0x80,0x80+3)-0xC0000000L);
			
			if(nextA == currentA){
				System.out.println(Long.toHexString(currentA));
				break;
			}
		}
	}
	public static long byteArray2Long (byte b[], int start, int end) {
		long value = 0;
		for (int i=start; i<=end; i++) {
			value += (b[i] & 0x000000FF) * Math.pow(16,2*(i-start));
			//or, value += (b[i] & 0x000000FF) << (8*(i-start));
		}
		return value;
	}
	
	public static void main (String [] args) throws IOException{
		parse();
	}
}
