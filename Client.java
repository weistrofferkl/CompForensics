import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.UnknownHostException;


public class Client {
	public static void main(String[] args) throws UnknownHostException, IOException{
		System.out.println("Connecting...");
		Socket sock = new Socket("127.0.1",12345);
		
		System.out.println("Connected.");
		
		InputStream is = sock.getInputStream();
		FileOutputStream fos = new FileOutputStream("Message-Copy.txt");
		
		System.out.println("Receiving....");
		
		byte[] b = new byte[1024];
		int bytes_read;
		
		while(true){
			bytes_read = is.read(b);
			if(bytes_read <=0){
				break;
			}
			fos.write(b,0,bytes_read);
			
		}
		fos.close();
		sock.close();
		
		System.out.println("Complete");
		
	}
}
