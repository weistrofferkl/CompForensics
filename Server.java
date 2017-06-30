import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;


public class Server {
	public static void main(String [] args) throws IOException{
		ServerSocket ssock = new ServerSocket(12345);
		
		while(true){
			System.out.println("Waiting for connection...");
			Socket sock = ssock.accept();
			
			System.out.println("Accepted Connection: "+ sock);
			
			OutputStream os = sock.getOutputStream();
			
			FileInputStream fis = new FileInputStream("Message.txt");
			
			byte[] b = new byte[1024];
			int bytes_read;
			
			while(true){
				bytes_read = fis.read(b);
				if(bytes_read <= 0){
					break;
				}
				os.write(b,0,bytes_read);
			}
			fis.close();
			os.close();
			sock.close();
			ssock.close();
		}
	}
}
