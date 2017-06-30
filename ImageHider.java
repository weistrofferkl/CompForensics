import java.io.*;
import java.awt.image.*;

import javax.imageio.*;

public class ImageHider {
	
	public static void doBGLSBSub(BufferedImage img, int x, int y, int s){
		int argb = img.getRGB(x,y);
		int red = (argb & 0x00FF0000) >> 16;
		int green = (argb &0x0000FF00) >> 8;
		int blue = (argb & 0x000000FF);
		
		blue = (blue & 0xFFFFFFFE) | (s>>1);
		green = (green & 0xFFFFFFFE) | (s>>0x01);
		
		img.setRGB(x,y,(red << 16) | (green << 8) | (blue));
	}
	
	public static void main(String [] args) throws Exception{
		BufferedImage img = ImageIO.read(new File("lena.bmp"));
		
		int width  = img.getWidth();
		int height = img.getHeight();
		
		int b;
		int p_index = 0;
		
		FileInputStream hidden = new FileInputStream("yoda.jpg");
		
		while((b=hidden.read())!= -1){
			doBGLSBSub(img, p_index%width, p_index/width, (b>>6)); p_index++;
			doBGLSBSub(img, p_index%width, p_index/width, (b>>4)&0x3); p_index++;
			doBGLSBSub(img, p_index%width, p_index/width, (b>>2)&0x3); p_index++;
			doBGLSBSub(img, p_index%width, p_index/width, (b&0x3)); p_index++;
		}
		File outputFile = new File("Lena-Yoda.bmp");
		ImageIO.write(img, "bmp", outputFile);
		
		hidden.close();
	}

}
