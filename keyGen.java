import java.util.*;
import java.util.regex.*;
import java.io.*;
public class keyGen {
	public static void main(String[] args) throws Exception {
		generatePasswordKey();
		generateUsernameKey();
		generateInitVector();
	}

	public static void generatePasswordKey() throws Exception {
		String sysName,passWordKey,base="passWordKey";
		for(;;) {
			passWordKey = generateRandom();
			Boolean bool = regexCheck(passWordKey);
			if(bool==true) {
				break;
			}
			else {
				continue;
			}
		}
		sysName = System.getProperty("user.name");
		File mainFolder = new File("C://Program Files//Octiax");
		if(mainFolder.exists()&&mainFolder.isDirectory()) {
			//Folder is already present
		}

		else {
			mainFolder.mkdir();
		}
	}

	public static void generateUsernameKey() throws Exception {
		for(;;) {
			String userNameKey = generateRandom();
			Boolean bool = regexCheck(userNameKey);
			if(bool==true) {
				break;
			}
			else {
				continue;
			}
		}
	}

	public static void generateInitVector() throws Exception{
		for(;;) {
			String initVector = generateRandom();
			Boolean bool = regexCheck(initVector);
			if(bool==true) {
				break;
			}
			else {
				continue;
			}
		}
	}

	public static String generateRandom() throws Exception{
		String strEncryptKey = "";
		String randomStr;
		int randomStrNo;
		Random random =  new Random();
		String [] characterArray =  {"D","w","8","-","!","3","A","T","a","@","7","c","1","r","$","I","6","#","B","m","F","C","l","5","H","v","&","L","Y","2","t","%","6","E","i","W","P","z","d","4","&","M","s","Z","g","+","=","S","O","q","N","V","K","*","G","b","n","Q","u","y","j","0","X","u","R","p","x","J","o","e","U","9","h","f","k"};
		for(int i=0;i<16;i++) {
			randomStrNo = random.nextInt(characterArray.length-1);
			randomStr = characterArray[randomStrNo];
			strEncryptKey = strEncryptKey + randomStr;
		}
		System.out.println(strEncryptKey);
		return strEncryptKey;
	}

	public static boolean regexCheck(String toCompile) throws Exception{
		String regex = "^(?=.*[0-9])"
					+ "(?=.*[a-z])(?=.*[A-Z])"
					+ "(?=.*[@#$%^&+!=])"
					+ "(?=\\S+$).{8,20}$";
		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(toCompile);
		Boolean exp = matcher.matches();
		return exp;
	}
}