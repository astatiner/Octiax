//importing libraries and APIs
import java.io.*;
import java.awt.datatransfer.StringSelection;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.util.*;
import java.awt.Desktop;
import java.net.URI;
import javax.crypto.Cipher;
import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.codec.binary.Base64;

public class seeYourPasswords{
	private static final String orgUserName="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";
	private static final String orgPassWord="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";
	private static final String passWordKey = "it6.uJOf@2#MagD%", userNameKey = "hS3s*fU7&dkSp$&5", initVector = "*$SI9!7&yyrUjY@l",fileKey = "N!@&$k9nVLzoQOuW";
	private static String sysName = System.getProperty("user.name");
	public static void main(String[] args) throws Exception {
		ArrayList<String> dns = new ArrayList<String>();
		dns.add(".com");
		dns.add(".org");
		dns.add(".net");
		dns.add(".io");

		Scanner sc = new Scanner(System.in);
		System.out.println("Enter your username");
		String userName = sc.next();
		System.out.println("Enter your password");
		String passWord = sc.next();
		if (hashStrings(userName).equals(orgUserName) && hashStrings(passWord).equals(orgPassWord)) {
			//getting the names of websites whose login credentials are stored
			System.out.println("What do you want to do today?");
			System.out.println("'SYP'- See your saved passwords");
			System.out.println("'CU' - Change the username for a site");
			System.out.println("'CP' - Change the password for a site");
			String response = sc.next();
			if(response.toLowerCase().equals("syp"))
				seeYourPasswords();
			else if(response.toLowerCase().equals("cp"))
				changePassWord();
			else if(response.toLowerCase().equals("cu"))
				changeUserName();
			else
				System.out.println("I dont even know what you are talking about.");
			System.exit(1);
		}
		
		else {
			System.out.println("Username or password wrong, terminating application.");
			System.exit(000);
		}
	}

	public static void seeYourPasswords() throws Exception{
		Scanner sc = new Scanner(System.in);
		System.out.println("Enter your username again: ");
		String userName = sc.next();
		String hashedUserName = hashStrings(userName);
		System.out.println("Enter your password again: ");
		String passWord = sc.next();
		String hashedPassWord = hashStrings(passWord);
		if(hashedPassWord.equals(orgPassWord)&&hashedUserName.equals(orgUserName)) {
			String basePath = "C:\\Users\\"+sysName+"\\Desktop\\OctiaxVault\\src\\base.txt";
			ArrayList<String> fileNames = new ArrayList<String>();
			BufferedReader br = new BufferedReader(new FileReader(basePath));
			String currentLine;
			while ((currentLine = br.readLine()) != null) {
				fileNames.add(fileDecrypt(currentLine));
			}
			System.out.println(fileNames);
			System.out.println("Enter the name of site you want to see the password for: ");
			Scanner s = new Scanner(System.in);
			String sitename = s.nextLine();
			String lowerSiteName = sitename.toLowerCase();
			String actualSiteName = hashStrings(lowerSiteName);
			String path = "C:\\Users\\"+sysName+"\\Desktop\\OctiaxVault\\" + actualSiteName + ".txt";
			String path1 = "C:\\Users\\"+sysName+"\\Desktop\\OctiaxVault\\" + actualSiteName + "(@!0Zk).txt";
			File file = new File(path);
			File nFile = new File(path1);
			ArrayList<String> resultArrayList = new ArrayList<String>();

			if (file.exists()) {
				if (nFile.exists()) {
					System.out.println("Match found, retrieving details....");
					Scanner fileScannerOne = new Scanner(new File(path));
					Scanner fileScannerTwo = new Scanner(new File(path1));
					while (fileScannerOne.hasNext()) {
						resultArrayList.add(fileScannerOne.next());
					}
					while (fileScannerTwo.hasNext()) {
						resultArrayList.add(fileScannerTwo.next());
					}

					String retrievedPassword = resultArrayList.get(0);
					String retrievedUserName = resultArrayList.get(1);
					String resultPassword = passWordDecrypt(retrievedPassword);
					String resultUsername = userNameDecrypt(retrievedUserName);
					System.out.println("Username: " + resultUsername);
					System.out.println("Password: " + resultPassword);
					System.out.println("The password has been copied to your clipboard");
					StringSelection stringSelection = new StringSelection(resultPassword);
					Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
					clipboard.setContents(stringSelection, null);
					String url = "https://www." + sitename + ".com";
					System.out.println("You'll very soon be redirected to " + url);
					if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
						Desktop.getDesktop().browse(new URI(url));
					}

				}
				System.exit(0);
			}
		}
	}

	public static String hashStrings(String tohash) throws Exception {
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(tohash.getBytes());
            byte[] stringHashArray = messageDigest.digest();
            StringBuilder sdbs = new StringBuilder();
            for(byte variable : stringHashArray) {
                sdbs.append(String.format("%02x",variable));
            }

            String result = sdbs.toString();
            return result;
	}

	public static String userNameDecrypt(String encryptedUserName) throws Exception {

			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec uskeySpec = new SecretKeySpec(userNameKey.getBytes("UTF-8"),"AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, uskeySpec, iv);
			byte[] originaluname = cipher.doFinal(Base64.decodeBase64(encryptedUserName));
			return new String(originaluname);
	}

	public static String passWordDecrypt(String encrypted) throws Exception {
        	IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        	SecretKeySpec skeySpec = new SecretKeySpec(passWordKey.getBytes("UTF-8"), "AES");
        	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        	cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        	byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));
        	return new String(original);
    }

	public static String fileDecrypt(String encryptedFile) throws Exception {
		IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
		SecretKeySpec fileKeySpec = new SecretKeySpec(fileKey.getBytes("UTF-8"),"AES");

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, fileKeySpec, iv);
		byte[] originalFileName = cipher.doFinal(Base64.decodeBase64(encryptedFile));
		return new String(originalFileName);
	}

	public static String userNameEncrypt(String toencrypt) throws Exception {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec uskeySpec = new SecretKeySpec(userNameKey.getBytes("UTF-8"),"AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, uskeySpec, iv);

			byte[] encryptedUsername = cipher.doFinal(toencrypt.getBytes());
			return Base64.encodeBase64String(encryptedUsername);

	}

	public static String passWordEncrypt(String value) throws Exception {
		IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
		SecretKeySpec skeySpec = new SecretKeySpec(passWordKey.getBytes("UTF-8"), "AES");

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

		byte[] encryptedPassword = cipher.doFinal(value.getBytes());
		return Base64.encodeBase64String(encryptedPassword);
	}

	public static void changeUserName() throws Exception {
		Scanner sc = new Scanner(System.in);
		System.out.println("Enter the name of the site you want to change the username for: ");
		String ogSiteName = sc.nextLine();
		String hashSiteName = hashStrings(ogSiteName);
		String path = "C://Users//"+sysName+"//Desktop//OctiaxVault//"+hashSiteName+"(@!0Zk).txt";
		File file = new File(path);
		if(file.exists()) {
			System.out.println("File found");
			Scanner fileReader = new Scanner(file);
			while(fileReader.hasNextLine()) {
				Scanner s = new Scanner(System.in);
				System.out.println("Original Username: "+userNameDecrypt(fileReader.nextLine()));
				System.out.println("ARE YOU SURE YOU WANT TO CHANGE THE USERNAME OF "+ogSiteName+"?(Y/N)");
				String response = s.next();
				if(response.toLowerCase().equals("y")) {
					Scanner scan = new Scanner(System.in);
					System.out.println("Enter the new username for "+ogSiteName);
					String newUserName = scan.nextLine();
					FileWriter fw = new FileWriter(file);
					fw.write(userNameEncrypt(newUserName));
					fw.close();
					System.out.println("Username changed succesfully! ");
				}
			}
			System.exit(0);
		}
	}

	public static void changePassWord() throws Exception {
		Scanner sc = new Scanner(System.in);
		System.out.println("Enter the name of the site you want to change the password for: ");
		String ogSiteName = sc.nextLine();
		String hashSiteName = hashStrings(ogSiteName);
		String path = "C://Users//"+sysName+"//Desktop//OctiaxVault//"+hashSiteName+".txt";
		File file = new File(path);
		if(file.exists()) {
			System.out.println("File found");
			Scanner fileReader = new Scanner(file);
			while(fileReader.hasNext()) {
				Scanner s = new Scanner(System.in);
				System.out.println("Original Password: "+passWordDecrypt(fileReader.nextLine()));
				System.out.println("ARE YOU SURE YOU WANT TO CHANGE THE PASSWORD FOR "+ogSiteName+"?(Y/N)");
				String response = s.next();
				if(response.toLowerCase().equals("y")) {
					System.out.println("Enter the new password for "+ogSiteName);
					String newPassWord = s.next();
					FileWriter fw = new FileWriter(file);
					fw.write(passWordEncrypt(newPassWord));
					fw.close();
					System.out.println("Password changed succesfully! ");
				}
			}
		}
	}
}
