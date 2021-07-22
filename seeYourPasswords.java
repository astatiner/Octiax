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

public class seeYourPasswords
{
	private static final String passWordKey = "it6.uJOf@2#MagD%", userNameKey = "hS3s*fU7&dkSp$&5", initVector = "*$SI9!7&yyrUjY@l",fileKey = "N!@&$k9nVLzoQOuW";
	private static String sysName = System.getProperty("user.name");
	public static void main(String[] args) throws Exception {
		ArrayList<String> dns = new ArrayList<String>();
		dns.add(".com");
		dns.add(".org");
		dns.add(".net");
		dns.add(".io");
		String orgUserName = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";
		String orgPassWord = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";
		Scanner sc = new Scanner(System.in);
		System.out.println("Enter your username");
		String userName = sc.nextLine();
		System.out.println("Enter your password");
		String passWord = sc.nextLine();
		if (hashStrings(userName).equals(orgUserName) && hashStrings(passWord).equals(orgPassWord)) {
			//getting the names of websites whose login credentials are stored

			String basePath = "C:\\Users\\"+sysName+"\\Desktop\\OctiaxVault\\src\\base.txt";
			ArrayList<String> fileNames = new ArrayList<String>();
			BufferedReader br = new BufferedReader(new FileReader(basePath));
			String currentLine;
			while ((currentLine = br.readLine()) != null) {
				fileNames.add(fileDecrypt(currentLine));
			}
			System.out.println(fileNames);

			//inputting the name of the website whose password the user wants to see
			System.out.println("Enter the name of site you want to see the password for: ");
			String sitename = sc.nextLine();
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

					String retreievedPassword = resultArrayList.get(0);
					String retreievedUserName = resultArrayList.get(1);
					String resultPassword = passWordDecrypt(retreievedPassword);
					String resultUsername = userNameDecrypt(retreievedUserName);
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
		
		else {
			System.out.println("Username or password wrong, terminating application.");
			System.exit(000);
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
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec uskeySpec = new SecretKeySpec(userNameKey.getBytes("UTF-8"),"AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, uskeySpec, iv);

			byte[] encryptedUsername = cipher.doFinal(toencrypt.getBytes());
			return Base64.encodeBase64String(encryptedUsername);
		}

		catch(Exception exc) {
			exc.printStackTrace();
		}
		return null;
	}

	public static void changeUserName() throws Exception {
		Scanner sc = new Scanner(System.in);
		System.out.println("Enter the name of the site you want to change the username or password for: ");
		String ogSiteName = sc.nextLine();
		String hashSiteName = hashStrings(ogSiteName);
		System.out.println(hashSiteName);
		String path = "C://Users//"+sysName+"//Desktop//OctiaxVault//"+hashSiteName+"(@!0Zk).txt";
		File file = new File(path);
		if(file.exists()) {
			System.out.println("File found");
			Scanner fileReader = new Scanner(file);
			while(fileReader.hasNextLine()) {
				Scanner s = new Scanner(System.in);
				System.out.println("Original Username: "+userNameDecrypt(fileReader.nextLine()));
				System.out.println("ARE YOU SURE YOU WANT TO CHANGE THE USERNAME OF "+ogSiteName+"?(Y/N)");
				String response = s.nextLine();
				if(response.toLowerCase().equals("y")) {
					System.out.println("Enter the new username for "+ogSiteName);
					String newUserName = s.nextLine();
					FileWriter fw = new FileWriter(file);
					fw.write(userNameEncrypt(newUserName));
					fw.close();
					System.out.println("Username changed succesfully! ");
				}
			}
			System.exit(0);
		}
	}
}
