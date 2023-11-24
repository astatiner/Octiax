/*
Octiax Password Manager
Sample Username: admin
Sample Password: admin
*/
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.swing.*;
import java.awt.event.*;
import java.util.regex.*;
import javax.imageio.ImageIO;
import java.awt.Desktop;
import org.apache.commons.codec.binary.Base64;
import java.security.MessageDigest;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


class Main  implements ActionListener {
	//Initialization of components of UI and variables.
	private static final String masterUserName= "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";
	private static final String masterPassword = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";
	//I have got to change this and fetch the passwords from somewhere instead of putting it in the code. LMAO!
	private static String path;
	private static String gen_captcha="";
	private static final String passWordKey = "E9*&gX@#Z93liFM#",fileKey = "fU&9H5#1UntY3Y!B",userNameKey = "Br8!0Zc#39P7c@#b", initVector = "V&&K$f7pT9mV/6gY";
	private static int tempvar=0,sample=0,tempex=0,sampsucvar=0,integer=0,blankFieldVar=0,loginFailureVar=0,failvar=0,sypBlankFieldVar=0,setvis=0;
	private static JPanel panel,loginPanel,confirmationPanel,syPanel;
	private static JLabel loginFailure,sypBlankField,blankField,pwdnotsaved,genpwd,pwdsaved,displayCaptcha,sampsuc,SYPfailure,uNameLabel,pWordLabel,hogaya,empty;
	private static JPasswordField passwordText,MPasswordField,loginPassWordField;
	private static JTextField captchaField,loginUserNameField,siteText,usernameText,siteNameField;
	private static JButton SAVE,gap,SYP,SAVE1,GO,loginButton,signUpButton,GO2;
	private static JFrame frame,confirmationFrame,loginFrame;

	 public static void main(String[] args) throws Exception {
	 	Date date = new Date();
	 	System.out.println(System.getProperty("os.name")+" "+" local date-time: "+ date);
	 	path = "C://";

	    loginFrame = new JFrame("Login to Octiax");
	    loginFrame.setIconImage(ImageIO.read(new File("C://Octiax//logo.png")));
		 JLabel loginUserName = new JLabel("Enter your username: ");
		 JLabel loginPassWord = new JLabel("Enter your password: ");
	 	loginUserNameField = new JTextField();
	 	loginPassWordField = new JPasswordField();
	 	loginPanel = new JPanel();
	 	loginButton = new JButton("LOGIN");
	 	signUpButton = new JButton("SIGN UP");
	 	loginPanel.setLayout(null);
	 	loginFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	 	loginFrame.setSize(450,400);
	 	loginUserName.setBounds(10,10,150,30);
	 	loginPassWord.setBounds(10,40,150,30);
	 	loginUserNameField.setBounds(165,10,140,25);
	 	loginPassWordField.setBounds(165,40,140,25);
	 	loginButton.setBounds(10,75,80,25);

	 	signUpButton.setBounds(10,115,100,25);
	 	loginButton.addActionListener(new Main());
	 	signUpButton.addActionListener(new Main());
	 	loginPanel.add(loginUserNameField);
	 	loginPanel.add(loginPassWordField);
		loginPanel.add(loginUserName);
		loginPanel.add(loginPassWord);
		loginPanel.add(loginButton);
		loginPanel.add(signUpButton);
		loginFrame.add(loginPanel);
	 	loginFrame.setVisible(true);
	 	loginFrame.setResizable(false);
	}

	
	public void actionPerformed(ActionEvent e) {
		if(e.getSource()==loginButton) {
			if(loginFailureVar>0) {
				loginFailure.setVisible(false);
				loginFailureVar--;
			}

			if(blankFieldVar>0) {
				blankField.setVisible(false);
				blankFieldVar--;
			}

			String loginUserNameText = loginUserNameField.getText();
			char [] loginPassWordChar = loginPassWordField.getPassword();
			String loginPassWordText = new String(loginPassWordChar);

			if(loginPassWordText.trim().equals("")|| loginUserNameText.trim().equals("")) {
				blankField = new JLabel("Please don't leave any field blank, try again.");
				blankFieldVar++;
				loginPanel.add(blankField);
				blankField.setBounds(10,140,250,25);
			}

			else {
				try {
					if (hashStrings(loginUserNameText).equals(masterUserName)&&hashStrings(loginPassWordText).equals(masterPassword)) {
						mainWindow();
					}
					else {
						loginFailure = new JLabel("Wrong username or password.");
						loginFailureVar++;
						loginPanel.add(loginFailure);
						loginFailure.setBounds(10,140,250,25);
					}
				}

				catch (Exception loginException) {
					loginException.printStackTrace();
				}
			}
		}

		if(e.getSource()==signUpButton) {
			signUp();
		}

		String siteName;
		String userName;
		String basepath;
		String password1;
		String siteNameDef;
		if(e.getSource()==SAVE) {

			//Condition where the user is entering his/her own password.
			char[] passchar;
			siteNameDef = siteText.getText();
			siteName = siteNameDef.toLowerCase();
			passchar = passwordText.getPassword();
			userName = usernameText.getText();
			password1 = new String(passchar);
			basepath = "C://OctiaxVault//src//base.txt";
			if(userName.trim().equals("")|| siteName.trim().equals("")|| password1.trim().equals("")) {
					//This block of code runs when the user has left any of the three fields: username, sitename or password blank.
					if(tempvar>0) {
						pwdsaved.setVisible(false);
						tempvar--;
					}

					if(sample>0) {
						pwdnotsaved.setVisible(false);
						sample--;
					}

					if(tempex>0) {
						genpwd.setVisible(false);
						tempex--;
					}

					if(sampsucvar>0) {
						sampsuc.setVisible(false);
						sampsucvar--;
					}

					pwdnotsaved = new JLabel("Please don't leave any field blank. Try again.");
					sample++;
					gap.setBounds(10,200,300,25);
					gap.addActionListener(new Main());
					panel.add(pwdnotsaved);
					pwdnotsaved.setBounds(10,140,280,25);

				}

				else {
					char[] passwordarr;
					siteNameDef = siteText.getText();
					siteName = siteNameDef.toLowerCase();
					passwordarr = passwordText.getPassword();
					userName = usernameText.getText();
					password1 = new String(passwordarr);
					try {
							try {

								String siteNameRes = hashStrings(siteName);
								System.out.println(siteNameRes);
        						FileWriter fw = new FileWriter("C://OctiaxVault//"+ siteNameRes +".txt");
								FileWriter fwr = new FileWriter("C://OctiaxVault//"+ siteNameRes +"(@!0Zk).txt");
								fw.write(Objects.requireNonNull(passWordEncrypt(password1)));
								fw.close();

								fwr.write(userNameEncrypt(userName));
								fwr.close();

								if(tempvar>0) {
									pwdsaved.setVisible(false);
									tempvar--;
								}

								if(sample>0) {
									pwdnotsaved.setVisible(false);
									sample--;
								}

								if(tempex>0) {
									genpwd.setVisible(false);
									tempex--;
								}

								if(sampsucvar>0) {
									sampsuc.setVisible(false);
									sampsucvar--;
								}

								pwdsaved = new JLabel("Password saved successfully!");
								tempvar++;
								try {
									FileWriter fileStream = new FileWriter(basepath, true);
									BufferedWriter outWriter = new BufferedWriter(fileStream);
									outWriter.write(fileEncrypt(siteName)+"\n");
									outWriter.close();
								}
								catch(Exception filex) {
									filex.printStackTrace();
								}
								panel.add(pwdsaved);
								siteText.setText("");
        						passwordText.setText("");
        						usernameText.setText("");
								gap.setVisible(true);
								gap.setBounds(10,170,300,25);
								pwdsaved.setBounds(10,140,180,25);
				
							}

							catch(Exception ex) {
								System.out.println("An error occured.");
								ex.printStackTrace();
							}
			
					}

					catch(Exception a) {
							a.printStackTrace();
					}
				}
		}

		if(e.getSource()==gap) {

			if(sample>0) {
				pwdnotsaved.setVisible(false);
				sample--;
			}

			if(tempvar>0) {
				pwdsaved.setVisible(false);
				tempvar--;
			}

			if(tempex>0) {
				genpwd.setVisible(false);
				tempex--;
			}
						
			if(sampsucvar>0) {
				sampsuc.setVisible(false);
				sampsucvar--;
			}
					    

            String regex = "^(?=.*[0-9])"
                         + "(?=.*[a-z])(?=.*[A-Z])"
                         + "(?=.*[@#$%^&+!=])"
                         + "(?=\\S+$).{8,20}$";

            Pattern pattern = Pattern.compile(regex);

			SAVE.setVisible(false);
			gap.setVisible(false);
			new StringBuilder();
			StringBuilder generated_password;
			for(;;) {
			int length,temp;
			generated_password = new StringBuilder();
			Random  rd = new Random();
			String [] characters = {"D","w","8","!","3","A","T","a","@","7","c","1","r","$","I","6","#","B","m","F","C","l","5","H","v","&","L","Y","2","t","%","6","E","i","W","P","z","d","4","&","M","s","Z","g","S","O","q","N","V","K","*","G","b","n","Q","u","y","j","0","X","u","R","p","x","J","o","e","U","9","h","f","k"};
			length = characters.length;
			System.out.println("L"+length);
			int password_length=rd.nextInt(4)+16;

			for(int ex=1;ex<=password_length;ex++) {
				temp = rd.nextInt(length);
				String generated_string = characters[temp];
				generated_password.append(generated_string);
			}
            
            	Matcher matcher = pattern.matcher(generated_password.toString());
            	boolean exp = matcher.matches();
                if(exp) {
                    break;
                }
                else {
					System.out.println("Password not upto the mark, generating another, stronger password.");
				}
        }       
			genpwd = new JLabel("Generated Password: "+ generated_password);
			System.out.println(generated_password);
			System.out.println("The password has been copied to your clipboard.");
			copyString(generated_password.toString());
			tempex++;
			panel.add(SAVE1);
			SAVE1.setVisible(true);
        	SAVE1.setBounds(10,200,80,25);
			panel.add(genpwd);
			genpwd.setBounds(10,110,280,25);
			integer++;
			passwordText.setText(generated_password.toString());
			passwordText.setEditable(false);

		}

		if(e.getSource()==SAVE1) {
			char[] passwordarray;
			siteNameDef = siteText.getText();
            siteName = siteNameDef.toLowerCase();
            passwordarray = passwordText.getPassword();
			userName = usernameText.getText();
			password1 = new String(passwordarray);
			basepath = "C://OctiaxVault//src//base.txt";
			if(userName.trim().equals("")|| siteName.trim().equals("")) {

				if(integer>0)
				{
					genpwd.setBounds(10,170,300,25);
					integer--;
				}

				if(tempvar>0) {
					pwdsaved.setVisible(false);
					tempvar--;
				}

				if(sample>0) {
					pwdnotsaved.setVisible(false);
					sample--;
				}
				
				if(sampsucvar>0) {
					sampsuc.setVisible(false);
					sampsucvar--;
				}

				pwdnotsaved = new JLabel("Please don't leave any field blank. Try again.");
				sample++;
				panel.add(pwdnotsaved);
				pwdnotsaved.setBounds(10,140,280,25);

			}

			else {
				try {
					try {
						if (sample>0) {
							pwdnotsaved.setVisible(false);
							sample--;
						}

						if(tempvar>0)
							pwdsaved.setVisible(false);
								
        				System.out.println("AES-128 Encrypted password: "+passWordEncrypt(password1));
        				String siteNameResTwo;
        				siteNameResTwo = hashStrings(siteName);
        				FileWriter fwrr = new FileWriter("C://OctiaxVault//"+siteNameResTwo+"(@!0Zk).txt");
        				FileWriter newfwr = new FileWriter("C://OctiaxVault//"+siteNameResTwo+".txt");
        				fwrr.write(userNameEncrypt(userName));
        				newfwr.write(passWordEncrypt(password1));
        				fwrr.close();
        				newfwr.close();
        				sampsuc = new JLabel("Password saved successsfully!");
						try {
							FileWriter fileStreamGap = new FileWriter(basepath, true);
							BufferedWriter outWriter = new BufferedWriter(fileStreamGap);
							outWriter.write(fileEncrypt(siteName)+"\n");
							outWriter.close();
						}
						catch (Exception baseWriteExcept) {
							baseWriteExcept.printStackTrace();
						}
        				sampsuc.setBounds(10,170,280,25);
        				sampsucvar++;
        				passwordText.setEditable(true);
        				panel.add(sampsuc);
             			siteText.setText("");
        				passwordText.setText("");
        				usernameText.setText("");
        				gap.setVisible(true);
        						
        				genpwd.setVisible(false);

        				SAVE1.setVisible(false);
        				SAVE.setVisible(true);
        			}

        			catch(Exception soy) {
        				soy.printStackTrace();
        			}
                }

				catch(Exception except) {
					except.printStackTrace();
				}
			}
        		
        }

        if(e.getSource()==SYP) {
        	//This block of code runs when the user wants to see passwords saved.
			frame.setVisible(false);
			confirmationFrame = new JFrame("Confirm your login details");
			try {
				confirmationFrame.setIconImage(ImageIO.read(new File("C://Octiax//logo.png")));
			} catch (IOException ex) {
				throw new RuntimeException(ex);
			}
			confirmationPanel = new JPanel();
			confirmationPanel.setLayout(null);
        	confirmationFrame.setSize(550,350);
			JLabel confirmation = new JLabel("We need to make sure it's you, please fill the following details.");
        	gen_captcha = generateCaptcha("");
			JLabel captcha = new JLabel("Enter the CAPTCHA you see below: ");
       		displayCaptcha = new JLabel("CAPTCHA: "+gen_captcha);
			JLabel MPassword = new JLabel("Enter your master password: ");
       		captchaField = new JTextField();
       		MPasswordField = new JPasswordField();
       		GO = new JButton("GO");
			confirmation.setBounds(10,10,500,40);
			captcha.setBounds(10,50,200,25);
			displayCaptcha.setBounds(10,80,130,35);
			MPassword.setBounds(10,120,180,25);
			captchaField.setBounds(210,50,100,25);
			MPasswordField.setBounds(210,120,170,25);
			GO.setBounds(10,155,80,25);
			GO.addActionListener(new Main());
			confirmationFrame.add(confirmationPanel);
       		confirmationPanel.add(MPasswordField);
       		confirmationPanel.add(MPassword);
       		confirmationPanel.add(captchaField);
       		confirmationPanel.add(displayCaptcha);
       		confirmationPanel.add(confirmation);
       		confirmationPanel.add(captcha);
       		confirmationPanel.add(GO);
			confirmationFrame.setVisible(true);
        }

        if(e.getSource()==GO) {
				char[] mpasswordarray;
				mpasswordarray = MPasswordField.getPassword();
				String mpassWordString = new String(mpasswordarray);
				String captchaString = captchaField.getText();
				try {
					boolean captchaBool = captchaString.trim().equals("");
					boolean passBool = mpassWordString.trim().equals("");
					if (!passBool && !captchaBool) {
						boolean passCheck = hashStrings(mpassWordString).equals(masterPassword);
						boolean captchaCheck = captchaString.equals(gen_captcha);
						if (failvar > 0) {
							SYPfailure.setVisible(false);
							failvar--;
						}
						if (passCheck && captchaCheck) {
							System.out.println("Access Granted");
							JLabel SYPsuccess = new JLabel("Right credentials! You'll be redirected to your saved passwords' window in a few seconds.");
							confirmationPanel.add(SYPsuccess);
							confirmationFrame.setVisible(false);
							seePassWordsWindow();
						} else {

							if (sypBlankFieldVar > 0) {
								sypBlankField.setVisible(false);
							}
							gen_captcha = generateCaptcha("");
							displayCaptcha.setText("CAPTCHA:" + gen_captcha);
							System.out.println("Access Denied");
							SYPfailure = new JLabel("Wrong credentials, please try again");
							confirmationPanel.add(SYPfailure);
							SYPfailure.setBounds(10, 185, 520, 25);
							failvar++;
						}
					} else {

						if (failvar > 0) {
							SYPfailure.setVisible(false);
							failvar--;
						}

						if (sypBlankFieldVar > 0) {
							sypBlankField.setVisible(false);
						}

						sypBlankField = new JLabel("Please don't leave any field blank, try again");
						confirmationPanel.add(sypBlankField);
						sypBlankField.setBounds(10, 185, 520, 25);
						sypBlankFieldVar++;
					}
				} catch (Exception hashexception) {
					hashexception.printStackTrace();
				}
			}
		if(e.getSource()==GO2) {
			try {
				if(setvis>0){
					syPanel.remove(uNameLabel);
					syPanel.remove(hogaya);
					setvis--;
				}
				String sNameText = siteNameField.getText().trim();
				if(sNameText.trim().equals("")){
					empty=new JLabel("You cannot leave that field empty.");
					empty.setBounds(10,100,350,25);
				}
				//This entire process here fetches the username and password for us.
				String actualSiteName = hashStrings(sNameText);
				String path = "C:\\OctiaxVault\\" + actualSiteName + ".txt";
				String path1 = "C:\\OctiaxVault\\" + actualSiteName + "(@!0Zk).txt";
				File file = new File(path);
				File nFile = new File(path1);
				String resultUsername="", resultPassword="";
				ArrayList<String> resultArrayList = new ArrayList<>();
				if (file.exists()) {
					if (nFile.exists()) {
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
						resultPassword = passWordDecrypt(retrievedPassword);
						resultUsername = userNameDecrypt(retrievedUserName);
					}
				}
				uNameLabel=new JLabel("Username: "+resultUsername);
				syPanel.add(uNameLabel);
				uNameLabel.setBounds(10,100,300,25);
				//pWordLabel=new JLabel("Password: "+resultPassword);
				//syPanel.add(pWordLabel);
				//pWordLabel.setBounds(10,130,300,25);
				setvis++;
				copyString(resultPassword);
				hogaya=new JLabel("Your password has been copied to your clipboard. Soon, you will redirected to "+ sNameText +".com");
				syPanel.add(hogaya);
				hogaya.setBounds(10,130,600,25);
				redirect(sNameText);
			}
			catch(Exception exception1){
						exception1.printStackTrace();
					}
				}
			}

	public static String passWordEncrypt(String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec skeySpec = new SecretKeySpec(passWordKey.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encryptedPassword = cipher.doFinal(value.getBytes());
            return Base64.encodeBase64String(encryptedPassword);
        } 	

        catch (Exception ex) {
           	 ex.printStackTrace();
        }

        return null;
    }

    public static String userNameEncrypt (String toencrypt) throws Exception {
    		IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
    		SecretKeySpec uskeySpec = new SecretKeySpec(userNameKey.getBytes(StandardCharsets.UTF_8),"AES");

    		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    		cipher.init(Cipher.ENCRYPT_MODE, uskeySpec, iv);

    		byte[] encryptedUsername = cipher.doFinal(toencrypt.getBytes());
    		return Base64.encodeBase64String(encryptedUsername);
    }

    public static String passWordDecrypt(String encrypted) {
    	try {
        	IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
        	SecretKeySpec skeySpec = new SecretKeySpec(passWordKey.getBytes(StandardCharsets.UTF_8), "AES");
 
        	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        	cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        	byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));
 
        	return new String(original);
    	} 

    	catch (Exception ex) {
        	ex.printStackTrace();
    	}
 
    	return null;
	}

	public static String userNameDecrypt(String encryptedUserName) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
			SecretKeySpec uskeySpec = new SecretKeySpec(userNameKey.getBytes(StandardCharsets.UTF_8),"AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, uskeySpec, iv);
			byte[] originaluname = cipher.doFinal(Base64.decodeBase64(encryptedUserName));
			return new String(originaluname);
		}

		catch(Exception decexcept) {
			decexcept.printStackTrace();
		}

		return null;
	}

	public static String hashStrings(String tohash) throws Exception {
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(tohash.getBytes());
            byte[] stringHashArray = messageDigest.digest();
            StringBuilder sdbs = new StringBuilder();
            for(byte variable : stringHashArray) {
                sdbs.append(String.format("%02x",variable));
            }

		return sdbs.toString();
	}

	public static String encryptStrings(String toencrypt) {
		StringBuilder strEncryptKey = new StringBuilder();
		String randomStr;
		int randomStrNo;
		Random random =  new Random();
		String [] characterArray =  {"D","w","8","-","!","3","A","T","a","@","7","c","1","r","$","I","6","#","B","m","F","C","l","5","H","v","&","L","Y","2","t","%","6","E","i","W","P","z","d","4","&","M","s","Z","g","+","=","S","O","q","N","V","K","*","G","b","n","Q","u","y","j","0","X","u","R","p","x","J","o","e","U","9","h","f","k"};
		for(int i=0;i<16;i++) {
			randomStrNo = random.nextInt(characterArray.length-1);
			randomStr = characterArray[randomStrNo];
			strEncryptKey.append(randomStr);
		}
		System.out.println(strEncryptKey);
		return null;
	}

	public static String fileEncrypt(String plain) throws Exception {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
    		SecretKeySpec sitekeySpec = new SecretKeySpec(fileKey.getBytes(StandardCharsets.UTF_8),"AES");

    		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    		cipher.init(Cipher.ENCRYPT_MODE, sitekeySpec, iv);

    		byte[] encryptedFileText = cipher.doFinal(plain.getBytes());
    		return Base64.encodeBase64String(encryptedFileText);
	}

	public static String fileDecrypt(String encryptedFile) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec fileKeySpec = new SecretKeySpec(fileKey.getBytes(StandardCharsets.UTF_8),"AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, fileKeySpec, iv);
        byte[] originalFileName = cipher.doFinal(Base64.decodeBase64(encryptedFile));
        return new String(originalFileName);
    }

    public static void signUp() {
		loginFrame.setVisible(false);
		JFrame signUpFrame = new JFrame("Sign Up to Octiax");
		signUpFrame.setSize(500,450);

		JPanel SUPanel = new JPanel();
		SUPanel.setLayout(null);
		JLabel emailLabelSU = new JLabel("Email: ");
		JLabel userNameLabelSU = new JLabel("Set a username: ");
		JLabel passWordLabelSU = new JLabel("Set a master password:");
		emailLabelSU.setBounds(10,10,120,25);
		userNameLabelSU.setBounds(10,35,120,25);
		passWordLabelSU.setBounds(10,60,170,25);
		SUPanel.add(emailLabelSU);
		SUPanel.add(userNameLabelSU);
		SUPanel.add(passWordLabelSU);
		signUpFrame.add(SUPanel);
		signUpFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		signUpFrame.setVisible(true);
	}

	public static void mainWindow() {
		loginFrame.setVisible(false);
		try {
			String nameoffolder = "OctiaxVault";
			path = path+nameoffolder;
			File file = new File(path);
			if(file.exists()&&file.isDirectory()) {
				System.out.println("Folder exists");
			}
			else {
				boolean bool = file.mkdir();
				if(bool) {
					System.out.println("Folder created");

					//Creating the base file
					String basefilepath = "C://OctiaxVault//src//base.txt";
					File basefile = new File(basefilepath);
					if(basefile.exists()) {
						System.out.println("Base file exists.");
					}

					else {
							basefile.createNewFile();
						System.out.println("Base file created.");
					}
				}
				else {
					System.out.println("An error occurred!");
				}
			}
		}
		catch(Exception dircrex) {
			dircrex.printStackTrace();
		}

		//Defining components of UI.
		frame = new JFrame("Octiax Password Manager");
		frame.setSize(450,450);
		frame.setResizable(false);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		panel = new JPanel();
		frame.add(panel);
		panel.setLayout(null);

		JLabel siteLabel = new JLabel("Site Name: ");
		siteLabel.setBounds(10, 20, 80, 25);
		panel.add(siteLabel);
		siteText = new JTextField(100);
		siteText.setBounds(100,20,165,25);
		panel.add(siteText);

		JLabel usernameLabel = new JLabel("Username: ");
		usernameLabel.setBounds(10, 50, 80, 25);
		panel.add(usernameLabel);
		usernameText = new JTextField(45);
		usernameText.setBounds(100,50,165,25);
		panel.add(usernameText);

		JLabel passwordLabel = new JLabel("Password:");
		passwordLabel.setBounds(10,80,90,25);
		panel.add(passwordLabel);
		passwordText = new JPasswordField(40);
		passwordText.setBounds(100,80,165,25);
		panel.add(passwordText);

		SAVE = new JButton("SAVE");
		SAVE.setBounds(10,110,80,25);
		SAVE.addActionListener(new Main());
		panel.add(SAVE);

		gap = new JButton("OR CLICK HERE FOR A STRONG PASSWORD");
		gap.setBounds(10,140,300,25);
		gap.addActionListener(new Main());
		panel.add(gap);

		SAVE1 = new JButton("SAVE");
		SAVE1.setBounds(10,140,80,25);
		SAVE1.addActionListener(new Main());

		SYP = new JButton("SEE YOUR PASSWORDS");
		SYP.setBounds(10,270,180,25);
		SYP.addActionListener(new Main());
		panel.add(SYP);



		//Setting the logo of the application
		try {
			frame.setIconImage(ImageIO.read(new File("C://Octiax//logo.png")));
			frame.setVisible(true);
		}

		catch(Exception imgEx) {
			imgEx.printStackTrace();
		}
	}

	public static String generateCaptcha(String togen) {
		StringBuilder togenBuilder = new StringBuilder(togen);
		for(int i = 1; i<=5; i++) {
				String [] captchaCharacters = {"D","w","8","!","3","A","T","a","@","7","c","1","r","$","6","#","B","m","F","C","5","H","v","&","L","Y","2","t","%","6","E","i","W","P","z","d","4","&","M","s","Z","g","S","q","N","V","K","*","G","b","n","Q","u","y","j","X","u","R","p","x","J","o","e","U","9","h","f","k"};
				Random rand = new Random();
				int index = rand.nextInt(captchaCharacters.length-1);
				togenBuilder.append(captchaCharacters[index]);
			}
		togen = togenBuilder.toString();

		return togen;
	}

	public void seePassWordsWindow() throws IOException {
		ArrayList<String> fileNames = new ArrayList<>();
		try {
			String basePath = "C://OctiaxVault//src//base.txt";
			BufferedReader br = new BufferedReader(new FileReader(basePath));
			String currentLine;
			while ((currentLine = br.readLine()) != null) {
				fileNames.add(fileDecrypt(currentLine));
			}
		}
		catch (Exception someshit) {
			someshit.printStackTrace();
		}
		JFrame sypFrame = new JFrame("Octiax: Saved Passwords");
			sypFrame.setSize(69*fileNames.size(),500);
			sypFrame.setIconImage(ImageIO.read(new File("C://Octiax//logo.png")));
			sypFrame.repaint();
			syPanel = new JPanel();
			sypFrame.add(syPanel);
			syPanel.setLayout(null);
			JLabel someLabel = new JLabel("Passwords saved for sites: "+fileNames);
			syPanel.add(someLabel);
			someLabel.setBounds(10,10,69*fileNames.size(),25);
			sypFrame.setVisible(true);
			sypFrame.setResizable(false);
			myPasswords();
	}
	public void myPasswords() {
        JLabel newlabel = new JLabel("Enter the name of the site you want to see the password for: ");
        syPanel.add(newlabel);
		newlabel.setBounds(10,40,450,25);
		siteNameField = new JTextField(100);
		siteNameField.setBounds(360,40,300,25);
		GO2=new JButton("GO");
		GO2.setBounds(10,70,80,25);
		GO2.addActionListener(new Main());
		syPanel.add(siteNameField);
		syPanel.add(GO2);
	}

	public void copyString(String toCopy){
		StringSelection stringSelection = new StringSelection(toCopy);
		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		clipboard.setContents(stringSelection, null);
	}
	public void redirect(String sitename) throws Exception{
		String url = "https://www." + sitename.trim() + ".com";
		if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
			Desktop.getDesktop().browse(new URI(url));
		}
	}
}
