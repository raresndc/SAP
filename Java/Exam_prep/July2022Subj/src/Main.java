import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Arrays;

public class Main {
    public static String getHexString(byte[] value) {
        StringBuilder result = new StringBuilder();
        result.append("0x");
        for(byte b : value) {
            result.append(String.format(" %02X", b));
        }
        return result.toString();
    }

    public static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static byte[] getFileHmac(
            String filename, String secret, String algorithm)
            throws NoSuchAlgorithmException, InvalidKeyException, IOException {

        File file = new File(filename);
        if(!file.exists()) {
            throw new UnsupportedOperationException("Missing file");
        }

        FileInputStream fis = new FileInputStream(file);
        BufferedInputStream bis = new BufferedInputStream(fis);
        //ONLY THE FIRST LINE
        BufferedReader reader = new BufferedReader(new InputStreamReader(bis));

        Mac hmac = Mac.getInstance(algorithm);
        Key hmacKey = new SecretKeySpec(secret.getBytes(), algorithm);
        hmac.init(hmacKey);

        String firstLine = reader.readLine();

        byte[] buffer = firstLine.getBytes();
        hmac.update(buffer, 0, buffer.length);

        reader.close();
        bis.close();

        return hmac.doFinal();

    }

    public static byte[] getHash(String input, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(input.getBytes());
    }

    public static void decrypt(
            String filename,
            String outputFile,
            byte[] password,
            String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {


        //IV the cipher file at the beginning

        File inputFile = new File(filename);
        if(!inputFile.exists()) {
            throw new UnsupportedOperationException("Missing file");
        }
        File outFile = new File(outputFile);
        if(!outFile.exists()) {
            outFile.createNewFile();
        }

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(outFile);

        Cipher cipher = Cipher.getInstance(algorithm + "/CTR/NoPadding");

        //getting the IV from the file
        byte[] IV = new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,51};

        SecretKeySpec key = new SecretKeySpec(password, algorithm);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] buffer = new byte[cipher.getBlockSize()];
        int noBytes = 0;

        while(true) {
            noBytes = fis.read(buffer);
            if(noBytes == -1) {
                break;
            }
            byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
            fos.write(cipherBlock);
        }
        byte[] lastBlock = cipher.doFinal();
        fos.write(lastBlock);

        fis.close();
        fos.close();
    }

    public static void encrypt(
            String filename, String cipherFilename, byte[] password, String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        File inputFile = new File(filename);
        if(!inputFile.exists()) {
            throw new UnsupportedOperationException("Missing file");
        }
        File cipherFile = new File(cipherFilename);
        if(!cipherFile.exists()) {
            cipherFile.createNewFile();
        }

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(cipherFile);

        Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(password, algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] buffer = new byte[cipher.getBlockSize()];
        int noBytes = 0;

        while(true) {
            noBytes = fis.read(buffer);
            if(noBytes == -1) {
                break;
            }
            byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
            fos.write(cipherBlock);
        }
        //get the last ciphertext block
        byte[] lastBlock = cipher.doFinal();
        fos.write(lastBlock);

        fis.close();
        fos.close();
    }

    public static void decryptECB(
            String filename, String outputFilename, byte[] password, String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        File inputFile = new File(filename);
        if(!inputFile.exists()) {
            throw new UnsupportedOperationException("Missing file");
        }
        File cipherFile = new File(outputFilename);
        if(!cipherFile.exists()) {
            cipherFile.createNewFile();
        }

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(cipherFile);

        Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(password, algorithm);

        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] buffer = new byte[cipher.getBlockSize()];
        int noBytes = 0;

        while(true) {
            noBytes = fis.read(buffer);
            if(noBytes == -1) {
                break;
            }
            byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
            fos.write(cipherBlock);
        }
        //get the last ciphertext block
        byte[] lastBlock = cipher.doFinal();
        fos.write(lastBlock);

        fis.close();
        fos.close();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        //take the first one into consideration
        String clue = "c1779745da19a6de1795cfcc5cd10f8a8d4ec93be1e27013ffb668a2dcbf7a3d";
        byte[] clueBytes = hexStringToByteArray(clue);
        String result = "377";
        byte[] key = new byte[0];

        File directory = new File("Messages");
        if(!directory.isDirectory()) {
            throw new RuntimeException("DIRECTORY isn t there!");
        } else {
            for (File file : directory.listFiles()) {
                byte[] hmacValue = getFileHmac(
                        file.getAbsolutePath(), "ismsecret", "HmacSHA256");

                if(Arrays.equals(hmacValue, clueBytes)) {
                    System.out.println("File is: " + file.getName());

                    key = getHash(result, "MD5");
                    System.out.println("\nHash is: " + getHexString(getHash(result, "MD5")));
                    break;
                }
            }
        }

        File qDirectory = new File("Questions");
        if(!qDirectory.isDirectory()) {
            throw new RuntimeException("DIRECTORY isn t there!");
        } else {
            for(File file : qDirectory.listFiles()) {
                if(file.getName().equals("Question_696.enc")) {
                    decrypt(file.getAbsolutePath(), "question_696.txt", key, "AES");
                }
            }
        }

        File response = new File("response.txt");
        FileWriter fw = new FileWriter(response);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write("Rares Nedelcu");
        bw.close();
        fw.close();

        encrypt(response.getAbsolutePath(), "response.enc", key, "AES");
        decryptECB("response.enc", "response_verifier.txt", key, "AES");
    }
}