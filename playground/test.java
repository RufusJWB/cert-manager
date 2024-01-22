import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

class Main {

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException {
        // Define your shared secret, salt, and hash algorithm
        String sharedSecret = "SiemensIT";
        String salt = "YourSalt";
        String hashAlgorithm = "SHA256";

        // Convert your shared secret and salt to byte arrays
        byte[] sharedSecretByteArray = sharedSecret.getBytes();

        System.out.println("Java shared secret " + bytesToHex(sharedSecretByteArray));

        byte[] protectionSalt = salt.getBytes();

        System.out.println("Java salt " + bytesToHex(protectionSalt));

        // Combine the shared secret and the salt
        byte[] calculatingBaseKey = new byte[sharedSecretByteArray.length + protectionSalt.length];
        System.arraycopy(sharedSecretByteArray, 0, calculatingBaseKey, 0, sharedSecretByteArray.length);
        System.arraycopy(protectionSalt, 0, calculatingBaseKey, sharedSecretByteArray.length, protectionSalt.length);

        System.out.println("Java input baseKey " + bytesToHex(calculatingBaseKey));

        // Construct the base key according to rfc4210, section 5.1.3.1
        final MessageDigest dig = MessageDigest.getInstance(hashAlgorithm);
        final int iterationCount = 500; // Define your iteration count
        for (int i = 0; i < iterationCount; i++) {
            calculatingBaseKey = dig.digest(calculatingBaseKey);
            // System.out.println("Java baseKey iteration " + i + " : " +
            // bytesToHex(calculatingBaseKey));
            dig.reset();
        }

//        byte[] calculatingBaseKey = "This is my baseKey".getBytes();
        System.out.println("Java final baseKey " + bytesToHex(calculatingBaseKey));

        String myBody = "This string identifies as a base64 encoded DER";
        byte[] myBodyByteArray = myBody.getBytes();

        System.out.println("Java myBody " + bytesToHex(myBodyByteArray));

        Mac sha1HMAC = Mac.getInstance("HmacSHA1");
        SecretKeySpec secretKey = new SecretKeySpec(calculatingBaseKey, "HmacSHA1");
        sha1HMAC.init(secretKey);
        //sha1HMAC.reset();
        sha1HMAC.update(myBodyByteArray,0,myBodyByteArray.length);

        byte[] hashedBytes = sha1HMAC.doFinal();
        System.out.println("Java HMAC of myBody " + bytesToHex(hashedBytes));
    }

}
