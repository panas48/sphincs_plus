import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


//main demo for slh-dsa 


public class Main {


//******************************************************************************************************************** */


    //generates keypair with param set
    public static Object[] generateKeyPair(String parameterSet) throws Exception {
        Params.setupParameterSet(parameterSet);
        return External_Functions.slhKeygen();
    }


//******************************************************************************************************************** */


    //signs message
    public static List<byte[]> signMessage(byte[] message, Object[] secretKey, boolean useHash, String hashAlgorithm) throws Exception {
        List<byte[]> context = new ArrayList<>();
        if (useHash) {
            return External_Functions.hashSlhSign(message, context, hashAlgorithm, secretKey);
        } else {
            return External_Functions.slhSign(message, context, secretKey);
        }
    }


//******************************************************************************************************************** */


    //verifies signature
    public static boolean verifySignature(byte[] message, List<byte[]> signature, Object[] publicKey) throws Exception {
        List<byte[]> context = new ArrayList<>();
        return Signature_Verification.slhVerify(message, signature, context, publicKey);
    }


//******************************************************************************************************************** */


    //prints all signature parts
    public static void printSignature(List<byte[]> signature) {
        for (int i = 0; i < signature.size(); i++) {
            System.out.println("Signature part " + i + ": " + Arrays.toString(signature.get(i)));
        }
    }


//******************************************************************************************************************** */

   //runs demo for slh-dsa
    public static void main(String[] args) {
        
        try {


            //////////////////////////////////////////
            //HERE YOU CAN CHANGE THE THINGS
            // Initialize parameters
            String parameterSet = "SLH-DSA-SHAKE-256s"; //hash function (parameter set)
            byte[] message = "Hello World".getBytes(); //message
            //////////////////////////////////////////

            
            // Generate key pair
            Object[] keys = generateKeyPair(parameterSet);
            Object[] secretKey = (Object[]) keys[0];
            Object[] publicKey = (Object[]) keys[1];


            //System.out.println("Private Key: " + Arrays.toString((byte[]) secretKey[0]));
            System.out.println("Public Key: " + Arrays.toString((byte[]) publicKey[1]));


            // Sign the message
            List<byte[]> signature = signMessage(message, secretKey, false, "SHAKE-256");
            //printSignature(signature);


            // Verify the signature
            boolean isValid = verifySignature(message, signature, publicKey);
            System.out.println(isValid ? "Signature valid" : "Signature invalid");


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

// -128 to 127 for java (IMPORTANT)
//******************************************************************************************************************** */

}
