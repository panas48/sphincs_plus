import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;



//RESEARCH QUESTION 2
//How feasible is a brute-force forgery attack on SPHINCS+ by targeting the XMSS authentication path under classical computation?


public class Experiment2 {

    public static void main(String[] args) {
        try {
            testXMSS();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


//******************************************************************************************************************** */


//NEW SIGNATURE FUNCTION FOR XMSS (FAKE)
//HERE WE CHANGE THE FUNCTION THAT GENERATES THE XMSS SIGNATURE

    public static List<byte[]> generateFAKESignature(byte[] M, byte[] skSeed, int idx, byte[] pkSeed, ADRS adrs) throws NoSuchAlgorithmException {
    
    List<byte[]> AUTH = new ArrayList<>(Params.h_);


    SecureRandom random = new SecureRandom();



    // Fill AUTH[0] to AUTH[h_ - 2] with random values
    for (int j = 0; j < Params.h_ - 1; j++) {
        byte[] fakeAuthNode = new byte[Params.n];
        random.nextBytes(fakeAuthNode);
        AUTH.add(fakeAuthNode);
    }

    // AUTH[h_ - 1] = placeholder (to be replaced by Grover)
    byte[] placeholder = new byte[Params.n]; // all 0s
    AUTH.add(placeholder);



    adrs.setTypeAndClear(Params.WOTS_HASH);
    adrs.setKeyPairAddress(idx);


    List<byte[]> wotsSig = WOTSPlus.wotsSign(M, skSeed, pkSeed, adrs);


    //Combine WOTS + AUTH
    List<byte[]> sigXmss = new ArrayList<>();
    sigXmss.addAll(wotsSig);
    sigXmss.addAll(AUTH);



    return sigXmss;
}


//******************************************************************************************************************** */


    public static void testXMSS() throws NoSuchAlgorithmException {


    Params.setupParameterSet("SLH-DSA-SHAKE-16");

    byte[] message = "Hello World".getBytes();
    ADRS adrs = new ADRS();



    //RANDOMLY GENERATED KEYS (FAKE KEYS)
    //create the keys
    SecureRandom random = new SecureRandom();

    //ORIGINAL
    byte[] originalSkSeed = random.generateSeed(Params.n);
    System.out.println(Arrays.toString(originalSkSeed));

    byte[] originalPkSeed = random.generateSeed(Params.n);
    System.out.println(Arrays.toString(originalPkSeed));



    // //PRIVATE
    byte[] attackerSkSeed = random.generateSeed(Params.n);
    System.out.println(Arrays.toString(attackerSkSeed));

    byte[] attackerPkSeed = random.generateSeed(Params.n);
    System.out.println(Arrays.toString(attackerPkSeed));



    //HARD-CODED KEYS THAT THE ATTACK IS SUCCESSFUL
    //8
    // byte[] originalSkSeed = new byte[] { -118 };
    // byte[] originalPkSeed = new byte[] { -62 };
    // byte[] attackerSkSeed = new byte[] { -23 };
    // byte[] attackerPkSeed = new byte[] { -47 };

    //16
    // byte[] originalSkSeed = new byte[] { -118 };
    // byte[] originalPkSeed = new byte[] { -62 };
    // byte[] attackerSkSeed = new byte[] { -23 };
    // byte[] attackerPkSeed = new byte[] { -47 };

    //24
    // byte[] originalSkSeed = new byte[] { -118 };
    // byte[] originalPkSeed = new byte[] { -62 };
    // byte[] attackerSkSeed = new byte[] { -23 };
    // byte[] attackerPkSeed = new byte[] { -47 };

//******************************************************************************************************************** */

    //ORIGINAL PUBLIC KEY CREATED USING HIS OWN KEYS
    byte[] originalPk = XMSS.xmssNode(originalSkSeed, 0, Params.h_, originalPkSeed, adrs);
    System.out.println(Arrays.toString(originalPk));


    //SIGNATURE
    //The attacker makes their fake signature look like it was created by the original public key 
    List<byte[]> signature = generateFAKESignature(message, attackerSkSeed, 0, attackerPkSeed, adrs);
    for (int i = 0; i < signature.size(); i++) {
       System.out.println("signature[" + i + "]: " + Arrays.toString(signature.get(i)));
    }


    boolean found = false;
    long startTime = System.currentTimeMillis();


// //BRUTE-FORCE FOR SHAKE8
//     for (int b = -128; b <= 127; b++) {
//         byte[] candidate = new byte[Params.n];  
//         candidate[0] = (byte) b;                

//         // Replace last AUTH node
//         signature.set(Params.len + Params.h_ - 1, candidate);

//         // Try verifying
//         byte[] derivedPk = XMSS.xmssPkFromSig(0, signature, message, attackerPkSeed, adrs);


//         if (Arrays.equals(derivedPk, originalPk)) {
//             long endTime = System.currentTimeMillis(); 
//             System.out.println("Found: " + b);
//             System.out.println("Derived public key: " + Arrays.toString(derivedPk));
//             System.out.println("Time taken (SHAKE8): " + (endTime - startTime) + " ms");

//             found = true;
//             break;
//         }
//     }


//     if (!found) {
//         long endTime8 = System.currentTimeMillis(); 
//         System.out.println("\n No matching value found for AUTH[h-1]. Try more bytes.");
//         System.out.println("Time spent (SHAKE8): " + (endTime8 - startTime) + " ms");

//     }


// //BRUTE-FORCE FOR SHAKE16
for (int b1 = -128; b1 <= 127; b1++) {
    for (int b2 = -128; b2 <= 127; b2++) {
        byte[] candidate = new byte[Params.n];  
        candidate[0] = (byte) b1;
        candidate[1] = (byte) b2;                

        // Replace last AUTH node
        signature.set(Params.len + Params.h_ - 1, candidate);

        // Try verifying
        byte[] derivedPk = XMSS.xmssPkFromSig(0, signature, message, attackerPkSeed, adrs);


        if (Arrays.equals(derivedPk, originalPk)) {
            long endTime = System.currentTimeMillis(); 
            System.out.println("Found b1 = " + b1 + ", b2 = " + b2);
            System.out.println("Derived public key: " + Arrays.toString(derivedPk));
            System.out.println("Time taken (SHAKE16): " + (endTime - startTime) + " ms");

            found = true;
            break;
        }
    }

}

    if (!found) {
        long endTime16 = System.currentTimeMillis(); // End timer even if not found
        System.out.println("\n No matching value found for AUTH[h-1]. Try more bytes.");
        System.out.println("Time spent (SHAKE8): " + (endTime16 - startTime) + " ms");

    }


//BRUTE-FORCE FOR SHAKE24
// for (int b1 = -128; b1 <= 127; b1++) {
//     for (int b2 = -128; b2 <= 127; b2++) {
//         for (int b3 = -128; b3 <= 127; b3++) {
//         byte[] candidate = new byte[Params.n];  
//         candidate[0] = (byte) b1;
//         candidate[1] = (byte) b2;                
//         candidate[2] = (byte) b3;

//         // Replace last AUTH node
//         signature.set(Params.len + Params.h_ - 1, candidate);

//         // Try verifying
//         byte[] derivedPk = XMSS.xmssPkFromSig(0, signature, message, attackerPkSeed, adrs);


//         if (Arrays.equals(derivedPk, originalPk)) {
//             long endTime = System.currentTimeMillis(); 
//             System.out.println("Found b1 = " + b1 + ", b2 = " + b2 + ", b3 = " + b3);
//             System.out.println("Derived public key: " + Arrays.toString(derivedPk));
//             System.out.println("Time taken (SHAKE16): " + (endTime - startTime) + " ms");

//             found = true;
//             break;

//             }
//         }
//     }

// }

//     if (!found) {
//         long endTime24 = System.currentTimeMillis(); // End timer even if not found
//         System.out.println("\n No matching value found for AUTH[h-1]. Try more bytes.");
//         System.out.println("Time spent (SHAKE8): " + (endTime24 - startTime) + " ms");

//     }

//We can choose random values for AUTH[0...h-2], 
//but we must search for the one full 256-bit value that completes the path to match the public key.
//******************************************************************************************************************** */

    
    }
}

// note to reader:
// to switch between different brute-force modes (shake-8, shake-16, shake-24),
// set the parameter set at the top of `testXMSS()` to match the hash size:
//     - use "SLH-DSA-SHAKE-8" for 8-bit hashes
//     - use "SLH-DSA-SHAKE-16" for 16-bit hashes
//     - use "SLH-DSA-SHAKE-24" for 24-bit hashes
//
// only run one brute-force block at a time. comment out the other two blocks 


//******************************************************************************************************************** */

