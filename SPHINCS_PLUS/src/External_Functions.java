import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


//Section 10 (External Functions)


public class External_Functions {


//********************************************************************************************************************

    //generates public and private keys
    public static Object[] slhKeygen() throws NoSuchAlgorithmException {

        try {

            SecureRandom secureRandom = new SecureRandom();
            byte[] SK_seed = new byte[Params.n];
            byte[] SK_prf = new byte[Params.n];
            byte[] PK_seed = new byte[Params.n];
            
            secureRandom.nextBytes(SK_seed);
            secureRandom.nextBytes(SK_prf);
            secureRandom.nextBytes(PK_seed);


            if (SK_seed == null || SK_prf == null || PK_seed == null) {
                return new Object[]{null, null}; // Return null if generation failed
            }

            return Internal_Functions.slhKeygenInternal(SK_seed, SK_prf, PK_seed);

        } catch (Exception e) {
            e.printStackTrace();
            return new Object[]{null, null};
        }
}


//********************************************************************************************************************

    //creates signature for message and context
    public static List<byte[]> slhSign(byte[] M, List<byte[]> ctx, Object[] SK) throws NoSuchAlgorithmException {

        try{


        if (ctx.size() > 255) {
            return new ArrayList<>();
        }

        SecureRandom random = new SecureRandom();
        byte[] addrnd = new byte[Params.n];
        random.nextBytes(addrnd);  


        // if (addrnd == null) {
        //     return new ArrayList<>();
        // }


        //builds message input 
        byte[] M_prime = HelpFunctions.concatenate(
            HelpFunctions.toByte(0, 1),
            HelpFunctions.toByte(ctx.size(), 1),
            HelpFunctions.concatenate(ctx.toArray(new byte[0][])),
            M
        );


            return Internal_Functions.slhSignInternal(List.of(M_prime), SK, addrnd);

            } catch (Exception e) {
                    e.printStackTrace();
                    return new ArrayList<>();
                }

        }


//********************************************************************************************************************



//NOT USED IN THE FINAL CODE!
    public static List<byte[]> hashSlhSign(byte[] M, List<byte[]> ctx, String PH, Object[] SK) {

        try {


            if (ctx.size() > 255) {
                return new ArrayList<>();
            }

            // Generate addrnd
            SecureRandom random = new SecureRandom();
            byte[] addrnd = new byte[Params.n];
            random.nextBytes(addrnd);

            // if (addrnd == null) {
            //     return new ArrayList<>();
            // }


            byte[] OID;
            byte[] PHM;
            switch (PH) {
                case "SHA-256":
                    //OID = HelpFunctions.toByte(0x0609608648016503040201, 11);
                    OID = new byte[]{0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
                    PHM = MessageDigest.getInstance("SHA-256").digest(M);
                    break;
                // case "SHA-512":
                //     OID = HelpFunctions.toByte(0x0609608648016503040203, 11);
                //     PHM = MessageDigest.getInstance("SHA-512").digest(M);
                //     break;
                // case "SHAKE128":
                //     OID = HelpFunctions.toByte(0x060960864801650304020B, 11);
                //     PHM = MessageDigest.getInstance("SHAKE128").digest(M);
                //     break;
                // case "SHAKE256":
                //     OID = HelpFunctions.toByte(0x060960864801650304020C, 11);
                //     PHM = MessageDigest.getInstance("SHAKE256").digest(M);
                //     break;
                default:
                    throw new UnsupportedOperationException("Unsupported pre-hash function");
            }


            byte[] M_prime = HelpFunctions.concatenate(
                    HelpFunctions.toByte(1, 1),
                    HelpFunctions.toByte(ctx.size(), 1),
                    HelpFunctions.concatenate(ctx.toArray(new byte[0][])),
                    OID,
                    PHM
            );


            return Internal_Functions.slhSignInternal(List.of(M_prime), SK, addrnd);
        } catch (Exception e) {
            e.printStackTrace();
            return new ArrayList<>();
        }
    }

}
