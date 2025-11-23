import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


//Section 9 (SLH-DSA Internal Functions)


public class Internal_Functions {


//******************************************************************************************************************** */


    //generates keypair
    public static Object[] slhKeygenInternal(byte[] skSeed, byte[] skPrf, byte[] pkSeed) throws NoSuchAlgorithmException {
        ADRS adrs = new ADRS();
        adrs.setLayerAddress(Params.d - 1);
        byte[] pkRoot = XMSS.xmssNode(skSeed, 0, Params.h_ , pkSeed, adrs);
        return new Object[]{
            new Object[]{skSeed, skPrf, pkSeed, pkRoot},
            new Object[]{pkSeed, pkRoot}
        };
    }


//******************************************************************************************************************** */


    //generates signature
    public static List<byte[]> slhSignInternal(List<byte[]> M, Object[] SK, byte[] addrnd) throws NoSuchAlgorithmException {

        int param1 = (int) Math.ceil((Params.k * Params.a) / 8.0);
        int param2 = (int) Math.ceil((Params.h - Params.h / Params.d) / 8.0);

        //System.out.println("Calculated param1: " + param1 + ", param2: " + param2);


        List<byte[]> SIG = new ArrayList<>();
        ADRS adrs = new ADRS();
        byte[] optRand = addrnd.clone();


        byte[] R = HashFunctions.PRF_msg( (byte[]) SK[1], optRand, M);
        SIG.add(R);

        //System.out.println("Randomness R generated, length: " + R.length);


        byte[] digest = HashFunctions.H_msg(R, (byte[]) SK[2], (byte[]) SK[3], M);

        //System.out.println("Digest generated, length: " + digest.length);


        byte[] md = slice(digest, 0, param1);
        byte[] tmpIdxTree = slice(digest, param1, param1 + param2);
        byte[] tmpIdxLeaf = slice(digest, param1 + param2, param1 + param2 + (int) Math.ceil(Params.h / (Params.d * 8.0)));

        //System.out.println("Slicing successful. md length: " + md.length + ", tmpIdxTree length: " + tmpIdxTree.length + ", tmpIdxLeaf length: " + tmpIdxLeaf.length);


        //int idxTree = (int) (HelpFunctions.toInt(tmpIdxTree, param2) % Math.pow(2, Params.h - Params.h / Params.d));
        int idxTree = Math.floorMod(HelpFunctions.toInt(tmpIdxTree, param2), (int) Math.pow(2, Params.h - Params.h / Params.d));

        int idxLeaf = (int) (HelpFunctions.toInt(tmpIdxLeaf, (int) Math.ceil(Params.h / (Params.d * 8.0))) % Math.pow(2, Params.h / Params.d));

        //System.out.println("Indices calculated: idxTree = " + idxTree + ", idxLeaf = " + idxLeaf);


        adrs.setTreeAddress(idxTree);
        adrs.setTypeAndClear(Params.FORS_TREE);
        adrs.setKeyPairAddress(idxLeaf);


        List<byte[]> SIG_FORS = FORS.forsSign(md, (byte[]) SK[0], (byte[]) SK[2], adrs);
        SIG.addAll(SIG_FORS);

        //System.out.println("FORS signature generated, length: " + SIG_FORS.size());


        byte[] PK_FORS = FORS.forsPkFromSig(SIG_FORS, md, (byte[]) SK[2], adrs);


        List<byte[]> SIG_HT = Hypertree.htSign(PK_FORS, (byte[]) SK[0], (byte[]) SK[2], idxTree, idxLeaf);
        SIG.addAll(SIG_HT);


        //System.out.println("Total signature length: " + SIG.size());


        return SIG;
    }


//******************************************************************************************************************** */


    //verifies signature 
    public static boolean slhVerifyInternal(List<byte[]> M, List<byte[]> SIG, Object[] PK) throws NoSuchAlgorithmException {

        int param1 = (int) Math.ceil((Params.k * Params.a) / 8.0);
        int param2 = (int) Math.ceil((Params.h - Params.h / Params.d) / 8.0);


        //System.out.println("Expected signature length: " + (1 + Params.k * (1 + Params.a) + Params.h + Params.d * Params.len));
        //System.out.println("Actual signature length: " + SIG.size());


        int expectedLength = 1 + Params.k * (1 + Params.a) + Params.h + Params.d * Params.len;
        if (SIG.size() != expectedLength) {
            return false;
        }

        ADRS adrs = new ADRS();
        byte[] R = SIG.get(0);
        List<byte[]> SIG_FORS = SIG.subList(1, 1 + Params.k * (1 + Params.a));
        List<byte[]> SIG_HT = SIG.subList(1 + Params.k * (1 + Params.a), SIG.size());

        
        byte[] digest = HashFunctions.H_msg(R, (byte[]) PK[0], (byte[]) PK[1], M);

        //System.out.println("Digest length in verification: " + digest.length);


        byte[] md = slice(digest, 0, param1);
        byte[] tmpIdxTree = slice(digest, param1, param1 + param2);
        byte[] tmpIdxLeaf = slice(digest, param1 + param2, param1 + param2 + (int) Math.ceil(Params.h / (8.0 * Params.d)));


        //int idxTree = (int) (HelpFunctions.toInt(tmpIdxTree, param2) % Math.pow(2, Params.h - Params.h / Params.d));
        int idxTree = Math.floorMod(HelpFunctions.toInt(tmpIdxTree, param2), (int) Math.pow(2, Params.h - Params.h / Params.d));

        int idxLeaf = (int) (HelpFunctions.toInt(tmpIdxLeaf, (int) Math.ceil(Params.h / (Params.d * 8.0))) % Math.pow(2, Params.h / Params.d));


        //System.out.println("idxTree: " + idxTree + ", idxLeaf: " + idxLeaf);


        adrs.setTreeAddress(idxTree);
        adrs.setTypeAndClear(Params.FORS_TREE);
        adrs.setKeyPairAddress(idxLeaf);


        byte[] PK_FORS = FORS.forsPkFromSig(SIG_FORS, md, (byte[]) PK[0], adrs);



        return Hypertree.htVerify(PK_FORS, SIG_HT, (byte[]) PK[0], idxTree, idxLeaf, (byte[]) PK[1]);
    }


//******************************************************************************************************************** */


    //slices a byte array
    private static byte[] slice(byte[] array, int start, int end) {
    try {
            if (start < 0 || end > array.length || start > end) {
                throw new ArrayIndexOutOfBoundsException("Invalid slice indices: start=" + start + ", end=" + end + ", array length=" + array.length);
            }
            byte[] result = new byte[end - start];
            System.arraycopy(array, start, result, 0, end - start);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[0];
        }
    }



}