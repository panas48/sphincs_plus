import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;


//Section 8 (FORS)


public class FORS {

//******************************************************************************************************************** */


    //generates fors secret value
    public static byte[] forsSkGen(byte[] skSeed, byte[] pkSeed, ADRS adrs, int idx) throws NoSuchAlgorithmException {

        ADRS skAdrs = new ADRS();  

        skAdrs.setTypeAndClear(Params.FORS_PRF);
        
        skAdrs.setKeyPairAddress(adrs.getKeyPairAddress());
        skAdrs.setTreeIndex(idx);

        return HashFunctions.PRF(pkSeed, skSeed, skAdrs);
    }


//******************************************************************************************************************** */

    //computes node in fors tree
    public static byte[] forsNode(byte[] skSeed, int i, int z, byte[] pkSeed, ADRS adrs) throws NoSuchAlgorithmException {


        byte[] node;

        if (z == 0) {
            byte[] sk = forsSkGen(skSeed, pkSeed, adrs, i);
            
            adrs.setTreeHeight(0);
            adrs.setTreeIndex(i);

            node = HashFunctions.F(pkSeed, adrs, List.of(sk));


        } else {
            byte[] lnode = forsNode(skSeed, 2 * i, z - 1, pkSeed, adrs);
            byte[] rnode = forsNode(skSeed, 2 * i + 1, z - 1, pkSeed, adrs);

            adrs.setTreeHeight(z);
            adrs.setTreeIndex(i);

            byte[] concatenatedNodes = HelpFunctions.concatenate(lnode, rnode);
            node = HashFunctions.H(pkSeed, adrs, List.of(concatenatedNodes));
        }

        return node;
    }


//******************************************************************************************************************** */

    //generates fors signature 
    public static List<byte[]> forsSign(byte[] md, byte[] skSeed, byte[] pkSeed, ADRS adrs) throws NoSuchAlgorithmException {

            List<byte[]> sigFORS = new ArrayList<>();


            int[] indices = HelpFunctions.base_2b(md, Params.a, Params.k);

            for (int i = 0; i < Params.k; i++) {


                int idx = i * (1 << Params.a) + indices[i];
                sigFORS.add(forsSkGen(skSeed, pkSeed, adrs, idx));

                for (int j = 0; j < Params.a; j++) {


                    int s = (indices[i] >> j) ^ 1;  
                    int authIdx = i * (1 << (Params.a - j)) + s;
                    sigFORS.add(forsNode(skSeed, authIdx, j, pkSeed, adrs));
                }
            }

            return sigFORS;
        }


//******************************************************************************************************************** */

    //gets fors public key from signature
    public static byte[] forsPkFromSig(List<byte[]> sigFORS, byte[] md, byte[] pkSeed, ADRS adrs) throws NoSuchAlgorithmException {


        int[] indices = HelpFunctions.base_2b(md, Params.a, Params.k);
        byte[][] root = new byte[Params.k][];
        byte[][] node = new byte[2][];

        for (int i = 0; i < Params.k; i++) {
            byte[] sk = sigFORS.get(i * (Params.a + 1));  
            adrs.setTreeHeight(0);
            adrs.setTreeIndex(i * (1 << Params.a) + indices[i]);  

            node[0] = HashFunctions.F(pkSeed, adrs, List.of(sk));
            

            List<byte[]> auth = sigFORS.subList(i * (Params.a + 1) + 1, (i + 1) * (Params.a + 1));


            for (int j = 0; j < Params.a; j++) {

                adrs.setTreeHeight(j + 1);

                if ((indices[i] >> j) % 2 == 0) {

                    adrs.setTreeIndex(adrs.getTreeIndex() / 2);
                    node[1] = HashFunctions.H(pkSeed, adrs, List.of(HelpFunctions.concatenate(node[0], auth.get(j))));

                } else {
                    adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
                    node[1] = HashFunctions.H(pkSeed, adrs, List.of(HelpFunctions.concatenate(auth.get(j), node[0])));
                }

                node[0] = node[1];
            }

            root[i] = node[0];
        }

        ADRS forspkADRS = new ADRS();
        forspkADRS.setTypeAndClear(Params.FORS_ROOTS);
        forspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());


        return HashFunctions.Tl(pkSeed, forspkADRS, List.of(root));
    }



//******************************************************************************************************************** */

}