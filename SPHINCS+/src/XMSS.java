import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


//Section 6 (XMSS)


public class XMSS {


//********************************************************************************************************************


    //computes xmss node or root
    public static byte[] xmssNode(byte[] skSeed, int i, int z, byte[] pkSeed, ADRS adrs) throws NoSuchAlgorithmException {
        byte[] node;
        
        if (z == 0) {
            adrs.setTypeAndClear(Params.WOTS_HASH);
            adrs.setKeyPairAddress(i);
            node = WOTSPlus.wotsPkGen(skSeed, pkSeed, adrs);
        } else {
            byte[] lnode = xmssNode(skSeed, i * 2, z - 1, pkSeed, adrs);
            byte[] rnode = xmssNode(skSeed, i * 2 + 1, z - 1, pkSeed, adrs);
            
            adrs.setTypeAndClear(Params.TREE);
            adrs.setTreeHeight(z);
            adrs.setTreeIndex(i);
            
            node = HashFunctions.H(pkSeed, adrs, List.of(HelpFunctions.concatenate(lnode, rnode)));
        }
        return node;
    }


//********************************************************************************************************************


    //generates xmss signature
    public static List<byte[]> xmssSign(byte[] M, byte[] skSeed, int idx, byte[] pkSeed, ADRS adrs) throws NoSuchAlgorithmException {

        List<byte[]> AUTH = new ArrayList<>(Params.h_);
        

        //normal way
        for (int j = 0; j < Params.h_; j++) {
            int k = (idx >> j) ^ 1; 
            AUTH.add(j, xmssNode(skSeed, k, j, pkSeed, adrs));
        }
        //XMSS authentication path

    
        
        adrs.setTypeAndClear(Params.WOTS_HASH);
        adrs.setKeyPairAddress(idx);


        List<byte[]> sig = WOTSPlus.wotsSign(M, skSeed, pkSeed, adrs);


                            
        List<byte[]> sigXmss = new ArrayList<>();
        sigXmss.addAll(sig); //WOTS signature
        sigXmss.addAll(AUTH); //XMSS authentication path
        

        return sigXmss;
    }


//********************************************************************************************************************


    //restores xmss root from signature
    public static byte[] xmssPkFromSig(int idx, List<byte[]> sigXmss, byte[] M, byte[] pkSeed, ADRS adrs) throws NoSuchAlgorithmException {
        
        byte[][] node = new byte[2][];
        
        adrs.setTypeAndClear(Params.WOTS_HASH);
        adrs.setKeyPairAddress(idx);

        
        List<byte[]> sig = getWOTSSig(sigXmss);
        List<byte[]> AUTH = getXMSSAUTH(sigXmss);

        
        node[0] = WOTSPlus.wotsPkFromSig(sig, M, pkSeed, adrs);
        
        adrs.setTypeAndClear(Params.TREE);
        adrs.setTreeIndex(idx);
        

        for (int k = 0; k < Params.h_; k++) {
            adrs.setTreeHeight(k + 1);
            
            if ((idx >> k & 1) == 0) {
                adrs.setTreeIndex(adrs.getTreeIndex() / 2);
                node[1] = HashFunctions.H(pkSeed, adrs, List.of(HelpFunctions.concatenate(node[0], AUTH.get(k))));
            } else {
                adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
                node[1] = HashFunctions.H(pkSeed, adrs, List.of(HelpFunctions.concatenate(AUTH.get(k), node[0])));
            }
            node[0] = node[1];
        }
        return node[0];
    }

    
//********************************************************************************************************************

    //gets wots+ signature part
    public static List<byte[]> getWOTSSig(List<byte[]> sigXmss) throws NoSuchAlgorithmException {
        return sigXmss.subList(0, Params.len);
    }


    //gets xmss auth path
    public static List<byte[]> getXMSSAUTH(List<byte[]> sigXmss) throws NoSuchAlgorithmException {
        return sigXmss.subList(Params.len, Params.len + Params.h_);
    }


//XMSS SIGNATURE = (WOTS SIGNATURE) + (XMSS AUTH PATH)
//********************************************************************************************************************


}