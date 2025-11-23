import java.util.Arrays;


//Section 4.2 (Addresses), Section 4.3 (Member Functions)


//holds address data for slh-dsa components
public class ADRS {

    //main address array, always 32 bytes
    private byte[] adrs;

    //makes a blank address with all bytes zero
    public ADRS() {
        this.adrs = HelpFunctions.toByte(0, 32);
    }

    //returns a copy of the address array
    public byte[] getADRS() {
        return adrs.clone();
    }


    //******************************************************************************************************************** */


    //sets the first 4 bytes to layer address
    public void setLayerAddress(int l) {
        System.arraycopy(HelpFunctions.toByte(l, 4), 0, adrs, 0, 4);
    }


//******************************************************************************************************************** */

    //sets bytes 4-15 to tree address
    public void setTreeAddress(int t) {
        System.arraycopy(HelpFunctions.toByte(t, 12), 0, adrs, 4, 12);
    }


//******************************************************************************************************************** */

    //sets type at byte 16-19, clears last 12 bytes
    public void setTypeAndClear(int Y) {
        System.arraycopy(HelpFunctions.toByte(Y, 4), 0, adrs, 16, 4);
        System.arraycopy(HelpFunctions.toByte(0, 12), 0, adrs, 20, 12);
    }


//******************************************************************************************************************** */

    //sets key pair address at byte 20-23
    public void setKeyPairAddress(int i) {
        System.arraycopy(HelpFunctions.toByte(i, 4), 0, adrs, 20, 4);
    }


//******************************************************************************************************************** */

    //sets chain address at byte 24-27
    public void setChainAddress(int i) {
        System.arraycopy(HelpFunctions.toByte(i, 4), 0, adrs, 24, 4);
    }


//******************************************************************************************************************** */

    //for some types, tree height is same as chain address
    public void setTreeHeight(int i) {
        setChainAddress(i);
    }


//******************************************************************************************************************** */

    //sets hash address at byte 28-31
    public void setHashAddress(int i) {
        System.arraycopy(HelpFunctions.toByte(i, 4), 0, adrs, 28, 4);
    }


//******************************************************************************************************************** */

    //for some types, tree index is same as hash address
    public void setTreeIndex(int i) {
        setHashAddress(i);
    }


//******************************************************************************************************************** */

    //gets the key pair address from byte 20-23
    public int getKeyPairAddress() {
        return HelpFunctions.toInt(Arrays.copyOfRange(adrs, 20, 24), 4);
    }


//******************************************************************************************************************** */

    //gets the tree index from byte 28-31
    public int getTreeIndex() {
        return HelpFunctions.toInt(Arrays.copyOfRange(adrs, 28, 32), 4);
    }


//******************************************************************************************************************** */


}


