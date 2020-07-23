package wallet;

import com.thor.cry.HDNode;

import java.util.Arrays;

/**
 * @author anzy
 * @version 1.0
 * @date 2020/7/23 17:30
 **/
public class HDNodeTest {

    public static void main(String[] args) throws Exception {

        String worlds = "ignore empty bird silly journey junior ripple have guard waste between tenant";
        HDNode hdNode = HDNode.createFromMnemonic(Arrays.asList(worlds.split(" ")));
        hdNode = HDNode.createFromSeed("28bc19620b4fbb1f8892b9607f6e406fcd8226a0d6dc167ff677d122a1a64ef936101a644e6b447fd495677f68215d8522c893100d9010668614a68b3c7bb49f".getBytes());
        System.out.println("getPrivateKey: " + hdNode.getPrivateKey());
        System.out.println("getPublicKey: " + hdNode.getPublicKey());
        System.out.println("getAddress: " + hdNode.getAddress());
        System.out.println("==================================================");

        hdNode = HDNode.createFromPrivate(hdNode.getDeterministicKey().getPrivKeyBytes(),hdNode.getChainCode());

        hdNode = HDNode.createFromPublic(hdNode.getDeterministicKey().getPubKey(),hdNode.getChainCode());
//        System.out.println("getPrivateKey: " + hdNode1.getPrivateKey());
        System.out.println("getPublicKey: " + hdNode.getPublicKey());
        System.out.println("getAddress: " + hdNode.getAddress());
        System.out.println("==================================================");
        for (int i = 0;i < 3; i++){
//            System.out.println("getPrivateKey: " + hdNode.derive(i).getPrivateKey());
            System.out.println("getPublicKey: " + hdNode.derive(i).getPublicKey());
            System.out.println("getAddress: " + hdNode.derive(i).getAddress());
        }


    }
}
