package com.thor.cry;

import com.google.common.collect.ImmutableList;
import org.bitcoinj.crypto.*;
import org.bitcoinj.wallet.DeterministicSeed;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * @author anzy
 * @version 1.0
 * @date 2020/7/22 16:50
 **/
public class HDNode {

    public DeterministicKey getDeterministicKey() {
        return deterministicKey;
    }

    public void setDeterministicKey(DeterministicKey deterministicKey) {
        this.deterministicKey = deterministicKey;
    }

    private DeterministicKey deterministicKey;

    private final String privateKey;

    private final String publicKey;

    private final String address;

    public byte[] getChainCode() {
        return chainCode;
    }

    private byte[] chainCode;

    public HDNode(HDNodeBuilder hdNodeBuilder){
        this.privateKey = hdNodeBuilder.privateKey;
        this.publicKey = hdNodeBuilder.publicKey;
        this.address = hdNodeBuilder.address;
        this.chainCode = hdNodeBuilder.chainCode;
    }

    public static class HDNodeBuilder{
        private String privateKey;

        private String publicKey;

        private String address;

        private byte[] chainCode;

        public HDNodeBuilder setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
            return this;
        }
        public HDNodeBuilder setChainCode(byte[] chainCode) {
            this.chainCode = chainCode;
            return this;
        }

        public HDNodeBuilder setPublicKey(String publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public HDNodeBuilder setAddress(String address) {
            this.address = address;
            return this;
        }

    }

    public byte[] getPrivKeyBytes() {
        return this.privateKey.getBytes();
    }
    public byte[] getPublicKeyBytes() {
        return this.publicKey.getBytes();
    }

    public String getPrivateKey() {
        return this.privateKey;
    }

    public String getPublicKey() {
        return this.publicKey;
    }

    public String getAddress() {
        return this.address;
    }

    /**
     * path路径
     */
    private final static ImmutableList<ChildNumber> BIP44_VET_ACCOUNT_ZERO_PATH = ImmutableList.of(new ChildNumber(44, true),
            new ChildNumber(818, true), ChildNumber.ZERO_HARDENED, ChildNumber.ZERO);


    /**
     * 生成HDNode
     * @return
     * @throws MnemonicException.MnemonicLengthException
     */
    public static HDNode createWallet() throws MnemonicException.MnemonicLengthException {

        SecureRandom secureRandom = new SecureRandom();
        byte[] entropy = new byte[DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8];
        secureRandom.nextBytes(entropy);

        //生成12位助记词
        List<String> str = MnemonicCode.INSTANCE.toMnemonic(entropy);;
        return createFromMnemonic(str);
    }

    /**
     * 通过助记词生成HDNode
     * @param mnemonic
     * @return
     */
    public static HDNode createFromMnemonic(List<String> mnemonic){
        //使用助记词生成钱包种子
        byte[] seed = MnemonicCode.toSeed(mnemonic, "");
        return createFromSeed(seed);
    }

    /**
     * 通过种子生成HDNode
     * @param seed
     * @return
     */
    public static HDNode createFromSeed(byte[] seed) {
        DeterministicKey masterDeterministicKey = HDKeyDerivation.createMasterPrivateKey(seed);
        return getHdNode(0, masterDeterministicKey);
    }

    public static HDNode createFromPrivate(byte[] privKeyBytes, byte[] chainCode) {
        return createFromPrivateChildNumber(privKeyBytes,chainCode,0);
    }


    public static HDNode createFromPrivateChildNumber(byte[] privKeyBytes, byte[] chainCode,int childNumber) {
        DeterministicKey deterministicKey = HDKeyDerivation.createMasterPrivKeyFromBytes(privKeyBytes, chainCode);
        return getHdNode(childNumber, deterministicKey);
    }

    private static HDNode getHdNode(int childNumber, DeterministicKey masterDeterministicKey) {
        DeterministicHierarchy deterministicHierarchy = new DeterministicHierarchy(masterDeterministicKey);
        DeterministicKey accountKey = deterministicHierarchy.get(BIP44_VET_ACCOUNT_ZERO_PATH, false, true);
        // 由父路径,派生出第一个子私钥
        DeterministicKey deterministicKey = HDKeyDerivation.deriveChildKey(accountKey, childNumber);
        ECKeyPair childEcKeyPair0 = ECKeyPair.create(deterministicKey.getPrivKeyBytes());

        HDNode hdNode =  new HDNode(new HDNodeBuilder().setPrivateKey(deterministicKey.getPrivateKeyAsHex()).setAddress(Keys.getAddress(childEcKeyPair0)).
                setPublicKey(deterministicKey.getPublicKeyAsHex()).setChainCode(deterministicKey.getChainCode()));
        hdNode.setDeterministicKey(deterministicKey);
        return hdNode;
    }

    public static HDNode createFromPublic(byte[] publicKey, byte[] chainCode) {
        HDNode hdNode =  createFromPublicChildNumber(publicKey,chainCode,0);
        return hdNode;
    }
    public static HDNode createFromPublicChildNumber(byte[] publicKey, byte[] chainCode,int childNumber) {
        DeterministicKey masterPubKey = HDKeyDerivation.createMasterPubKeyFromBytes(publicKey, chainCode);
        // 由父路径,派生出第一个子私钥
        DeterministicKey deterministicKey = HDKeyDerivation.deriveChildKey(masterPubKey, childNumber);
        HDNode hdNode =  new HDNode(new HDNodeBuilder().setAddress(Keys.getAddress(deterministicKey.getPublicKeyAsHex())).
                setPublicKey(deterministicKey.getPublicKeyAsHex()).setChainCode(deterministicKey.getChainCode()));
        hdNode.setDeterministicKey(deterministicKey);
        return hdNode;
    }

    public HDNode derive(int childNumber){
        if (this.getPrivateKey()!= null){
            return createFromPrivateChildNumber(this.getDeterministicKey().getPrivKeyBytes(),chainCode,childNumber);
        }else {
           return createFromPublicChildNumber(this.getDeterministicKey().getPubKey(),chainCode,childNumber);
        }
    }



    public static void main(String[] args) throws Exception {

        String worlds = "ignore empty bird silly journey junior ripple have guard waste between tenant";
        HDNode hdNode = createFromMnemonic(Arrays.asList(worlds.split(" ")));
        hdNode = createFromSeed("28bc19620b4fbb1f8892b9607f6e406fcd8226a0d6dc167ff677d122a1a64ef936101a644e6b447fd495677f68215d8522c893100d9010668614a68b3c7bb49f".getBytes());
        System.out.println("getPrivateKey: " + hdNode.getPrivateKey());
        System.out.println("getPublicKey: " + hdNode.getPublicKey());
        System.out.println("getAddress: " + hdNode.getAddress());
        System.out.println("==================================================");

        hdNode = createFromPrivate(hdNode.getDeterministicKey().getPrivKeyBytes(),hdNode.getChainCode());

        hdNode = createFromPublic(hdNode.getDeterministicKey().getPubKey(),hdNode.getChainCode());
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
