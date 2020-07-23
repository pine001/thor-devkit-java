package wallet;

import com.google.common.collect.ImmutableList;
import org.bitcoinj.crypto.*;
import org.bitcoinj.wallet.DeterministicSeed;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;

import java.security.SecureRandom;
import java.util.List;

/**
 * @author anzy
 * @version 1.0
 * @date 2020/7/22 20:39
 **/
public class Wallet {

    /**
     * path路径
     */
    private final static ImmutableList<ChildNumber> BIP44_ETH_ACCOUNT_ZERO_PATH = ImmutableList.of(new ChildNumber(44, true),
                    new ChildNumber(818, true), ChildNumber.ZERO_HARDENED, ChildNumber.ZERO);

    private static void createWallet()  throws MnemonicException.MnemonicLengthException {
        String worlds = "ignore empty bird silly journey junior ripple have guard waste between tenant";

        SecureRandom secureRandom = new SecureRandom();
        byte[] entropy = new byte[DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8];
        secureRandom.nextBytes(entropy);

        //生成12位助记词
        List<String> str = MnemonicCode.INSTANCE.toMnemonic(entropy);

        //使用助记词生成钱包种子
        byte[] seed = MnemonicCode.toSeed(str, "");
        DeterministicKey masterPrivateKey = HDKeyDerivation.createMasterPrivateKey(seed);
        DeterministicHierarchy deterministicHierarchy = new DeterministicHierarchy(masterPrivateKey);
        DeterministicKey deterministicKey = deterministicHierarchy
                .deriveChild(BIP44_ETH_ACCOUNT_ZERO_PATH, false, true, new ChildNumber(0));
        byte[] bytes = deterministicKey.getPrivKeyBytes();
        ECKeyPair keyPair = ECKeyPair.create(bytes);
        //通过公钥生成钱包地址
        String address = Keys.getAddress(keyPair.getPublicKey());

        System.out.println("助记词：");
        System.out.println(str);
        System.out.println("地址：");
        System.out.println("0x"+address);
        System.out.println("私钥：");
        System.out.println("0x"+keyPair.getPrivateKey().toString(16));
        System.out.println("公钥：");
        System.out.println(keyPair.getPublicKey().toString(16));
    }
    public static void main(String[] args) throws Exception {
        //创建钱包
        createWallet();
    }


}
