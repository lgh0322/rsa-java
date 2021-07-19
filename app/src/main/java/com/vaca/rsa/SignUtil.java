package com.vaca.rsa;

import org.apache.commons.codec.binary.Base64;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;


public class SignUtil {

    //#priKeyText
    private final static String priKeyText = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQChXmxaPt6Qg+XTiqaCG1cZEKwGPbKy/Qs5xGNx4HotngGUM2n/5FdZtSHZofJWsNUUKpZa+BynhNg0E0Qn4Xrp0WSi+Z5LgDewT7DeA0b5Cky386MEWwc11Asa+SuMiR5XFUjXdWrMQX5E7wVRcbuoq7A8QBfm3i8F4PdMokhlMviwhLngKOrWVKobE8cyA25Jv2FZgxv1NzVZ7zyGaO60a49X/NaA2poe5OB9zXBfsa8kfHl0b+sMQMd38uVrtCIqs2KABW6EGTToezk55i+hHg7nqMLum7Xtw8z/T1fpEtKgsnKANph7eqRHVHmjUDpHidx3BiTAArw07MVIq1LhAgMBAAECggEADJPDdjU4O6NMInTIDZP78eQuxD3C09iNK293IMUSQMPz840eUeeGN2O6w6+vp7oYoX3AQk7cTOI5x7VItqMIZXkAkwNJpzDTJlbPvj4bJgX7fMrshcZihXuFchDBqC53wunRx5lLPahNIypOC88FhVv8XHXSZxgiKh8ip0JuyhRS38TDVCcrIzKclsSY9CT3kYhVdPkfWEEGSb0qj7J4VxK7evE6yQD0/UJqB9j54Ts418DsEHNOZPDf6PFgNgl585AQZ3KpEUrfsx3rygLhUG+GQD+bkkDExA7vJlw5v1CF7Kr1T/XK9gjqRbRBjtzLy0MUe11ips3OM5LYkNv/EQKBgQDuWD+i64alAdXeReJAHWU8sQjZgmZYhlMhxfq8rsalJ490br3joZ2+KHXD7yDmvTUj0IFre99BcB7hi9Sx0joOjyS8+Rz7Bw02bdnwJbva5SYg3XojqdEoKGl5nFN67rL762jGsDG2Y5/hVEe/vxmH9sWB/OvQZ10If3p5OJ/jcwKBgQCtUnl1IWn57xHzqDqQEIMlCskGRXElMYdU/jtADLTt27DgSjzbgW5GgGMectvDDxYADYb93VUuTvz4EvHXAwo3CepDUjs4JtkGZeaAnMCER6doIyXPfRsxHMXRN4NgG70yEA5u7IfYFA1DuGLDwjddg4rU122ftqUM2UcwaaBjWwKBgQC9R9wRuFXPiOudf4Y0QKP7VOSgSAybVOGEOsPrQCmFUyt73c5zjg/Fyj/sAGXymGQxMw70mwUr5KzBldit9zQgB9G3OWaofGsjxI2FR5IuPjjPdNPgqqXt7FoHN/yb7iC6K7Ojxp1UKT35JoNsZYkTDwi/OGrVsKCTdRmAV1WyvQKBgBZD6Qxt/XI5DwJREyzcoixJBWgD1bQkd7Eoc64Xs8p2lXNKtiSwrNzrs0//C1I0huv80OGd5EptpTutG1o2rsJBSNHbJ3ZgLzMONh1Bhc24cr4C/eF4vdyCSLtGuV7IUXaz71a6lfzhHo8bibyCH6CovFX5UsDYsr1C0E1c1FjPAoGAXQ4hZ7/APQ/V1wmkZnplGchbXefqixvhDZWUvIAy6sAmypaRe3fRjd3SFLGXhOg48CQ59A0P3dQjKja8U7eQA6c6qw9Ci4F/cceHcdgnH6fOkqiHMdN6Sr0/SinbVP0kqU25y+AbRdJjwYZGTmWeqMdFUra+MVK9befn+hA3zAk=";

    //#pubKeyText
    private final static String pubKeyText = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoV5sWj7ekIPl04qmghtXGRCsBj2ysv0LOcRjceB6LZ4BlDNp/+RXWbUh2aHyVrDVFCqWWvgcp4TYNBNEJ+F66dFkovmeS4A3sE+w3gNG+QpMt/OjBFsHNdQLGvkrjIkeVxVI13VqzEF+RO8FUXG7qKuwPEAX5t4vBeD3TKJIZTL4sIS54Cjq1lSqGxPHMgNuSb9hWYMb9Tc1We88hmjutGuPV/zWgNqaHuTgfc1wX7GvJHx5dG/rDEDHd/Lla7QiKrNigAVuhBk06Hs5OeYvoR4O56jC7pu17cPM/09X6RLSoLJygDaYe3qkR1R5o1A6R4ncdwYkwAK8NOzFSKtS4QIDAQAB";

    private final static String CHARACTER_ENCODING_UTF_8 = "UTF-8";

    public static void main(String[] args) {

        String signString = "bijian 您好!";
        try {
            // 加签
            String localSignature = SignUtil.sign(priKeyText.getBytes(CHARACTER_ENCODING_UTF_8), signString);
            System.out.println(localSignature);
            //验签
            boolean verifyResult = SignUtil.verify(pubKeyText.getBytes(CHARACTER_ENCODING_UTF_8), signString, localSignature);
            System.out.println("verifyResult:" + verifyResult);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    /**
     * RSA私钥加签
     * @param priKeyText经过base64处理后的私钥
     * @param plainText明文内容
     * @return 十六进制的签名字符串
     * @throws Exception
     */
    public static String sign(byte[] priKeyText, String plainText) throws Exception {
        try {
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.decodeBase64(priKeyText));
            KeyFactory keyf = KeyFactory.getInstance("RSA");
            PrivateKey prikey = keyf.generatePrivate(priPKCS8);

            // 用私钥对信息生成数字签名
            java.security.Signature signet = java.security.Signature.getInstance("SHA256withRSA");
            signet.initSign(prikey);
            signet.update(plainText.getBytes("UTF-8"));
            return DigestUtil.byte2hex(signet.sign());
        } catch (Exception e) {
            throw e;
        }
    }

    /**
     * 公钥验签
     * @param pubKeyText经过base64处理后的公钥
     * @param plainText明文内容
     * @param signText十六进制的签名字符串
     * @return 验签结果 true验证一致 false验证不一致
     */
    public static boolean verify(byte[] pubKeyText, String plainText, String signText) {
        try {
            // 解密由base64编码的公钥,并构造X509EncodedKeySpec对象
            java.security.spec.X509EncodedKeySpec bobPubKeySpec = new java.security.spec.X509EncodedKeySpec(
                    Base64.decodeBase64(pubKeyText));
            // RSA算法
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            // 取公钥匙对象
            java.security.PublicKey pubKey = keyFactory.generatePublic(bobPubKeySpec);
            // 十六进制数字签名转为字节
            byte[] signed = DigestUtil.hex2byte(signText.getBytes("UTF-8"));
            java.security.Signature signatureChecker = java.security.Signature.getInstance("SHA256withRSA");
            signatureChecker.initVerify(pubKey);
            signatureChecker.update(plainText.getBytes("UTF-8"));
            // 验证签名是否正常
            return signatureChecker.verify(signed);
        } catch (Throwable e) {
            return false;
        }
    }
}