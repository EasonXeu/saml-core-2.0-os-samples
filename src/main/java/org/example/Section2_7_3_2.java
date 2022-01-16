package org.example;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.EncryptedAttribute;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.*;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Sample of section 2.7.3.2
 * 文档如下：
 * https://yizhenn.gitbook.io/saml/saml-co-re-2.0-os/2saml-duan-yan/2.7-sheng-ming/2.7.3-yuan-su-attributestatement/2.7.3.2-yuan-su-encryptedattribute
 */
public class Section2_7_3_2 {
    public static void main(String[] args) throws Exception{
        DefaultBootstrap.bootstrap();
        Attribute attribute= createAttribute("username","yizhen");
        System.out.println(XMLHelper.nodeToString(samlObject2DOM(attribute)));
        System.out.println("-----------------------------------------------------");

        //用来加密数据密钥的Key
        Credential asymmetricKey = SecurityHelper.generateKeyPairAndCredential(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15,
                1024, true);
        //用来加密明文的数据密钥
        Credential dataEncCredential = SecurityHelper.getSimpleCredential(
                SecurityHelper.generateSymmetricKey(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256)
        );
        EncryptedAttribute encryptedAttribute = createEncryptedAttribute(attribute,asymmetricKey,dataEncCredential);
        System.out.println(XMLHelper.nodeToString(samlObject2DOM(encryptedAttribute)));
        System.out.println("-----------------------------------------------------");

        Attribute originalAttribute = parseEncryptedAttribute(encryptedAttribute,asymmetricKey);
        System.out.println(XMLHelper.nodeToString(samlObject2DOM(originalAttribute)));
        System.out.println("-----------------------------------------------------");

    }

    private static Attribute parseEncryptedAttribute(EncryptedAttribute encryptedAttribute, Credential asymmetricKey) throws DecryptionException {

        KeyInfoCredentialResolver keyResolver=new StaticKeyInfoCredentialResolver(asymmetricKey);
        Decrypter decrypter=new Decrypter(null,keyResolver,null);
        EncryptedKey encryptedKey = encryptedAttribute.getEncryptedKeys().get(0);
        EncryptedData encryptedData = encryptedAttribute.getEncryptedData();
        //首先解密Data Key
        Key key = decrypter.decryptKey(encryptedKey,encryptedData.getEncryptionMethod().getAlgorithm());

        BasicCredential basicCredential = new BasicCredential();
        basicCredential.setSecretKey((SecretKey) key);
        KeyInfoCredentialResolver dataKeyInfoCredentialResolver=new StaticKeyInfoCredentialResolver(basicCredential);
        //设置Data Key，进而解密原文
        decrypter.setKeyResolver(dataKeyInfoCredentialResolver);
        XMLObject attributeXMLObject = decrypter.decryptData(encryptedData);
        return (Attribute) attributeXMLObject;
    }
    private static EncryptedAttribute createEncryptedAttribute(Attribute attribute, Credential asymmetricKey,Credential dataEncCredential) throws EncryptionException, NoSuchAlgorithmException, KeyException, NoSuchProviderException, DecryptionException {
        EncryptionParameters encryptionParameters = new EncryptionParameters();
        encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);
        encryptionParameters.setEncryptionCredential(dataEncCredential);

        Credential keyEncCredential = SecurityHelper.getSimpleCredential(asymmetricKey.getPublicKey(), asymmetricKey.getPrivateKey());
        KeyEncryptionParameters keyEncryptionParameters=new KeyEncryptionParameters();
        keyEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15);
        keyEncryptionParameters.setEncryptionCredential(keyEncCredential);

        org.opensaml.saml2.encryption.Encrypter encrypter = new org.opensaml.saml2.encryption.Encrypter(encryptionParameters, keyEncryptionParameters);
        encrypter.setKeyPlacement(org.opensaml.saml2.encryption.Encrypter.KeyPlacement.PEER);
        return encrypter.encrypt(attribute);
    }

    private static Attribute createAttribute(String key, String value) {
        AttributeBuilder attributeBuilder = new AttributeBuilder();
        Attribute attribute = attributeBuilder.buildObject();
        attribute.setName(key);
        XSStringBuilder stringBuilder = new XSStringBuilder();
        XSString attributeValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        attributeValue.setValue(value);
        attribute.getAttributeValues().add(attributeValue);
        return attribute;
    }

    private static Element samlObject2DOM(SAMLObject samlObject) throws MarshallingException {
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(samlObject);
        return marshaller.marshall(samlObject);
    }
}
