/*
 * File:   Assinador.java
 *
 * Created on 30/03/16, 09:58
 */
package br.com.nexas.emites.bhiss;

import org.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class Assinador {

    //constande de tranformacao da Chave
    private static final String C14N_TRANSFORM_METHOD = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    //metodo de assinatura
    @SuppressWarnings("unchecked")
    public void assinar(String caminhoXml, String caminhoCertificado, String senha, String caminhoXmlNovo,
        String tagGeracao, String tagInsercao, KeyStore.PrivateKeyEntry keyEntry, KeyStore ks){
        try{
            //tag a qual será gerado o assinador, ou seja, pelo fato da nfse poder ter mais de uma assinatura em
            //um só XML, é preciso que seja informada qual a tag, qual o intervalo, para a qual a assinatura será válida
            String tag = tagGeracao;

            //objeto responsável por abrir o documento XML
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(false);
            //objeto responsável pela construção do XML
            DocumentBuilder builder = factory.newDocumentBuilder();
            //abor o XML para o objeto docs
            Document docs = builder.parse(new File(caminhoXml));

            //marco na lista de tags, qual será assinada, procurando pelo nome da tag no documento
            NodeList listaTagsAssinar = docs.getElementsByTagName(tag);

            //percorro a lista de tags
            for(int i = 0; i < listaTagsAssinar.getLength(); i++){

                //verifico os elementos dentro da tag assinalada
                Element infNFe = (Element) listaTagsAssinar.item(i);

                String id = "";

                //tento obter o id da tag
                if (infNFe.hasAttribute("id")){
                    id = infNFe.getAttribute("id");
                }else if (infNFe.hasAttribute("Id")){
                    id = infNFe.getAttribute("Id");
                }else if (infNFe.hasAttribute("iD")){
                    id = infNFe.getAttribute("iD");
                }else if (infNFe.hasAttribute("ID")){
                    id = infNFe.getAttribute("ID");
                }else{
                    throw new Exception("Tag " + tag + " Não tem o atributo ID.");
                }

                //crio o objeto de assinatura do XML, por assim dizer
                XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());

                //crio a lista de transformação para a marcação <Transforms> da assinatura
                ArrayList transformList = new ArrayList();
                TransformParameterSpec tps = null;
                Transform envelopedTransform = signatureFactory.newTransform(Transform.ENVELOPED, tps);
                Transform c14NTransform = signatureFactory.newTransform(C14N_TRANSFORM_METHOD, tps);
                transformList.add(envelopedTransform);
                transformList.add(c14NTransform);

                //crio a marcação <Reference> da assinatura do documento, passando como URI da tag a string
                //"#" concatenada com o id encontrado anteriormente
                //é passado para as referencias o objeto de TRANSFORM criado anteriormente, devido ao fato do mesmo,
                //ser um nível dentro do <Reference>
                //pode-se perceber a criação do DigestMethod, o qual também é uma tag dentro de <Reference>
                Reference ref = signatureFactory.newReference("#" + id,
                                signatureFactory.newDigestMethod(DigestMethod.SHA1, null),
                                transformList, null, null);

                //crio a tag <CanonicalizationMethod>
                SignedInfo signedInfo = signatureFactory.newSignedInfo(signatureFactory.newCanonicalizationMethod(
                                        CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                                        signatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                                        Collections.singletonList(ref));

                //crio um objeto de KeyStore, o qual é responsável por colocar o certificado digital na assinatura,
                //para isso, é carregado o certificado digital
/*                KeyStore ks = null;
                ks = KeyStore.getInstance("PKCS12");
                ks.load(new FileInputStream(caminhoCertificado), senha.toCharArray());

                //pego o enumerado de alias do certificado
                Enumeration aliasesEnum = ks.aliases();
                String alias = "";
                //percorro a lista de alias
                while (aliasesEnum.hasMoreElements()) {

                    //pego elemento por elemento do certificado digital
                    alias = (String) aliasesEnum.nextElement();

                    //verifico as entradas do certificado digital
                    if (ks.isKeyEntry(alias)) {
                        // System.out.println(alias);
                        break;
                    }
                }

                //monto a chave privada a partir do entrada do alias, certificado e senha
                KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
                                                     new KeyStore.PasswordProtection(senha.toCharArray()));*/

                //pego o certificado digital montado da chave privada
                X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
                // Crio um KeyInfo com as informações da chave privada
                KeyInfoFactory kif = signatureFactory.getKeyInfoFactory();
                List x509Content = new ArrayList();

                //adiciono o certificado ao conteudo de assinatura
                x509Content.add(cert);
                X509Data xd = kif.newX509Data(x509Content);
                KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

                //Inicializo o documento a ser assinado
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setNamespaceAware(true);
                DocumentBuilder build = dbf.newDocumentBuilder();
                Document doc = build.parse(new File(caminhoXml));

                //tento pegar a informaação de ONDE o documento vai ser assinado,
                //essa marcação é para resolver o problema de várias assinaturas da NFSe, assim, é preciso informar
                //a tag onde vai ser encaixado a assinatura, por exemplo, se Não for informada tag nenhuma, a assinatura
                //será feita ao final do XML. Caso seja informada alguma tag (<InfRps>, exemplo), a assinatura será
                //feita após essa marcação
                Element inf = null;
                //verifico se existe taga para inserindo
                if (tagInsercao == null) {
                    //caso Não exista, assino o final do XML
                    inf = doc.getDocumentElement();
                }else{
                    //caso exista, busco a marcação no documento
                    NodeList lista= doc.getElementsByTagName(tagInsercao);
                    //busco a tag
                    inf = (Element) lista.item(0);
                }

                // Create a DOMSignContext and specify the RSA PrivateKey and
                // location of the resulting XMLSignature's parent element.
                DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), inf);

                XMLSignature signature = null;

                // Create the XMLSignature, but don't sign it yet.
                signature = signatureFactory.newXMLSignature(signedInfo, ki, null, "Ass_" + id, null);

                // Marshal, generate, and sign the enveloped signature.
                signature.sign(dsc);

                // Output the resulting document.
                OutputStream os = new FileOutputStream(caminhoXmlNovo);
                TransformerFactory tf = TransformerFactory.newInstance();
                Transformer trans = tf.newTransformer();
                trans.transform(new DOMSource(doc), new StreamResult(os));

                // Find Signature element.
                NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

                if (nl.getLength() == 0) {
                    throw new Exception("Cannot find Signature element");
                }

                // Create a DOMValidateContext and specify a KeySelector and document
                // context.
                DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(ks), nl.item(0));
                // Unmarshal the XMLSignature.
                XMLSignature signatures = signatureFactory.unmarshalXMLSignature(valContext);
                // Validate the XMLSignature.
                boolean coreValidity = signatures.validate(valContext);

                // Check core validation status.
                if (coreValidity == false) {
                    System.out.println("Falha na Assinatura");
                } else {
                    System.out.println("Assinatura Correta");
                }
            }

        }catch (Exception e){
            System.out.println("Não foi possível  gerar a assinatura do XML. \n" + e.getMessage());
            e.printStackTrace();
            return;
        }
    }
}
