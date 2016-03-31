package br.com.nexas.emites.bhiss;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

/**
 * Unit test for simple App.
 */
public class AppTest 
    extends TestCase
{
    private static final String SRCXML = "rps.xml";
    private static final String DSTXML = "dstrps.xml";
    private static final String CERT = "cert.pfx";
    private static final String PWD = "123456";
    private static final String TAGGEN = "InfRps";
    private static final String TAGINS = "Rps";
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( AppTest.class );
    }

    /**
     * Rigourous Test :-)
     */
    public void testApp()
    {
        KeyStore ks = null;
        KeyStore.PrivateKeyEntry keyEntry = null;
        try
        {
            ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(CERT), PWD.toCharArray());
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
            keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
                new KeyStore.PasswordProtection(PWD.toCharArray()));
        } catch (IOException e)
        {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        } catch (CertificateException e)
        {
            e.printStackTrace();
        } catch (KeyStoreException e)
        {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e)
        {
            e.printStackTrace();
        }

        Assinador assinador = new Assinador();
        assinador.assinar(SRCXML, null, null, DSTXML, TAGGEN, TAGINS, keyEntry, ks);
/*        try
        {
            Thread.sleep(1000);
        } catch (InterruptedException e)
        {
            e.printStackTrace();
        }
        assinador.assinar("../dstrps.xml", CERT, PWD, "../dstlote.xml", "LoteRps", "GerarNfseEnvio");*/
        assertTrue( true );
    }
}
