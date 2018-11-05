package kz;

import kz.gamma.xmldsig.JCPXMLDSigInit;
import org.apache.xml.security.Init;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.*;
import org.xml.sax.SAXException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import kz.gamma.jce.provider.GammaTechProvider;
import kz.gamma.tumarcsp.params.StoreObjectParam;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.codec.binary.Base64;
import java.util.Properties;

/**
 * Simple signer servlet
 * Created by magzhan on 3/14/17.
 */
@WebServlet(
        name = "KiscSigner",
        urlPatterns = {"/sign"})
public class KiscSigner extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        setEncoding(request, response);
        String unsignedXml= parseDataFromRequestParameters(request);
        signMessage(unsignedXml,response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        setEncoding(request, response);
        String unsignedXml= parseDataFromRequestBody(request);
        signMessage(unsignedXml, response);
    }

    /**
     * Выставить кодировки запросу и ответу
     */
    private void setEncoding(HttpServletRequest request, HttpServletResponse response) throws UnsupportedEncodingException {
        request.setCharacterEncoding("UTF-8");
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/xml");
    }

    private void signMessage(String unsignedXml,HttpServletResponse response) throws IOException {
        if(unsignedXml==null)
            return;

        KiskSecurityDetails kiskSecurityDetails = createKiskSecurityDetails();
        String signedXml = null;
        try {
            signedXml = signString(unsignedXml, kiskSecurityDetails);
        } catch (Exception e) {
            e.printStackTrace();
        }
        print(response,signedXml);

        // String responseXml = sendMessage(signedXml, "2", kiskSecurityDetails);
        //print(response, unsignedXml, signedXml, responseXml);
    }

    /**
     * Принт xml
     */
    private void print(HttpServletResponse response, String xml) throws IOException {
        PrintWriter out = response.getWriter();
        out.println(xml);
        out.close();
    }

    /**
     * Принт всех xml
     */
    private void print(HttpServletResponse response, String unsignedXml, String signedXml, String responseXml) throws IOException {
        PrintWriter out = response.getWriter();
        out.println("Xml");
        out.println(unsignedXml);
        out.println("Request");
        out.println(signedXml);
        out.println("Response");
        out.println(responseXml);
        out.close();
    }

    private String parseDataFromRequestParameters(HttpServletRequest req) throws IOException {
        Enumeration<String> parameterNames = req.getParameterNames();
        while (parameterNames.hasMoreElements()) {
            String paramName = parameterNames.nextElement();
            String[] paramValues = req.getParameterValues(paramName);
            return paramValues[0];
        }
        return null;
    }

    private String parseDataFromRequestBody(HttpServletRequest req) throws IOException {
        StringBuilder buffer = new StringBuilder();
        BufferedReader reader = req.getReader();
        String line;
        while ((line = reader.readLine()) != null) {
            buffer.append(line);
        }
        return buffer.toString();
    }

    /**
     * Инит SecurityDetails данными для тестового сервера КЦМР
     */
    private KiskSecurityDetails createKiskSecurityDetails() {
        final String filePath = "/allpay/KiscSigner/extra/kisc.properties";
        final Properties props = new Properties();
        try {
            props.load(new FileInputStream(filePath));
        } catch (IOException e) {
            e.printStackTrace();
        }
        String signKeyPath = props.getProperty("signKeyPath");
        String signKeyPassword = props.getProperty("signKeyPassword");
        String webserviceUrl = props.getProperty("webserviceUrl");
        String webserviceUsername = props.getProperty("webserviceUsername");
        String webservicePassword = props.getProperty("webservicePassword");
        return new KiskSecurityDetails(signKeyPath, signKeyPassword, webserviceUrl, webserviceUsername, webservicePassword);
    }

    /**
     * Отправить сообщение в КЦМР
     * @param message - xml
     * @param operationType - тип операции
     * @param securityDetails - объект класса KiskSecurityDetails, с данными сервера КЦМР
     * @return - ответ в виде xml
     */
    private String sendMessage(String message, String operationType, KiskSecurityDetails securityDetails) {
        String text;
        try {

            HttpClient client = new HttpClient();
            PostMethod postMethod = new PostMethod(securityDetails.getWebserviceUrl());
            String name = securityDetails.getWebserviceUsername();
            String password = securityDetails.getWebservicePassword();
            String authString = name + ":" + password; //Base64 encoding below=Base64(authString)

            byte[] encodedBytes = Base64.encodeBase64(authString.getBytes());
            System.out.println("encodedBytes " + new String(encodedBytes));
            String encoding =new String(encodedBytes);
            //"MTA0MnwxMzk0OmIwNzFjZmE4MTY=";
            postMethod.addRequestHeader("Authorization", "Basic " + encoding);
            postMethod.addRequestHeader("OperationType", operationType);
            StringRequestEntity requestEntity = new StringRequestEntity(message, "text/xml", "UTF-8");

            postMethod.setRequestEntity(requestEntity);
            client.setConnectionTimeout(50000);
            client.setTimeout(300000);
            client.executeMethod(postMethod);

            Header responseHeader = postMethod.getResponseHeader("Set-Cookie");
            if (responseHeader != null) {
                String sessionId = responseHeader.getValue();
            }
            //Get Response
            InputStream inputStream = postMethod.getResponseBodyAsStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
            StringBuilder builderRs = new StringBuilder();

            String aux;
            while ((aux = reader.readLine()) != null) {
                builderRs.append(aux).append("\n");
            }
            text = builderRs.toString();

        } catch (Exception e) {
            e.printStackTrace();
            return "Failed";
        }
        return text;
    }

    /**
     * Подписать xml
     * @param message - xml, которую нужно подписать
     * @param securityDetails - объект класса KiskSecurityDetails, с данными для сервера КЦМР
     */
    private String signString(String message, KiskSecurityDetails securityDetails) throws KeyStoreException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, XMLSecurityException, TransformerException {
        Security.addProvider(new GammaTechProvider());
        KeyStore store = KeyStore.getInstance("PKCS12", "GAMMA");
        store.load(new ByteArrayInputStream(securityDetails.getSignKeyPath().getBytes()), securityDetails.getSignKeyPassword().toCharArray());

        //Find alias
        String aliasKey = "";
        Enumeration en = store.aliases();
        while (en.hasMoreElements()) {
            StoreObjectParam profParam = (StoreObjectParam) en.nextElement();
            aliasKey = profParam.sn;
        }

        //Get private key
        PrivateKey privateKey = (PrivateKey) store.getKey(aliasKey, securityDetails.getSignKeyPassword().toCharArray());
        Certificate cert = store.getCertificate(aliasKey);

        //Get the XML Document object
        Document doc = xmlToDocument(message);

        //Init Security. This is needed for the Transforms
        Init.init();
        JCPXMLDSigInit.init();

        //Sign Document
        String signMethod = "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";
        String digestMethod = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
        assert doc != null;
        XMLSignature sig = new XMLSignature(doc, "", signMethod);
        String res = "";
        if (doc.getFirstChild() != null) {
            Node nodeHeader = doc.createElement("header");
            Node node = doc.createElement("security");
            node.appendChild(sig.getElement());
            nodeHeader.appendChild(node);
            NodeList nodeListBody = doc.getElementsByTagName("body");
            doc.getFirstChild().insertBefore(nodeHeader, nodeListBody.item(0));
            Transforms transforms = new Transforms(doc);
            transforms.addTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature");
            transforms.addTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
            sig.addDocument("#signedContent", transforms, digestMethod);
            sig.addKeyInfo((X509Certificate) cert);
            sig.sign(privateKey);
            StringWriter os = new StringWriter();
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer trans = tf.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(os));
            os.flush();
            res = os.toString();
            os.close();
        }
        return res;
    }

    /**
     * @param message - xml в виде string
     * @return - xml в виде документа
     */
    private Document xmlToDocument(String message) {
        try {
            InputStream is = new ByteArrayInputStream(message.getBytes());
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            return dbf.newDocumentBuilder().parse(is);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private class KiskSecurityDetails {

        private String signKeyPath;
        private String signKeyPassword;
        private String webserviceUrl;
        private String webserviceUsername;
        private String webservicePassword;

        KiskSecurityDetails(String signKeyPath, String signKeyPassword, String webserviceUrl,
                            String webserviceUsername, String webservicePassword) {
            this.signKeyPath = signKeyPath;
            this.signKeyPassword = signKeyPassword;
            this.webserviceUrl = webserviceUrl;
            this.webserviceUsername = webserviceUsername;
            this.webservicePassword = webservicePassword;
        }

        String getSignKeyPath() {
            return signKeyPath;
        }

        String getSignKeyPassword() {
            return signKeyPassword;
        }

        String getWebserviceUrl() {
            return webserviceUrl;
        }

        String getWebserviceUsername() {
            return webserviceUsername;
        }

        String getWebservicePassword() {
            return webservicePassword;
        }
    }
}
