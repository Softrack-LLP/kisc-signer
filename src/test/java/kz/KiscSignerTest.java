package kz;

/**
 * Created by magzhan on 3/14/17.
 */
import org.testng.annotations.Test;

import javax.servlet.ServletException;
import java.io.IOException;


public class KiscSignerTest {

    @Test(enabled = false)
    public void testDoGet() {
        KiscSigner kiscSigner=new KiscSigner();
        try {
            kiscSigner.doGet(null,null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
