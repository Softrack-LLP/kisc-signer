package kz;


import org.apache.catalina.startup.Tomcat;

public class Main {
    public static void main(String[] args) throws Exception {
        String contextPath = "/KiscSignManager";
        String appBase = ".";
        Tomcat tomcat = new Tomcat();
        tomcat.setPort(5001);
        tomcat.getHost().setAppBase(appBase);
        tomcat.addWebapp(contextPath, appBase);
        tomcat.start();
        tomcat.getServer().await();
    }
}