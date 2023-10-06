package net.usmans;

import rife.bld.Project;
import rife.bld.dependencies.Scope;

import java.util.List;
import java.util.jar.Attributes;

import static rife.bld.dependencies.Repository.MAVEN_CENTRAL;

public class V4keystore_converterBuild extends Project {
    public V4keystore_converterBuild() {
        pkg = "net.usmans";
        name = "V4keystore_converter";
        mainClass = "net.usmans.V4keystore_converterMain";
        version = version(0, 1, 0);

        downloadSources = true;
        autoDownloadPurge = true;
        repositories = List.of(MAVEN_CENTRAL);
        scope(Scope.compile)
                .include(dependency("info.picocli", "picocli", version(4, 7, 5)))
                .include(dependency("com.fasterxml.jackson.core", "jackson-databind", version(2, 15, 2)))
                .include(dependency("org.apache.tuweni", "tuweni-bytes", version(2, 3, 1)))
                .include(dependency("org.bouncycastle", "bcprov-jdk18on", version(1, 74)))
                .include(dependency("com.google.guava", "guava", version(32, 1, 2, "jre")))
                .include(dependency("org.slf4j", "slf4j-api", version(2, 0, 9)));

        scope(Scope.runtime)
                .include(dependency("org.bouncycastle", "bcpkix-jdk18on", version(1, 74)))
                .include(dependency("org.slf4j", "slf4j-simple", version(2, 0, 9)));

        jarOperation().manifestAttribute(Attributes.Name.MAIN_CLASS, mainClass());

        testOperation().mainClass("net.usmans.V4keystore_converterTest");
    }

    public static void main(String[] args) {
        new V4keystore_converterBuild().start(args);
    }
}
