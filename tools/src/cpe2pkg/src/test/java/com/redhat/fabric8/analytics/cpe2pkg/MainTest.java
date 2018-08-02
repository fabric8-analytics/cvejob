package com.redhat.fabric8.analytics.cpe2pkg;

/*
 * Copyright 2018 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.HashSet;
import java.util.Set;

import org.apache.lucene.queryparser.classic.ParseException;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class MainTest {

    private static final String pkgFile = "src/test/resources/packages.csv";

    private static PrintStream outBackup;
    private static PrintStream errBackup;

    private ByteArrayOutputStream out;
    private ByteArrayOutputStream err;

    @BeforeClass
    public static void beforeClass() {
        outBackup = System.out;
        errBackup = System.err;
    }

    @Before
    public void before() {
        this.out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));

        this.err = new ByteArrayOutputStream();
        System.setErr(new PrintStream(err));
    }

    @AfterClass
    public static void afterClass() {
        if (outBackup != null) {
            System.setOut(outBackup);
        }

        if (errBackup != null) {
            System.setErr(errBackup);
        }
    }

    @Test
    public void sanityTest() throws IOException, ParseException {
        assertTrue("Bug in tests", this.out.toString().length() == 0);

        Main main = new Main();
        main.configureAndRun(new String[]{"--pkgfile", pkgFile, "--top", "1", "vendor:( apache poi ) AND product:( poi )"});

        String[] lines = this.out.toString().split("\n");
        assertTrue(lines.length == 1);
        String[] resultPair = lines[0].split(" ");
        assertTrue(resultPair.length == 2);
        assertTrue(resultPair[1], resultPair[1].equals("org.apache.poi:poi"));
    }

    @Test
    public void noDuplicatesTest() throws IOException, ParseException {
        assertTrue("Bug in tests", this.out.toString().length() == 0);

        Main main = new Main();
        main.configureAndRun(new String[]{"--pkgfile", pkgFile, "--top", "1", "vendor:( apache poi ) AND product:( poi )"});

        String[] lines = this.out.toString().split("\n");

        Set<String> resultSet = new HashSet<String>();
        for (String line: lines) {
            String[] resultPair = line.split(" ");
            assertTrue(resultPair.length == 2);
            resultSet.add(resultPair[1]);
        }
        assertTrue(resultSet.size() == lines.length);
    }
}
