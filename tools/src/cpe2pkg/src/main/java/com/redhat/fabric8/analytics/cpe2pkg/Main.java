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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.core.KeywordAnalyzer;
import org.apache.lucene.analysis.miscellaneous.PerFieldAnalyzerWrapper;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.RAMDirectory;
import org.owasp.dependencycheck.data.lucene.SearchFieldAnalyzer;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;

public class Main {

    private static final String VENDOR_FIELD = "vendor";
    private static final String PRODUCT_FIELD = "product";

    @Parameter(description = "query-string", required = true)
    private String query;

    @Parameter(names = { "--help", "-h" }, help = true)
    private boolean help;

    @Parameter(names = { "--pkgfile", "-p" }, description = "File cointaining list of package names")
    private String pkgFile = "packages";

    @Parameter(names = { "--top", "-t" }, description = "Number of top results to print")
    private Integer top = 10;

    public static void main(String[] args) throws IOException, ParseException {

        Main main = new Main();
        main.configureAndRun(args);
    }

    protected void configureAndRun(String[] args) throws IOException {

        JCommander jcmd = JCommander.newBuilder().addObject(this).build();
        jcmd.setProgramName("cpe2pkg");

        try {
            jcmd.parse(args);
        } catch (ParameterException e) {
            e.usage();
            System.exit(1);
        }

        if (this.help) {
            jcmd.usage();
            return;
        }

        run();
    }

    private void run() throws IOException {

        Analyzer analyzer = createSearchingAnalyzer();
        Directory index = buildIndex(analyzer);

        IndexReader reader = DirectoryReader.open(index);
        IndexSearcher searcher = new IndexSearcher(reader);

        try {
            Query q = new QueryParser(PRODUCT_FIELD, analyzer).parse(query);
            TopDocs docs = searcher.search(q, this.top);
            ScoreDoc[] hits = docs.scoreDocs;

            for (int i = 0; i < hits.length; ++i) {
                int docId = hits[i].doc;
                Document d = searcher.doc(docId);
                System.out.println((hits[i].score) + " " + d.get(VENDOR_FIELD) + ":" + d.get(PRODUCT_FIELD));
            }
        } catch (ParseException e) {
            System.err.println("Unable to parse given query: " + e.getMessage());
            System.exit(1);
        }
    }

    private Directory buildIndex(Analyzer analyzer) throws IOException {
        Directory index = new RAMDirectory();
        IndexWriterConfig config = new IndexWriterConfig(analyzer);
        IndexWriter w = new IndexWriter(index, config);

        List<String> packages = Files.readAllLines(Paths.get(this.pkgFile));
        for (String pkg : packages) {
            String[] gav = pkg.split(",");
            if (gav.length < 2) {
                // weird one, skipping...
                continue;
            }
            addDoc(w, gav[0], gav[1]);
        }

        w.commit();
        w.close();

        return index;
    }

    private void addDoc(IndexWriter w, String vendor, String product) throws IOException {
        Document doc = new Document();
        doc.add(new TextField(VENDOR_FIELD, vendor, Field.Store.YES));
        doc.add(new TextField(PRODUCT_FIELD, product, Field.Store.YES));
        w.addDocument(doc);
    }

    private Analyzer createSearchingAnalyzer() {
        final Map<String, Analyzer> fieldAnalyzers = new HashMap<>();
        final SearchFieldAnalyzer productFieldAnalyzer = new SearchFieldAnalyzer();
        final SearchFieldAnalyzer vendorFieldAnalyzer = new SearchFieldAnalyzer();
        fieldAnalyzers.put(VENDOR_FIELD, vendorFieldAnalyzer);
        fieldAnalyzers.put(PRODUCT_FIELD, productFieldAnalyzer);

        return new PerFieldAnalyzerWrapper(new KeywordAnalyzer(), fieldAnalyzers);
    }
}
