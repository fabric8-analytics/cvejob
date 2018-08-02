package io.openshift.analytics.packages;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import org.apache.lucene.document.Document;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.MultiFields;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.util.Bits;
import org.apache.maven.index.ArtifactInfo;
import org.apache.maven.index.Indexer;
import org.apache.maven.index.context.IndexCreator;
import org.apache.maven.index.context.IndexUtils;
import org.apache.maven.index.context.IndexingContext;
import org.apache.maven.index.updater.IndexUpdateRequest;
import org.apache.maven.index.updater.IndexUpdateResult;
import org.apache.maven.index.updater.IndexUpdater;
import org.apache.maven.index.updater.ResourceFetcher;
import org.apache.maven.index.updater.WagonHelper;
import org.apache.maven.wagon.Wagon;
import org.apache.maven.wagon.events.TransferEvent;
import org.apache.maven.wagon.events.TransferListener;
import org.apache.maven.wagon.observers.AbstractTransferListener;
import org.codehaus.plexus.DefaultContainerConfiguration;
import org.codehaus.plexus.DefaultPlexusContainer;
import org.codehaus.plexus.PlexusConstants;
import org.codehaus.plexus.PlexusContainer;
import org.codehaus.plexus.PlexusContainerException;
import org.codehaus.plexus.component.repository.exception.ComponentLookupException;
import org.eclipse.aether.version.InvalidVersionSpecificationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/*
 * Crawl through Maven Central index and print out all package names.
 * 
 * @see https://github.com/apache/maven-indexer/blob/master/indexer-examples/indexer-examples-basic/src/main/java/org/apache/maven/indexer/examples/BasicUsageExample.java
 */
public class MavenPackages {

    private final Logger logger = LoggerFactory.getLogger(MavenPackages.class);;
    private final static String MAVEN_URL = "https://repo1.maven.org/maven2";
    private final PlexusContainer plexusContainer;
    private final Indexer indexer;
    private final IndexUpdater indexUpdater;
    private final Wagon httpWagon;

    public static void main(String[] args) throws Exception {

        new MavenPackages().perform();
    }

    private MavenPackages() throws PlexusContainerException, ComponentLookupException {

        final DefaultContainerConfiguration config = new DefaultContainerConfiguration();
        config.setClassPathScanning(PlexusConstants.SCANNING_INDEX);

        this.plexusContainer = new DefaultPlexusContainer(config);
        this.indexer = plexusContainer.lookup(Indexer.class);
        this.indexUpdater = plexusContainer.lookup(IndexUpdater.class);
        this.httpWagon = plexusContainer.lookup(Wagon.class, "http");
    }

    private void perform() throws IOException, ComponentLookupException, InvalidVersionSpecificationException {
        File centralLocalCache = new File(System.getProperty("centralLocalCache", "target/central-cache"));
        File centralIndexDir = new File(System.getProperty("centralIndexDir", "target/central-index"));

        List<IndexCreator> indexers = new ArrayList<IndexCreator>();
        indexers.add(plexusContainer.lookup(IndexCreator.class, "min"));

        IndexingContext centralContext = indexer.createIndexingContext("central-context", "central", centralLocalCache,
                centralIndexDir, MAVEN_URL, null, true, true, indexers);

        Date previousCheck;
        {
            logger.info("Updating Index...");
            logger.info("This might take a while on first run, so please be patient!");

            TransferListener listener = new AbstractTransferListener() {
                public void transferStarted(TransferEvent transferEvent) {
                    logger.info("  Downloading " + transferEvent.getResource().getName());
                }

                public void transferProgress(TransferEvent transferEvent, byte[] buffer, int length) {
                }

                public void transferCompleted(TransferEvent transferEvent) {
                    logger.info(" - Done");
                }
            };
            ResourceFetcher resourceFetcher = new WagonHelper.WagonFetcher(httpWagon, listener, null, null);
            previousCheck = centralContext.getTimestamp();

            if (previousCheck == null) {
                previousCheck = new Date(0);
            }
            IndexUpdateRequest updateRequest = new IndexUpdateRequest(centralContext, resourceFetcher);
            IndexUpdateResult updateResult = indexUpdater.fetchAndUpdateIndex(updateRequest);
            if (updateResult.isFullUpdate()) {
                logger.info("Full update happened!");
            } else if (updateResult.getTimestamp().equals(previousCheck)) {
                logger.info("No update needed, index is up to date!");
            } else {
                logger.info("Incremental update happened, change covered " + previousCheck + " - "
                        + updateResult.getTimestamp() + " period.");
            }
        }

        logger.info("Reading index...");

        final Set<Package> packages = new HashSet<Package>();

        final IndexSearcher searcher = centralContext.acquireIndexSearcher();
        try {
            final IndexReader ir = searcher.getIndexReader();
            Bits liveDocs = MultiFields.getLiveDocs(ir);
            for (int i = 0; i < ir.maxDoc(); i++) {
                if (liveDocs == null || liveDocs.get(i)) {
                    final Document doc = ir.document(i);
                    final ArtifactInfo ai = IndexUtils.constructArtifactInfo(doc, centralContext);

                    if (ai == null || !"jar".equals(ai.getPackaging())) {
                        continue;
                    }
                    packages.add(new Package(ai.getGroupId(), ai.getArtifactId()));
                }
            }
        } finally {
            centralContext.releaseIndexSearcher(searcher);
        }

        for (Package p : packages) {
            System.out.println(p);
        }

        indexer.closeIndexingContext(centralContext, false);
    }
}
