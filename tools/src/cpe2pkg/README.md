# cpe2pkg

cpe2pkg is a small utility which can help you to identify actual package names when you only have partial information.

Current version only supports Maven.


## How to build

```shell
$ mvn clean verify
```

## How to run

You will need a CSV file containing a list of all existing groupId,artifactId pairs.

```shell
$ head -5 ~/packages
am.ik.blog,blog-domain
at.favre.lib,bytes
biz.ostw,fsi
br.com.moip,jassinaturas
ca.derekcormier.recipe,recipe-generator
```

You can then run the following command to perform search:

```
$ cd target/
$ java -jar cpe2pkg-0.2.0-jar-with-dependencies.jar --pkgfile ~/packages --top 3 'vendor:( apache poi ) AND product:( poi )'
9.472723 org.apache.poi:poi
8.971347 poi:poi
8.960626 org.apache.poi.DELETE:poi
```

The command above will print top 3 results for given query, together with confidence score.
