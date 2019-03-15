FROM registry.centos.org/centos/centos:7

ENV PREP_DIR=/prep
ENV CVEJOB_CPE2PKG_PATH=/prep/tools/bin/cpe2pkg.jar
ENV CVEJOB_JAVA_PACKAGES_JAR=/prep/tools/bin/maven-packages.jar
ENV CVEJOB_PKGFILE_DIR=/prep/data
ENV GIT_COMMITTER_NAME=Bishop
ENV GIT_COMMITTER_EMAIL=fabric8.analytics.cve.bot@gmail.com
ENV GIT_AUTHOR_NAME=Bishop
ENV GIT_AUTHOR_EMAIL=fabric8.analytics.cve.bot@gmail.com
ENV NLTK_DATA=/nltk_data

RUN yum install -y epel-release https://centos7.iuscommunity.org/ius-release.rpm &&\
    yum install -y python36u python36u-devel python36u-pip java-1.8.0-openjdk-headless gcc git which npm make maven &&\
    yum clean all

RUN mkdir -p ${PREP_DIR}/data ${NLTK_DATA}

WORKDIR ${PREP_DIR}

COPY Makefile ${PREP_DIR}/
COPY tools ${PREP_DIR}/tools
COPY scripts ${PREP_DIR}/scripts

# cache dependencies
COPY requirements.txt /tmp/
RUN python3.6 -m pip install -r /tmp/requirements.txt
RUN python3.6 -c "import nltk; nltk.download('words')"
RUN python3.6 -c "import nltk; nltk.download('punkt')"
RUN python3.6 -c "import nltk; nltk.download('stopwords')"

RUN chmod 755 ${NLTK_DATA}

# This will take a while. Sit back and relax.
RUN make prep

COPY ./ /cvejob/

WORKDIR /cvejob

# cvejob needs to be able to create directories in workdir
RUN chmod -R 777 .

RUN python3.6 -m pip install -r requirements.txt

CMD ["/cvejob/cronjob-run.sh"]
