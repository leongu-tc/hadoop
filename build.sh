#!/bin/bash

function build(){	
	mvn clean install -Pdist,native -DskipTests -Dtar
	if [ $? -ne 0 ];then
    	echo "[ERROR] cmd 'mvn clean install -Pdist,native -DskipTests -Dtar' execute fail"
    	return 1
	fi
	return 0
}

function rpm(){   
	echo "[INFO] start to rpm HADOOP"
	cd ${buildPath}
	chmod +x ${buildPath}/rpm-hadoop.sh
	${buildPath}/rpm-hadoop.sh ${binaryPath} ${last_changed_version} || exit 1
	echo "[INFO] end to rpm HADOOP"
	return 0
}

##
# main function
##
function _main(){
	echo "[INFO] start to build HADOOP"
	build
	if [ $? -ne 0 ];then
    	echo "[ERROR] build HADOOP failed"
    	exit 1;
	fi
	rpm
	if [ $? -ne 0 ];then
    	echo "[ERROR] rpm HADOOP failed"
    	exit 1;
	fi
	echo "[INFO] build HADOOP successfully"
}

BINDIR=`dirname "$0"`
cd $BINDIR
currentPath=`pwd`
last_changed_version=$1
export PATH=/usr/local/Cellar/openssl/1.0.2n/bin:$PATH
export OPENSSL_ROOT_DIR=/usr/local/Cellar/openssl/1.0.2n
export OPENSSL_INCLUDE_DIR=/usr/local/Cellar/openssl/1.0.2n/include
export OPENSSL_LIBRARIES=/usr/local/Cellar/openssl/1.0.2n/lib
binaryPath=${currentPath}/hadoop-dist/target/hadoop-2.7.2-SDP
buildPath=${currentPath}/build
export rpmbase=/data/rpm/build
_main
