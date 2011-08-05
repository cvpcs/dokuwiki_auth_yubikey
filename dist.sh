#!/bin/bash

distfiles="
	conf
	inc
	README
	";

distname="dokuwiki_auth_yubikey"
date="$(date +%Y%m%d)"

zipname="${distname}-${date}.zip"
if [ -e ${zipname} ] ; then rm ${zipname}; fi
zip -r ${zipname} ${distfiles}

tgzname="${distname}-${date}.tar.gz"
if [ -e ${tgzname} ] ; then rm ${tgzname}; fi
tar -zcvf ${tgzname} ${distfiles}

tbzname="${distname}-${date}.tar.bz2"
if [ -e ${tbzname} ] ; then rm ${tbzname}; fi
tar -jcvf ${tbzname} ${distfiles}

tlzname="${distname}-${date}.tar.lzma"
if [ -e ${tlzname} ] ; then rm ${tlzname}; fi
tar --lzma -cvf ${tlzname} ${distfiles}

txzname="${distname}-${date}.tar.xz"
if [ -e ${txzname} ] ; then rm ${txzname}; fi
tar --xz -cvf ${txzname} ${distfiles}


