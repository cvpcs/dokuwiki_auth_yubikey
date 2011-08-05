#!/bin/bash

distfiles="
	conf
	inc
	README*
	";

distname="dokuwiki_auth_yubikey"
date="$(date +%Y%m%d)"

zipname="${distname}-${date}.zip"
if [ -e ${zipname} ] ; then rm ${zipname}; fi
zip -r ${zipname} ${distfiles}
md5sum ${zipname} > ${zipname}.md5sum
