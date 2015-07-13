#!/bin/sh
set -e

STDJ="-j4"
MAKE=${MAKE-make} # gmake
RUMPSRC=${PWD}/src

RUMPMAKE=${PWD}/obj/tooldir/rumpmake

BUILDRUMP=${PWD}/buildrump.sh

die ()
{
	echo '>>' $*
	exit 1
}

checkout()
{
	if ! [ -d ${RUMPSRC} ]; then
		${BUILDRUMP}/buildrump.sh checkout
	fi

	rm -rf "${RUMPSRC}/lib/librumpuser"
	cp -Rp librumpuser "${RUMPSRC}/lib/"

}

buildrump()
{
	${BUILDRUMP}/buildrump.sh \
		-V RUMPUSER_THREADS=fiber -V RUMP_CURLWP=hypercall \
		${1-fullbuild}
}

clean()
{
	rm -rf rump src obj
}

case $1 in
'clean')
	clean
	;;
'tests')
	buildrump tests
	;;
*)
	checkout
	buildrump
	;;
esac
