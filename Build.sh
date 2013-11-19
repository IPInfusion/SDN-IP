#!/bin/sh

TOPDIR=`pwd`


# Build open source
cd ${TOPDIR}/Opensource/onion
cmake .
make

# Configure BGP-SDN
cd ${TOPDIR}/BGP-SDN
./configure --enable-bgp --disable-memmgr --enable-bgp-sdn

# Build BGP-SDN
cd ${TOPDIR}/BGP-SDN/platform/linux
make all

cd ${TOPDIR}
