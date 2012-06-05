#!/bin/sh
#
# Sample OpenBSD recording script
# Pipe this over to sscall

aucat -r 8000 -C0:0 -e s16le -o -
