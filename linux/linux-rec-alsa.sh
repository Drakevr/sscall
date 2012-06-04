#!/bin/sh
#
# Sample Linux ALSA recording script
# Pipe this over to sscall

arecord -r 8000 -f S16_LE -D default
