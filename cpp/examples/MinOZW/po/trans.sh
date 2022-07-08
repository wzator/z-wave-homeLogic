#!/bin/bash

xgettext -d MinOZW -o MinOZW.pot -k_ -s ../Main.cpp
msgfmt MinOZW.pot -o MinOZW.mo
