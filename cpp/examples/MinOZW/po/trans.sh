#!/bin/bash

xgettext -d MinOZW -o MinOZW.pot -k_ -s ../Main.cpp
msgfmt MinOZW.po -o MinOZW.mo
