#!/bin/bash

if [[ $_ == $0 || "$1" == ""  ]]; then
	printf "Usage:\tsource ""$0"

	printf "\n\nNOTE. Sourcing the script!\n"
else
	export COOKIE="$1"
	#export COOKIE="sessionid=fgfcwih8km8graxapw1t26xcb43g29iy;"
fi
