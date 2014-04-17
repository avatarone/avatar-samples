#!/bin/sh

if [ x"$1" = x"on" ]
then
	ssh lucian "sispmctl -o 2"
else
	ssh lucian "sispmctl -f 2"
fi

true
