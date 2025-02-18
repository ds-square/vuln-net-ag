#!/bin/bash

for filename in dataset/*; do
	echo "$filename"
	{ echo "$filename" >> time_log.txt && time graph_gen.sh "$filename" -l ; } 2>> time_log.txt
done
wait
