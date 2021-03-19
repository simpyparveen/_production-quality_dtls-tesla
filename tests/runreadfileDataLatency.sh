for f in cf*.txt
do
	echo "File name is $f"
	tag=$( tail -n 1 $f )
	#echo $tag
	echo "$tag" | awk '{ print $5 }'
	
done

# bash runreadfileDataLatency.sh
# Reading files to recover only data transfer latency from all files


