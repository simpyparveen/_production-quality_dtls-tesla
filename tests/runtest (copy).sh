for i in $(seq 5 20)
  do 
     echo "Welcome $i times"
	./dtls-client 127.0.0.1
 done



for i in $(seq 5 20)
  do 
     echo "Welcome $i times" > cf$i.txt
	
 done



for f in *.txt
do
	echo "File name is $f"
	while read -r line; do
 	 	if [[ "$line" == "Handshake complete with role :DTLS_CLIENT and hs_rtt: "*]] ; then echo $line; fi
	done < $f
done




while IFS= read -r line
do
#echo "$line"
  if [[ "$line" == *"apt"* ]]; then
    echo "$line"
  fi
done < results.txt




for f in cf*.txt
do
	
	while IFS= read -r line
	do
		if [[ "$line" == "RTT for sending file"* ]]; then
			echo "$line" | awk '{ print $2,$3,$4,$5 }'
		fi
	done < $f
done

# bash runreadfileDataLatency.sh
# Reading files to recover only data transfer latency from all files
