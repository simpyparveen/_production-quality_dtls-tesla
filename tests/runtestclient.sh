for i in $(seq 1 100)
  do 
     echo "Welcome $i times"
	./dtls-client 127.0.0.1 > cf$i.txt
 done


# RUN : sh runtestclient.sh
# ./dtls-client 136.159.7.172 > cf$i.txt


