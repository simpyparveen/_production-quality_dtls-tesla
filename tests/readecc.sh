for f in cf*.txt
do
	#echo "File name is $f"
	while IFS= read -r line
	do
		if [[ "$line" == "ECDSA KEYGEN Time "* ]]; then
			echo "$line" | awk '{ print $4, $7 }'
		fi
	done < $f
done

