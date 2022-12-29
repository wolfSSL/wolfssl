./setup.sh
for file in "benchmark" "client" "server" "test"; do
    cd ${IDF_PATH}/examples/protocols/wolfssl_${file}/ && idf.py build
    if [ $? -ne 0 ]; then
        echo "Failed in ${file}"
        break
    fi
done
