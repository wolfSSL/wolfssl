#!/bin/bash

POSIXLY_CORRECT=1

CHECK_API=false
GEN_HTML=false
GEN_PDF=false
GEN_ALL=false
INSTALL_DOX=false

find_cmd () {
    missing=""

    for cmd in "$@" ; do
        command -V $cmd 2> /dev/null
        if [ $? -ne "0" ]; then
            missing="$missing $cmd"
        fi
    done

    if [ -n "$missing"  ]; then
        echo
        echo "The following executables are missing. Please install:"
        echo " $missing"
        exit 1
    fi
}

# Checking arguments and setting appropriate option variables

for var in "$@"
do
    case $var in
    -install)
        INSTALL_DOX=true
        ;;
    -html)
        CHECK_API=true
        GEN_HTML=true
        ;;
    -pdf)
        CHECK_API=true
        GEN_PDF=true
        ;;
    -all)
        CHECK_API=true
        GEN_ALL=true
        ;;
    esac
done

# Checking if doxygen is already installed
# True - doxygen from "which doxygen" is used to generate documentation
# False - clones doxygen Release_1_8_13 and ./build/bin/ added to PATH

if [ $INSTALL_DOX = true ] && [ ! "$(which doxygen 2>/dev/null)" ]; then
    find_cmd git cmake g++ make
    mkdir -p build
    cd build
    echo "cloning doxygen 1.8.13..."
    git clone --depth 1 --branch Release_1_8_13 https://github.com/doxygen/doxygen
    cmake -G "Unix Makefiles" doxygen/
    make
    cd ..
    export PATH="./build/bin/:$PATH"
fi

# Runs script to check that all API with documentation match wolfSSL API
if [ $CHECK_API = true ]; then
    ./check_api.sh
fi

if [ $? = 1 ]; then
    echo "Not all API match"
    exit 1
fi

#HTML GENERATION
if [ $GEN_HTML = true ] || [ $GEN_ALL = true ]; then
    find_cmd doxygen
    cp -r formats/html/* ./
    echo "generating html..."
    doxygen Doxyfile
    cp html_changes/search/* html/search/
    cp html_changes/*.css html/
    cp html_changes/*.js html/
    rm footer.html header.html
    rm -rf html_changes
    rm mainpage.dox
    rm Doxyfile
    echo "finished generating html..."
    echo "To view the html files use a browser to open the index.html file located at doc/html/index.html"
fi

#PDF GENERATION
if [ $GEN_PDF = true ] || [ $GEN_ALL = true ]; then
    find_cmd make doxygen
    cp -r formats/pdf/* ./
    echo "generating pdf..."
    doxygen Doxyfile
    cd latex/
    make
    mv refman.pdf ../
    cd ..
    rm -rf latex/
    rm Doxyfile
    rm header.tex
    echo "finished generating pdf..."
fi
