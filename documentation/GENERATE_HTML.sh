#!/bin/sh

command -v g++
if [ $? -ne "0" ]; then
echo "Please install g++"
exit 1
fi

command -v cmake
if [ $? -ne "0" ]; then
echo "Please install cmake"
exit 1
fi

command -v git
if [ $? -ne "0" ]; then
echo "Please install git"
exit 1
fi

command -v make
if [ $? -ne "0" ]; then
echo "Please install make"
exit 1
fi

if [ ! -e "build" ]; then
echo "build directory not present...creating directory..."
mkdir build
cd build
echo "cloning doxygen 1.8.13..."
git clone https://github.com/doxygen/doxygen --branch Release_1_8_13
cmake -G "Unix Makefiles" doxygen/
make
cd ..
else
echo "build exists"
fi

build/bin/doxygen Doxyfile

cp html_changes/* html/
cp html_changes/search/* html/search/
