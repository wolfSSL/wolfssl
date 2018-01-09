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
if [ ! -e "build/bin/doxygen" ]; then
cd build
echo "cloning doxygen 1.8.13..."
git clone https://github.com/doxygen/doxygen --branch Release_1_8_13
cmake -G "Unix Makefiles" doxygen/
make
cd ..
fi
fi

if [ $1 = "-html" ] || [ $1 = "-all" ]; then
#HTML GENERATION
cp -r formats/html/* ./
echo "generating html..."
build/bin/doxygen Doxyfile
cp html_changes/search/* html/search/
cp html_changes/* html/
rm footer.html header.html
rm -rf html_changes
rm mainpage.dox
rm Doxyfile
echo "finished generating html..."
echo "To view the html files use a browser to open the index.html file located at documentation/html/index.html"
fi

#PDF GENERATION
if [ $1 = "-pdf" ] || [ $1 = "-all" ]; then
cp -r formats/pdf/* ./
echo "generating pdf..."
build/bin/doxygen Doxyfile
cd latex/
make
mv refman.pdf ../
cd ..
rm -rf latex/
rm Doxyfile
rm header.tex
echo "finished generating pdf..."
fi
