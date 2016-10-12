#!/bin/sh

sudo apt-get install -y software-properties-common python-software-properties
sudo add-apt-repository -y ppa:team-gcc-arm-embedded/ppa 
sudo apt-get update
sudo apt-get install -y git subversion binutils-dev gettext flex bison pkg-config \
    libglib2.0-dev nasm liblua5.1-0-dev libsigc++-2.0-dev \
    texinfo  expat libexpat1-dev python2.7-dev \
    automake g++ libusb-1.0-0-dev gcc-arm-embedded
mkdir projects
(
    cd projects 
    git clone --branch eurecom/avatar https://github.com/eurecom-s3/s2e.git
    mkdir s2e-build
    (
        cd s2e-build
        make -f ../s2e/Makefile
    )
    git clone --branch cortex-m https://github.com/eurecom-s3/gdb.git 
    mkdir gdb-build
    (
        cd gdb-build
        ../gdb/configure --with-python --with-expat=yes --target=arm-none-eabi
        make -j4
    )
    
    # Install Python3 and dependencies
    sudo apt-get install -y python3 python3-setuptools
    # pip version < 8 required for Python 3.2
    wget https://github.com/pypa/pip/archive/7.1.2.tar.gz
    tar -xzf 7.1.2.tar.gz
    cd pip-7.1.2/
    sudo python3 setup.py install
    cd ..
    sudo pip install future
    
    # Download Avatar and Avatar samples
    git clone --branch master https://github.com/eurecom-s3/avatar-python   
    sudo pip3.2 install git+https://github.com/eurecom-s3/avatar-python.git#egg=avatar
    git clone --branch master https://github.com/eurecom-s3/avatar-samples

    git clone --branch cortex-m https://github.com/eurecom-s3/openocd
    (
        cd openocd
        ./bootstrap
        ./configure
        make
        sudo make install
    )
)
