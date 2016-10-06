#!/bin/sh

sudo apt-get update
sudo apt-get install -y git subversion binutils-dev gettext flex bison pkg-config \
    libglib2.0-dev nasm liblua5.1-0-dev libsigc++-2.0-dev \
    texinfo  expat libexpat1-dev python2.7-dev \
    automake libusb-dev g++ 
mkdir projects
(
    cd projects 
    git clone --branch eurecom/avatar https://github.com/eurecom-s3/s2e.git
    mkdir s2e-build
    (
        cd s2e-build
        make -f ../s2e/Makefile
    )
    git clone --branch eurecom/wip https://github.com/eurecom-s3/gdb.git 
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
    
    # Download Avatar and Avatar samples
    git clone --branch master https://github.com/eurecom-s3/avatar-python   
    cd avatar-python
    git checkout cbfaa6bcc8238a580833c02171ee860656daa906
    cd ..
    #sudo pip3.2 install git+https://github.com/eurecom-s3/avatar-python.git#egg=avatar
    git clone --branch master https://github.com/eurecom-s3/avatar-samples

    git clone --branch eurecom/wip https://github.com/eurecom-s3/openocd
    (
        cd openocd
        ./bootstrap
        ./configure
        make
        sudo make install
    )
)
