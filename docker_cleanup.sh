#!/bin/bash
# Copyright 2017 Théo Chamley
# Permission is hereby granted, free of charge, to any person obtaining a copy of 
# this software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
# to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
# BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM.

# Array to hold image IDs. Note that it is not necessary to provide the entire
# image ID. Just the first few characters is sufficient.
# Use "docker images" at the command prompt to find image IDs
# Image IDs are entered on the command line separate by a space.

# Changelog
# Added instructional language prior to script execution - DB

# Added ability to exit the script in the event that user failed to include
# a key requirement - DB

# Change code to use an environment variable for location to write image archives -DB

# Added option to not delete archived docker images after Docker reset
IMAGES=$@
clear

echo "This script is designed to help address the growth of the Docker.qcow2 file by:"
echo "1. backing up the image IDs you identify at the command line to a temp directory"
echo "2. removing any containers and images NOT listed below"
echo "3. deleting the Docker.qcow2 file"
echo "4. restoring your image backups"
echo "5. and offering to delete the those backup files."
echo 
echo "****You will loose all of your images if you do not provide the IMAGE IDs on the command line.****"
echo "The script will use the directory identified by the TMP_DIR environment variable,"
echo "or you may set this variable using the 'EXPORT TMP_DIR=<directory>' command prior to running the script." 
echo "If you need to exit this script for any reason please do so now."
read -p "Exit? [yes/no] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]
	then
		exit
	else	

		echo "Backup and restore the following images:"
		echo ${IMAGES}
		read -p "Are you sure? [yes/no] " -n 1 -r
		echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
	then
		exit
	fi
# Assign local variable to TMP_DIR location either from enviroment variable
# in profile or via EXPORT TMP_DIR command
my_dir=$(echo $TMP_DIR)
pushd $my_dir >/dev/null

# Use the Docker save command to save images
open -a Docker
echo "Saving images. Please note that large images can take some time to archive."
for image in ${IMAGES}; do
		echo "Saving ${image}"
		tar=$(echo -n ${image} | base64)
		docker save -o ${tar}.tar ${image}
		echo "Done."
done

echo -n "Quiting Docker"
osascript -e 'quit app "Docker"'
while docker info >/dev/null 2>&1; do
	echo -n "."
	sleep 1
done;
echo ""

echo "Removing the problem child --> Docker.qcow2 file"
rm ~/Library/Containers/com.docker.docker/Data/com.docker.driver.amd64-linux/Docker.qcow2

echo "Restarting Docker application."
open -a Docker
until docker info >/dev/null 2>&1; do
	echo -n "."
	sleep 1
done;
echo 

echo "Restart Complete!"

echo "Restoring images from archive."
for image in ${IMAGES}; do
	tar=$(echo -n ${image} | base64)
	docker load -q -i ${tar}.tar || exit 1
	echo "==> Done."
done

popd >/dev/null

# Delete archived Images
echo "Would you like it delete archived image(s)?"
echo ${IMAGES}
read -p "[yes/no] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
	then
		exit
	fi

echo "Deleting saved images."
cd $my_dir
rm *.tar
fi
