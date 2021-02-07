#!/bin/bash
####
# Dowloads latest state of source repository and updates this one.
####
# @author stev leibelt <artodeto@bazzline.net>
# @since 2021-02-01
####

function _cleanup_root ()
{
	local STRING_LENGTH_PATH_OF_THE_ROOT=$((${#PATH_TO_THE_ROOT} + 1)) #we have to add +1 to remove the "/"

	if [[ ${DEBUG} -eq 1 ]];
	then
		echo ":: PATH_OF_THIS_FILE >>${PATH_OF_THIS_FILE}<<."
		echo ":: PATH_TO_THE_ROOT >>${PATH_TO_THE_ROOT}<<."
		echo ":: STRING_LENGTH_PATH_OF_THE_ROOT >>${STRING_LENGTH_PATH_OF_THE_ROOT}<<."
	fi

	for ITEM_PATH in ${PATH_TO_THE_ROOT}/*
	do
		ITEM_NAME="${ITEM_PATH:${STRING_LENGTH_PATH_OF_THE_ROOT}}"

		if [[ ${ITEM_NAME} != "bin" ]];
		then
			if [[ ${DEBUG} -eq 1 ]];
			then
				echo ":: Delete >>${ITEM_PATH}<<"
			fi
			rm -fr ${ITEM_PATH}
		else
			if [[ ${DEBUG} -eq 1 ]];
			then
				echo ":: Keep >>${ITEM_PATH}<<"
			fi
		fi
	done
}

function _copy_source_to_root ()
{
	if [[ ${DEBUG} -eq 1 ]];
	then
		echo ":: Copy content of >>${PATH_TO_THE_PLUGIN_SOURCE}<< to >>${PATH_TO_THE_ROOT}<<"
	fi

	cp -a ${PATH_TO_THE_PLUGIN_SOURCE}/* ${PATH_TO_THE_ROOT}
}

function _update_readme ()
{
	if [[ ${DEBUG} -eq 1 ]];
	then
		echo ":: Prefixing >>${PATH_TO_THE_ROOT_README}<< with important information."
	fi

	cat > ${PATH_TO_THE_ROOT_README} <<DELIM
IMPORTANT INFORMATION
=====================

> This is a clone from https://git.kolab.org/diffusion/RPK/  
> For bug reports and pull requests, please go to https://kolab.org/

How to upgrade this clone
=========================

Execute the [synchronise_with_source.sh](bin/synchronise_with_source.sh) shell script.

DELIM

	if [[ ${DEBUG} -eq 1 ]];
	then
		echo ":: Attaching content of >>${PATH_TO_THE_SOURCE_README}<< to >>${PATH_TO_THE_ROOT}<<."
	fi

	cat ${PATH_TO_THE_SOURCE_README} >> ${PATH_TO_THE_ROOT_README}
}

function _update_source ()
{
	if [[ -d "${PATH_TO_THE_SOURCE}" ]];
	then
		if [[ ${DEBUG} -eq 1 ]];
		then
			echo ":: Source path exists."
			echo ":: Removing >>${PATH_TO_THE_SOURCE}<<."
		fi
		rm -fr "${PATH_TO_THE_SOURCE}"
	fi

	if [[ ${DEBUG} -eq 1 ]];
	then
		echo ":: Creating path >>${PATH_TO_THE_SOURCE}<<."
		echo ":: Cloning repository into >>${PATH_TO_THE_SOURCE}<<."
	fi

	mkdir -p "${PATH_TO_THE_SOURCE}"

	cd "${PATH_TO_THE_SOURCE}"

	$(git clone https://git.kolab.org/diffusion/RPK/roundcubemail-plugins-kolab.git .)

	LATEST_SOURCE_TAG=$(git tag | grep roundcubemail | sort -n | tail -n 1)

	if [[ ${LATEST_SOURCE_TAG} == ${LATEST_TAG} ]];
	then
		echo ":: No new tag available."
		echo "   Latest source tag >>${LATEST_SOURCE_TAG}<<."
		echo "   Is equal to latest tag >>${LATEST_TAG}<<."

		echo ""
		cd -

		exit
		echo "   Aborting"
	fi

	if [[ ${DEBUG} -eq 1 ]];
	then
		echo ":: Switching to latest tag >>${LATEST_SOURCE_TAG}<<."
	fi

	git checkout ${LATEST_SOURCE_TAG}

	cd -
}

function synchronise_from_source_repository ()
{
	#bo: variable declaration
	##independent section
	local CURRENT_WORKING_DIRECTORY=$(pwd)
	local DEBUG=0
	local PATH_OF_THIS_FILE=$(cd $(dirname "${BASH_SOURCE[0]}"); pwd)
	local LATEST_TAG=$(git tag | sort -n | tail -n 1)

	##dependent section
	local PATH_TO_THE_ROOT=$(cd "${PATH_OF_THIS_FILE}/../"; pwd)
	local PATH_TO_THE_SOURCE="${PATH_OF_THIS_FILE}/data/source"

	local PATH_TO_THE_PLUGIN_SOURCE="${PATH_TO_THE_SOURCE}/plugins/kolab_2fa"

	local PATH_TO_THE_ROOT_README="${PATH_TO_THE_ROOT}/README.md"
	local PATH_TO_THE_SOURCE_README="${PATH_TO_THE_PLUGIN_SOURCE}/README.md"
	#eo: variable declaration

	#bo: business logic
	_cleanup_root
	_update_source
	_copy_source_to_root
	_update_readme
	echo ""
	echo ":: Done"
	echo "   Please create latest tag >>${LATEST_SOURCE_TAG}<<."
	#eo: business logic
}

synchronise_from_source_repository
