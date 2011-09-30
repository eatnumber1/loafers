#!/bin/zsh
emulate -L zsh
setopt err_exit
#setopt xtrace

if [[ "$(uname -s)" == "Darwin" ]]; then
	function libtoolize {
		glibtoolize "$@"
	}

	function aclocal {
		typeset -a args
		if [[ -d "/usr/local/share/aclocal" ]]; then
			args=( -I "/usr/local/share/aclocal" )
		fi
		command aclocal "$@" "$args[@]"
	}
fi

libtoolize -i
aclocal -I m4
autoconf
autoheader
automake --add-missing

# vim:ft=zsh
