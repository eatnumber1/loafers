#!/bin/zsh
emulate -L zsh
setopt err_exit
#setopt xtrace

if [[ "$(uname -s)" == "Darwin" ]]; then
	function libtoolize {
		glibtoolize "$@"
	}

	if [[ -x ${commands[brew]} ]]; then
		function aclocal {
			local pkg_config_prefix="$(brew --prefix pkg-config)"
			typeset -a args
			if [[ -d "$pkg_config_prefix" ]]; then
				args=( -I "$pkg_config_prefix/share/aclocal" )
			fi
			command aclocal "$args[@]" "$@"
		}
	fi
fi

libtoolize -i
aclocal -I m4
autoconf
autoheader
automake --add-missing

# vim:ft=zsh
