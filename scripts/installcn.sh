#!/bin/sh

# AdGuard Home 安装脚本

# 如果管道失败则退出脚本 (-e)，防止意外的文件名
# 扩展 (-f)，并将未定义的变量视为错误 (-u)。
set -e -f -u

# 函数 log 是 echo 的包装器，如果调用者
# 请求的详细级别大于 0，则写入 stderr。否则，它什么都不做。
log() {
	if [ "$verbose" -gt '0' ]; then
		echo "$1" 1>&2
	fi
}

# 函数 error_exit 是 echo 的包装器，写入 stderr 并停止
# 脚本执行，退出代码为 1。
error_exit() {
	echo "$1" 1>&2

	exit 1
}

# 函数 usage 打印关于如何使用脚本的说明。
#
# TODO(e.burkov): 记录每个选项。
usage() {
	echo 'install.sh: 用法: [-C cpu_type] [-h] [-O os] [-o output_dir]' \
		'[-r|-R] [-u|-U] [-v|-V] [-t tag]' 1>&2
	echo '' 1>&2
	echo '选项:' 1>&2
	echo '  -C cpu_type    CPU 类型 (amd64, 386, arm64, 等)' 1>&2
	echo '  -O os          操作系统 (linux, darwin, freebsd, openbsd)' 1>&2
	echo '  -o output_dir  输出目录 (默认: /opt)' 1>&2
	echo '  -r             重新安装' 1>&2
	echo '  -R             不重新安装' 1>&2
	echo '  -u             卸载' 1>&2
	echo '  -U             不卸载' 1>&2
	echo '  -v             详细输出' 1>&2
	echo '  -V             不详细输出' 1>&2
	echo '  -t tag         版本标签 (默认: 自动获取最新版本)' 1>&2
	echo '' 1>&2
	echo '示例:' 1>&2
	echo '  ./installcn.sh                           # 安装最新版本' 1>&2
	echo '  ./installcn.sh -t v1.0.0                # 安装指定版本' 1>&2
	echo '  ./installcn.sh -o /opt/adguardhome     # 指定安装目录' 1>&2

	exit 2
}

# 函数 maybe_sudo 如果 use_sudo 不等于 0，则以 root 权限运行传递的命令。
#
# TODO(e.burkov): 在所有地方使用，sudo_cmd 不加引号。
maybe_sudo() {
	if [ "$use_sudo" -eq 0 ]; then
		"$@"
	else
		"$sudo_cmd" "$@"
	fi
}

# 函数 is_command 检查命令是否存在于机器上。
is_command() {
	command -v "$1" >/dev/null 2>&1
}

# 函数 is_little_endian 检查 CPU 是否为小端序。
#
# 参见 https://serverfault.com/a/163493/267530。
is_little_endian() {
	# ASCII 字符 "I" 的八进制代码为 111。在两字节八进制
	# 显示模式 (-o) 下，hexdump 在小端序系统上会将其打印为 "000111"，
	# 在大端序系统上会打印为 "111000"。返回第六个
	# 字符以与数字 '1' 进行比较。
	#
	# 不要使用 echo -n，因为在存在 -n 标志的情况下，其行为
	# 在 POSIX 中是明确定义的。使用 hexdump 而不是 od，
	# 因为 OpenWrt 及其衍生版本有前者但没有后者。
	is_little_endian_result="$(
		printf 'I' \
			| hexdump -o \
			| awk '{ print substr($2, 6, 1); exit; }'
	)"
	readonly is_little_endian_result

	[ "$is_little_endian_result" -eq '1' ]
}

# 函数 check_required 检查机器上是否有必需的软件。必需的软件：
#
#   unzip (macOS) / tar (其他 unix 系统)
#
# curl/wget 在函数 configure 中检查。
check_required() {
	required_darwin="unzip"
	required_unix="tar"
	readonly required_darwin required_unix

	case "$os" in
	'freebsd' | 'linux' | 'openbsd')
		required="$required_unix"
		;;
	'darwin')
		required="$required_darwin"
		;;
	*)
		# 通常不应该发生，因为操作系统已经验证过了。
		error_exit "不支持的操作系统: '$os'"
		;;
	esac
	readonly required

	# 不要使用引号以获取单词分割。
	for cmd in $required; do
		log "检查 $cmd"
		if ! is_command "$cmd"; then
			log "必需软件的完整列表: [$required]"

			error_exit "需要 $cmd 才能通过此脚本安装 AdGuard Home"
		fi
	done
}

# 函数 check_out_dir 要求输出目录已设置且存在。
check_out_dir() {
	if [ "$out_dir" = '' ]; then
		error_exit '应该提供输出目录'
	fi

	if ! [ -d "$out_dir" ]; then
		log "将创建 $out_dir 目录"
	fi
}

# 函数 parse_opts 解析选项列表并验证其组合。
parse_opts() {
	while getopts "C:hO:o:rRuUvVt:" opt "$@"; do
		case "$opt" in
		C)
			cpu="$OPTARG"
			;;
		h)
			usage
			;;
		O)
			os="$OPTARG"
			;;
		o)
			out_dir="$OPTARG"
			;;
		R)
			reinstall='0'
			;;
		U)
			uninstall='0'
			;;
		r)
			reinstall='1'
			;;
		u)
			uninstall='1'
			;;
		V)
			verbose='0'
			;;
		v)
			verbose='1'
			;;
		t)
			tag="$OPTARG"
			;;
		*)
			log "错误的选项 $OPTARG"

			usage
			;;
		esac
	done

	if [ "$uninstall" -eq '1' ] && [ "$reinstall" -eq '1' ]; then
		error_exit '-r 和 -u 选项互斥'
	fi
}

# 函数 set_os 如果需要则设置 os 并验证值。
set_os() {
	# 如果需要则设置。
	if [ "$os" = '' ]; then
		os="$(uname -s)"
		case "$os" in
		'Darwin')
			os='darwin'
			;;
		'FreeBSD')
			os='freebsd'
			;;
		'Linux')
			os='linux'
			;;
		'OpenBSD')
			os='openbsd'
			;;
		*)
			error_exit "不支持的操作系统: '$os'"
			;;
		esac
	fi

	# 验证。
	case "$os" in
	'darwin' | 'freebsd' | 'linux' | 'openbsd')
		# 一切正常，继续。
		;;
	*)
		error_exit "不支持的操作系统: '$os'"
		;;
	esac

	# 记录。
	log "操作系统: $os"
}

# 函数 set_cpu 如果需要则设置 cpu 并验证值。
set_cpu() {
	# 如果需要则设置。
	if [ "$cpu" = '' ]; then
		cpu="$(uname -m)"
		case "$cpu" in
		'x86_64' | 'x86-64' | 'x64' | 'amd64')
			cpu='amd64'
			;;
		'i386' | 'i486' | 'i686' | 'i786' | 'x86')
			cpu='386'
			;;
		'armv5l')
			cpu='armv5'
			;;
		'armv6l')
			cpu='armv6'
			;;
		'armv7l' | 'armv8l')
			cpu='armv7'
			;;
		'aarch64' | 'arm64')
			cpu='arm64'
			;;
		'mips' | 'mips64')
			if is_little_endian; then
				cpu="${cpu}le"
			fi

			cpu="${cpu}_softfloat"
			;;
		'riscv64')
			cpu='riscv64'
			;;
		*)
			error_exit "不支持的 cpu 类型: $cpu"
			;;
		esac
	fi

	# 验证。
	case "$cpu" in
	'amd64' | '386' | 'armv5' | 'armv6' | 'armv7' | 'arm64' | 'riscv64')
		# 一切正常，继续。
		;;
	'mips64le_softfloat' | 'mips64_softfloat' | 'mipsle_softfloat' | 'mips_softfloat')
		# 这也是正确的。
		;;
	*)
		error_exit "不支持的 cpu 类型: $cpu"
		;;
	esac

	# 记录。
	log "cpu 类型: $cpu"
}

# 函数 fix_darwin 如果需要，为 macOS 执行一些配置更改。
#
# TODO(a.garipov): 在 v0.107.0 最终版本发布后删除。
#
# 参见 https://github.com/AdguardTeam/AdGuardHome/issues/2443。
fix_darwin() {
	if [ "$os" != 'darwin' ]; then
		return 0
	fi

	# 设置包扩展名。
	pkg_ext='zip'

	# 在 macOS 上将 AdGuard Home 安装到 /Applications 目录
	# 很重要。否则，它可能不会授予 AdGuard Home 足够的权限。
	out_dir='/Applications'
}

# 函数 fix_freebsd 执行一些修复以使其在 FreeBSD 上工作。
fix_freebsd() {
	if [ "$os" != 'freebsd' ]; then
		return 0
	fi

	rcd='/usr/local/etc/rc.d'
	readonly rcd

	if ! [ -d "$rcd" ]; then
		mkdir "$rcd"
	fi
}

# download_curl 使用 curl(1) 下载文件。第一个参数是 URL。
# 第二个参数是可选的，是输出文件。
download_curl() {
	curl_output="${2:-}"
	if [ "$curl_output" = '' ]; then
		curl -L -S -s "$1"
	else
		curl -L -S -o "$curl_output" -s "$1"
	fi
}

# download_wget 使用 wget(1) 下载文件。第一个参数是 URL。
# 第二个参数是可选的，是输出文件。
download_wget() {
	wget_output="${2:--}"

	wget --no-verbose -O "$wget_output" "$1"
}

# download_fetch 使用 fetch(1) 下载文件。第一个参数是
# URL。第二个参数是可选的，是输出文件。
download_fetch() {
	fetch_output="${2:-}"
	if [ "$fetch_output" = '' ]; then
		fetch -o '-' "$1"
	else
		fetch -o "$fetch_output" "$1"
	fi
}

# 函数 set_download_func 设置适当的函数来下载
# 文件。
set_download_func() {
	if is_command 'curl'; then
		# 继续使用默认值，download_curl。
		return 0
	elif is_command 'wget'; then
		download_func='download_wget'
	elif is_command 'fetch'; then
		download_func='download_fetch'
	else
		error_exit "需要 curl 或 wget 才能通过此脚本安装 AdGuard Home"
	fi
}

# 函数 set_sudo_cmd 设置适当的命令以在超级用户
# 权限下运行命令。
set_sudo_cmd() {
	case "$os" in
	'openbsd')
		sudo_cmd='doas'
		;;
	'darwin' | 'freebsd' | 'linux')
		# 继续使用默认值，sudo。
		;;
	*)
		error_exit "不支持的操作系统: '$os'"
		;;
	esac
}

# 函数 get_latest_tag 从 GitHub API 获取最新的 release tag。
get_latest_tag() {
	# GitHub API 端点获取最新 release
	api_url="https://api.github.com/repos/KS-OTO/AdGuardHome/releases/latest"

	log "正在从 GitHub 获取最新版本信息..."

	# 使用下载函数获取 API 响应
	api_response="$("$download_func" "$api_url" 2>/dev/null)"

	# 从 JSON 中提取 tag_name 字段
	latest_tag="$(echo "$api_response" | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4 | head -1)"

	if [ "$latest_tag" = '' ]; then
		log "无法从 GitHub 获取最新版本，将使用 'latest'"
		latest_tag='latest'
	else
		log "检测到最新版本: $latest_tag"
	fi

	echo "$latest_tag"
}

# 函数 configure 设置脚本的配置。
configure() {
	set_os
	set_cpu
	fix_darwin
	set_download_func
	set_sudo_cmd
	check_out_dir

	pkg_name="AdGuardHome_${os}_${cpu}.${pkg_ext}"

	# 如果未指定 tag，则从 GitHub 获取最新版本
	if [ "$tag" = '' ]; then
		tag="$(get_latest_tag)"
	fi

	url="https://gh-proxy.org/https://github.com/KS-OTO/AdGuardHome/releases/download/${tag}/${pkg_name}"
	agh_dir="${out_dir}/AdGuardHome"
	readonly pkg_name url agh_dir

	log "AdGuard Home 将安装到 $agh_dir"
}

# 函数 is_root 检查是否已授予 root 权限。
is_root() {
	user_id="$(id -u)"
	if [ "$user_id" -eq '0' ]; then
		log '脚本以 root 权限执行'

		return 0
	fi

	if is_command "$sudo_cmd"; then
		log '请注意，使用此脚本安装 AdGuard Home 需要 root 权限'

		return 1
	fi

	error_exit '使用此脚本安装 AdGuard Home 需要 root 权限，请以 root 权限重新启动'
}

# 函数 rerun_with_root 下载脚本，以 root 权限运行它，
# 并退出当前脚本。它将当前脚本的必要配置
# 传递给子脚本。
#
# TODO(e.burkov): 尝试避免重新启动。
rerun_with_root() {
	script_url='https://raw.githubusercontent.com/KS-OTO/AdGuardHome/master/scripts/installcn.sh'
	readonly script_url

	r='-R'
	if [ "$reinstall" -eq '1' ]; then
		r='-r'
	fi

	u='-U'
	if [ "$uninstall" -eq '1' ]; then
		u='-u'
	fi

	v='-V'
	if [ "$verbose" -eq '1' ]; then
		v='-v'
	fi

	t=''
	if [ "$tag" != '' ]; then
		t="-t $tag"
	fi

	readonly r u v t

	log '以 root 权限重新启动'

	# 将 curl/wget 与 echo 分组，这样如果前者在产生任何输出之前失败，
	# 后者会打印一个 exit 命令供后续 shell 执行，以防止它获得空输入
	# 并在这种情况下以零代码退出。
	{ "$download_func" "$script_url" || echo 'exit 1'; } \
		| $sudo_cmd sh -s -- -C "$cpu" -O "$os" -o "$out_dir" "$r" "$u" "$v" "$t"

	# 退出脚本。由于前一个管道的代码非零，
	# 由于 set -e，执行不会到达此点，以零退出。
	exit 0
}

# 函数 download 从 URL 下载文件并将其保存到
# 指定的文件路径。
download() {
	log "从 $url 下载包到 $pkg_name"

	if ! "$download_func" "$url" "$pkg_name"; then
		error_exit "无法从 $url 下载包到 $pkg_name"
	fi

	log "成功下载 $pkg_name"
}

# 函数 unpack 根据扩展名解压传递的存档。
unpack() {
	log "从 $pkg_name 解压包到 $out_dir"

	# shellcheck disable=SC2174
	if ! mkdir -m 0700 -p "$out_dir"; then
		error_exit "无法创建目录 $out_dir"
	fi

	case "$pkg_ext" in
	'zip')
		unzip "$pkg_name" -d "$out_dir"
		;;
	'tar.gz')
		tar -C "$out_dir" -f "$pkg_name" -x -z
		;;
	*)
		error_exit "意外的包扩展名: '$pkg_ext'"
		;;
	esac

	unpacked_contents="$(
		echo
		ls -l -A "$agh_dir"
	)"
	log "解压成功，内容: $unpacked_contents"

	rm "$pkg_name"
}

# 函数 handle_existing 检测现有的 AGH 安装并在需要时
# 处理删除它。
handle_existing() {
	if ! [ -d "$agh_dir" ]; then
		log '无需卸载'

		if [ "$uninstall" -eq '1' ]; then
			exit 0
		fi

		return 0
	fi

	existing_adguard_home="$(ls -1 -A "$agh_dir")"
	if [ "$existing_adguard_home" != '' ]; then
		log '检测到现有的 AdGuard Home 安装'

		if [ "$reinstall" -ne '1' ] && [ "$uninstall" -ne '1' ]; then
			error_exit \
				"要使用此脚本重新安装/卸载 AdGuard Home，请指定 '-r' 或 '-u' 标志之一"
		fi

		# TODO(e.burkov): 在 v0.107.1 发布后删除 stop。
		if (cd "$agh_dir" && ! ./AdGuardHome -s stop || ! ./AdGuardHome -s uninstall); then
			# 它不会终止脚本，因为 AGH 可能只是
			# 没有作为服务安装但出现在目录中。
			log "无法从 $agh_dir 卸载 AdGuard Home"
		fi

		rm -r "$agh_dir"

		log 'AdGuard Home 已成功卸载'
	fi

	if [ "$uninstall" -eq '1' ]; then
		exit 0
	fi
}

# 函数 install_service 尝试将 AGH 安装为服务。
install_service() {
	# 至少在 FreeBSD 上需要以 root 身份安装服务。
	use_sudo='0'
	if [ "$os" = 'freebsd' ]; then
		use_sudo='1'
	fi

	if (cd "$agh_dir" && maybe_sudo ./AdGuardHome -s install); then
		return 0
	fi

	log "安装失败，正在删除 $agh_dir"

	rm -r "$agh_dir"

	# 一些检测到具有 armv7 CPU 的设备与实际的 armv7 构建存在兼容性问题。
	# 我们应该尝试安装 armv5 二进制文件代替。
	#
	# 参见 https://github.com/AdguardTeam/AdGuardHome/issues/2542。
	if [ "$cpu" = 'armv7' ]; then
		cpu='armv5'
		reinstall='1'

		log "尝试使用 $cpu cpu"

		rerun_with_root
	fi

	error_exit '无法将 AdGuardHome 安装为服务'
}

# 入口点

# 设置配置变量的默认值。
reinstall='0'
uninstall='0'
verbose='0'
cpu=''
os=''
out_dir='/opt'
pkg_ext='tar.gz'
download_func='download_curl'
sudo_cmd='sudo'
tag=''

parse_opts "$@"

echo '启动 AdGuard Home 安装脚本'

configure
check_required

if ! is_root; then
	rerun_with_root
fi
# 需要权限。
fix_freebsd

handle_existing

download
unpack

install_service

printf '%s\n' \
	'AdGuard Home 现已安装并运行' \
	'您可以使用以下命令控制服务状态:' \
	"$sudo_cmd ${agh_dir}/AdGuardHome -s start|stop|restart|status|install|uninstall"
