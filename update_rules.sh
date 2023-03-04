#!/bin/bash
set -euo pipefail

wget_no_verbose() {
    wget -nv "$@"
}

rm -rf rules rules.tar.gz

trap 'rm -rf "$TEMPDIR"' EXIT

TEMPDIR="$(mktemp -d)"
readonly TEMPDIR

pushd "$TEMPDIR"

# update config file
wget_no_verbose -qO- 'https://raw.githubusercontent.com/vokins/yhosts/master/dnsmasq/union.conf' | sed 's/=\/./ \//; s/0.0.0.0/#/' - >yhosts_union.ad.conf.tmp &
wget_no_verbose -qO- 'https://cokebar.github.io/gfwlist2dnsmasq/dnsmasq_gfwlist.conf' | sed 's/127.0.0.1#5353/secure/; s/server/nameserver/' - >gfwlist.conf.tmp &
wget_no_verbose -O googlehosts.conf.tmp 'https://raw.githubusercontent.com/googlehosts/hosts/master/hosts-files/dnsmasq.conf' &
wget_no_verbose -O googlehosts_ipv6.conf.tmp 'https://raw.githubusercontent.com/googlehosts/hosts-ipv6/master/hosts-files/dnsmasq.conf' &
wget_no_verbose -O anti-ad.ad.conf.tmp 'https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-smartdns.conf' &
wget_no_verbose -O hblock.ad.conf.tmp 'https://hblock.molinero.dev/hosts_dnsmasq.conf' &
wait

sed -i '/^#/d; /^$/d; s/=/ /' ./*.conf.tmp

# update hosts
wget_no_verbose -O adguard.hosts.tmp 'https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardDNS.txt' &
wget_no_verbose -O Peter_Lowe.hosts.tmp 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&mimetype=plaintext' &
wget_no_verbose -qO- 'https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts.txt' | sed '/^@/d' - >yhosts.hosts.tmp &
wget_no_verbose -O adwars.hosts.tmp 'https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts' &
wget_no_verbose -O neohosts.hosts.tmp 'https://cdn.jsdelivr.net/gh/neoFelhz/neohosts@gh-pages/full/hosts' &
wget_no_verbose -O adaway.hosts.tmp 'https://adaway.org/hosts.txt' &
wait

cat ./*.hosts.tmp >all.hosts.tmp
dos2unix all.hosts.tmp
sed -i '/^#/d; /localhost/d; /loopback/d; /^$/d; s/127.0.0.1/#/; s/0.0.0.0/#/; s/::/#/; s/\t/ /g' all.hosts.tmp
sort -u all.hosts.tmp ./*.ad.conf.tmp | awk '/^#/ {printf"address /%s/%s\n",$2,$1}' >all_block.conf.tmp

# allowlist
wget_no_verbose -qO- 'https://raw.githubusercontent.com/vokins/yhosts/master/data/moot/cps.txt' | sed '/^@/d' - >allowlist_cps.txt

sed '/^#/d' allowlist_*.txt | awk '{print $2}' >allowlist.txt
while IFS= read -r allowed; do
    sed -i "/$allowed/d" all_block.conf.tmp
done < <(grep -v '^ *#' <allowlist.txt)

rm ./*.ad.conf.tmp ./*.hosts.tmp ./*.txt

if hash rename.ul; then
    rename() {
        rename.ul "$@"
    }
fi
rename .tmp '' ./*.conf.tmp

popd

cp -rT "$TEMPDIR" rules

tar --sort=name \
    --mtime='@0' \
    --owner=0 --group=0 --numeric-owner \
    --format=ustar \
    -c -I 'pigz -n -11 -O -I100' -C rules -f rules.tar.gz .
