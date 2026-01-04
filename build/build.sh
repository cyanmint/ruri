if [ -f /etc/resolv.conf ]; then
    rm /etc/resolv.conf
fi
echo nameserver 1.1.1.1 >/etc/resolv.conf

# Source build environment variables if available
if [ -f /build_env.sh ]; then
    . /build_env.sh
fi

apk update --no-cache
for i in wget make clang git libseccomp-dev libseccomp-static libcap-static libcap-dev xz-dev libintl libbsd-static libsemanage-dev libselinux-utils libselinux-static xz-libs zlib zlib-static libselinux-dev linux-headers libssl3 libbsd libbsd-dev gettext-libs gettext-static gettext-dev gettext python3 build-base openssl-misc openssl-libs-static openssl zlib-dev xz-dev openssl-dev automake libtool bison flex gettext autoconf gettext sqlite sqlite-dev pcre-dev wget texinfo docbook-xsl libxslt docbook2x musl-dev gettext gettext-asprintf gettext-dbg gettext-dev gettext-doc gettext-envsubst gettext-lang gettext-libs gettext-static
do
    if apk search -q $i >/dev/null 2>&1; then
        apk add $i || true
    fi
done

for package in upx lld; do
    if apk search -q $package >/dev/null 2>&1; then
        apk add $package || true
    fi
done

mkdir output output2 output3

# Use environment variables if set, otherwise use defaults
REPO_URL="${GITHUB_REPOSITORY_URL:-https://github.com/moe-hacker/ruri.git}"
COMMIT_SHA="${GITHUB_SHA:-}"

if [ -n "$COMMIT_SHA" ]; then
    # Clone with all branches and checkout the specific commit
    echo "Cloning from $REPO_URL and checking out $COMMIT_SHA"
    git clone --no-single-branch "$REPO_URL" ruri || git clone "$REPO_URL" ruri
    cd ruri
    git checkout "$COMMIT_SHA" 2>/dev/null || {
        echo "Failed to checkout $COMMIT_SHA, trying to fetch it"
        git fetch origin "$COMMIT_SHA" 2>/dev/null || true
        git checkout "$COMMIT_SHA" 2>/dev/null || {
            echo "Warning: Could not checkout $COMMIT_SHA, using current HEAD"
            git checkout HEAD
        }
    }
else
    # Fallback to shallow clone of default branch
    git clone --depth 1 "$REPO_URL" ruri
    cd ruri
fi

echo "Building from commit: $(git rev-parse --short HEAD)"

cc build.c -o build-ruri
./build-ruri -s -f

cp ruri ../output/ruri
cp LICENSE ../output/LICENSE

cp ruri ../output2/ruri
cp LICENSE ../output2/LICENSE

./build-ruri -s -c -f
cp ruri ../output3/ruri
cp LICENSE ../output3/LICENSE

if command -v upx >/dev/null 2>&1; then
    cd ..
    upx --best output2/ruri
    upx --best output3/ruri
fi
# WTF? shell is not like rust!
exit $?