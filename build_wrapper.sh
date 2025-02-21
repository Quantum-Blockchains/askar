 #!/bin/sh

RUST_VERSION=1.81.0
OS=ubuntu-latest
LIB=libaries_askar.so
TARGET=x86_64-unknown-linux-gnu
USE_CROSS=$true
CROSS_VERSION=0.2.4
ARCHITECTURE=linux-aarch64


echo "-----Install Rust toolchain-----"
rustup toolchain install stable-$TARGET 

echo "-----Build askar lib-----"
cargo build --lib --release --target $TARGET

echo "-----Copy $LIB to python wrapper-----"
cp target/$TARGET/release/$LIB wrappers/python/aries_askar/

echo "-----Install python dependencies-----"
cd wrappers/python
python3 -m pip install --upgrade pip
pip install setuptools wheel twine auditwheel

echo "-----Build wheel package-----"
python3 setup.py bdist_wheel --python-tag=py3 --plat-name=manylinux2014_x86_64
# echo "Build"
# if [ -n "$USE_CROSS" ]; then
#     cargo install --bins --git https://github.com/rust-embedded/cross --locked --tag v$CROSS_VERSION cross
#     # Required for compatibility with manylinux2014.
#     # https://github.com/briansmith/ring/issues/1728
#     if [ "$ARCHITECTURE" = "linux-aarch64" ]; then
#         export CFLAGS="-D__ARM_ARCH=8"
#     fi
#     cross build --lib --release --target $TARGET
# elif [ "$ARCHITECTURE" == "darwin-universal" ]; then
#     ./build-universal.sh
# else
#     cargo build --lib --release --target $TARGET
# fi

# echo "Create artifacts directory"
# mkdir release-artifacts
# cp target/$TARGET/release/$LIB release-artifacts/

# echo "Build python wrapper"

# echo "Install dependencies"
# cd wrappers/python
# python3 -m pip install --upgrade pip
# pip install setuptools wheel twine auditwheel

# echo "Fetch library artifacts"
# cp ../../release-artifacts/$LIB aries_askar/

# echo "Build wheel package"
# python3 setup.py bdist_wheel --python-tag=py3 --plat-name=manylinux2014_x86_64

echo "Run test"
pip install pytest pytest-asyncio dist/*
echo "-- Test SQLite in-memory --"
python3 -m pytest --log-cli-level=WARNING -k "not contention"
echo "-- Test SQLite file DB --"
TEST_STORE_URI=sqlite://test.db python3 -m pytest --log-cli-level=WARNING -k "not contention"
if [ -n "$POSTGRES_URL" ]; then
    echo "-- Test Postgres DB --"
    TEST_STORE_URI="$POSTGRES_URL" python3 -m pytest --log-cli-level=WARNING -k "not contention"
fi

echo "Audit wheel"
cd ../../
auditwheel show wrappers/python/dist/* | tee auditwheel.log
grep -q manylinux_2_17_ auditwheel.log


# rm -r release-artifacts