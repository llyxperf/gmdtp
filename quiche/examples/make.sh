cd ../.. & cargo build --examples --features="dtp"
rm -rf build
make dtptest-client
make dtptest-server
