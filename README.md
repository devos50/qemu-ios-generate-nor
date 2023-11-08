### Generating an iPod Touch 2G NOR Image (for QEMU-iOS)

This README contains the instructions on how to generate the NOR image for the iPod Touch 2G that can be read by [QEMU-iOS](https://github.com/devos50/qemu-ios).
For this, you will need the `iPod2,1_2.1.1_5F138_Restore.ipsw` file.

First, compile the binary with the following command:

```
gcc generate_nor.c aes.c -o generate_nor -I/usr/local/Cellar/openssl@3/3.0.7/include -L /usr/local/Cellar/openssl@3/3.0.7/lib -lssl -lcrypto
```

Depending on your OS, you might have to change the OpenSSL include and library paths.

Then, create a directory named `data` and copy the following files from `iPod2,1_2.1.1_5F138_Restore/Firmware/all_flash/all_flash.n72ap.production/` into the `data` directory:

```
applelogo.img3
batterylow0.img3
batterylow1.img3
dtree.img3
glyphcharging.img3
glyphplugin.img3
iboot.img3
llb.img3
needservice.img3
recoverymode.img3
```

Now run `generate_nor`, which should produce `nor.bin` in the root directory:

```
./generate_nor
```
