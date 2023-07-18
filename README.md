Compile with:

`gcc generate_nor.c aes.c -o generate_nor -I/usr/local/Cellar/openssl@1.1/1.1.1l/include -L/usr/local/Cellar/openssl@1.1/1.1.1l/lib -lssl -lcrypto`

Create a directory named data and copy the following files from <b>iPod1,1_1.1_3A101a_Restore/Firmware/all_flash/all_flash.n45ap.production/</b>

`DeviceTree.n45ap.img2` <br>
`applelogo.img2` <br>
`batterylow0.img2` <br>
`batterylow1.img2` <br>
`needservice.img2` <br>
`batterycharging.img2` <br>
`recoverymode.img2` <br>

paste the files into the data directory

then use decryptor in the decryptor directory to go through each item and decrypt it. <br>

Syntax: decryptor [file in] [file out] (the file out name is just the original name minus the .img2 file ending


