##### Follow the steps in the main branch

# About

This branch exists for debug purposes. It will boot the emulator into single user mode. This is a mode where the only accessible functionality comes from the command line. <br>
If you do not know how to use the command line or came here by mistake please use the `main` branch instead which will provide you with a stock iOS environment. <br>
Please note that to use this properly you will need to make further modifictions to your nand image as by default `/bin/sh` and many other core utilities are not available. <br>
The changes in question can be found under the nand repo in `SingleUserMode.md`. <br>
If you have not already generated your own filesystem using `Changes.md` it is highly recommended that you do so as the method is more robust than simply downloading the basic premodified filesystem.
