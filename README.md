psvimgtools
===========
This is a set of tools that let you decrypt, extract, and repack Vita CMA backup images. To use this you need your backup key which is tied to your PSN AID.

## Building

You should have `cmake` and `zlib` installed. To enable hardware accelerated crypto, make sure `libgcrypt` is installed. Windows users should install either Cygwin or Bash on Ubuntu for Windows.

Then just run
```
mkdir build && cd build
cmake ..
make
```

## Usage

### psvimg-extract

This is used to extract `.psvimg` files. The extracted output includes a directory for each backup set (e.g: `ur0:appmeta`, `ux0:iconlayout.ini`, and `ur0:tmp/registry` are three separate sets). Each backup set contains zero or more files and directories. A special file `VITA_PATH.TXT` is created for each set to remember what the original path was before extraction (this is used for repacking). A set can be only a single file (for example `ux0:iconlayout.ini`). In that case, the file `VITA_DATA.BIN` is created to host the contents of the file.

### psvmd-decrypt

This decrypts and decompresses `.psvmd` files. The contents of which are defined in `psvimg.h`. This contains information such as the firmware version of the system that created the backup and the unique PSID of the system. Extracting this file is not required for repacking and is provided for reverse engineering/debugging purposes.

### psvimg-create

This repacks extracted files and creates the associated `.psvimg` and `.psvmd` files. If you have a _decrypted_ `.psvmd`, you may pass it in with `-m` and the tool will reuse as many fields as possible (exception: size fields). No validity checks will be performed. If you do not have a decrypted `.psvmd`, you should use the `-n` option and specify the name of the backup. You should use the same name (the file name without the `.psvimg` extension) when repacking because CMA does check for a valid name. For example, if you are repacking `license.psvimg`, you should specify `-n license`.

The pack input directory should follow the same format as the output of `psvimg-extract`. The means a separate directory for each backup set (there may only be one set, in which your input directory will contain one subdirectory) each with a `VITA_PATH.TXT` file specifying the Vita path and optionally a `VITA_DATA.BIN` file if the set is a file.

Note that CMA does check the paths of the backup sets. Trying to add a backup set with a custom path may result in failure.

## psvimg-keyfind

This is a brute-force backup key find tool. You should generate a valid `partials.bin` file using the provided "dump_partials" Vita homebrew that runs on HENkaku enabled consoles. You can generate partials for other people as well if you know their AID. The `partials.bin` file does not contain any console-unique information but is derived from the provided PSN AID. The AID is the 16 hex characters in your CMA backup path. For example, if I wish to decrypt `PS Vita/PGAME/xxxxxxxxxxxxxxxx/NPJH00053/game/game.psvimg` then my AID is `xxxxxxxxxxxxxxxx`.

The `-n` option specifies the number of threads to run. On Linux, each thread tries to run on a separate processor. On OSX/Windows, it is up to the scheduler to make such decisions. You should not specify too high of a number here, as running multiple threads on a single CPU will result in diminishing returns. A good rule of thumb is to specify the number of CPU cores on your system.
