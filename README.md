<b>Compare a section of bytes in multiple files, located after the entry point, to aid in the creation of packer detection yara rules</b>

This Yara rule generator takes the initial first 40 bytes after the Entry Point of a PE file, it then clusters these Hex Strings in similar clusters, and if a character repeatedly appears at a given index in over 90% (Changeable value) of that cluster it will generate a rule from this data for to generate YARA rules if we know its packed with a certain packer. Larger datasets are definitely preferable, the default character threshold is 90% and the default string comparison threshold is 70%
```usage: PEPackerPattern.py [-h] [-b <buffSize>] [-d <dir>] [-ct <1-100>]
                          [-st <1-100>]

Compare a section of bytes in multiple files, located after the entry point,
to aid in the creation of packer detection yara rules

optional arguments:
  -h, --help            show this help message and exit
  -b <buffSize>, --buffer <buffSize>
                        Specifies how many 0's to look for default is -
                        Default is 40 bytes
  -d <dir>, --dir <dir>
                        Specify directory of files to scan
  -ct <1-100>, --charthresh <1-100>
                        Specifiy how often a character should appear in a
                        cluster for it to be added to a rule, e.g. 90% of the
                        cluster = 90
  -st <1-100>, --stringthresh <1-100>
                        Specifiy how similar the hex data must be for the
                        string to be added to a cluster e.g. 80% similarity =
                        80

 ```
Example Commands: ```python PEPackerPattern.py -d <directory>```
                  ```python PEPackerPatter.py -d <dir> -ct 90 -st 70```
