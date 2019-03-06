<b>Compare a section of bytes in multiple files, located after the entry point, to aid in the creation of packer detection yara rules</b>

This Yara rule generator takes the initial first 40 bytes after the Entry Point of a PE file, it then clusters these Hex Strings in similar clusters, and if a character repeatedly appears at a given index in over 80% of that cluster it will generate a rule from this data for to generate YARA rules if we know its packed with a certain packer. Larger datasets are definitely preferable, I'll add functionality to allow the user to adjust the weights soon

Example Command: ```python PEPackerPattern.py -d <directory>```
