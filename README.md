# NAME
tnt2 - a program the encrypts/decrypts files using an infinite (with respect to the plaintext) key.

# Usage:
  **tnt2** [command]

## Available Commands:
      completion  generate the autocompletion script for the specified shell
      decode      Decode a TNT2 encoded file.  
      encode      Encode plaintext using TNT2  
      help        Help about any command
      version     Display version information

## Flags:
          --config string         config file (default is $HOME/.tnt2.yaml)\n      
      -h, --help                  help for tnt2
      -i, --inputFile string      Name of the plaintext file to encrypt/decrypt. (default "-")
      -o, --outputFile string     Name of the file containing
      -f, --proformafile string   Name of file containing the proforma machine to use.
      -v, --version               version for tnt2

Use "tnt2 [command] --help" for more information about a command.

# DESCRIPTION
**tnt2** is an encryption/description system that uses an infinite (with
respect to the plaintext) key to encode the data.  The psuedo-random generator
used by **tnt2** can encode approximately 1.680088572×10³⁹ bytes before the
generated key will repeat itself.

# encode
Encode plaintext using the TNT2 Infinite (with respect to the plaintext) Key Encryption System.
## Usage:
  tnt2 encode [flags]

## Flags:
      -c, --compress       compress input file using flate  
      -n, --count string   initial block count (default "-1")

  > The count can be given as a fraction of the maximum number of blocks that can be generated by the encryption engine.  Using "SecretKey" as the key and "1/2" as the block count, there are 5.250276786×10³⁷) 32 byte blocks that can be generated, resulting in a starting block count of 2.625138393×10³⁷.

      -h, --help           help for encode  
      -a, --useASCII85     use ASCII85 encoding  
      -p, --usePem         use PEM encoding.

## Global Flags:
          --config string       config file (default is $HOME/.tnt2.yaml)
      -i, --inputFile string    Name of the plaintext file to encrypt/decrypt. (default "-")
      -o, --outputFile string   Name of the file containing the encrypted/decrypted plaintext.

# decode
Decode a file encoded by the TNT2 Infinite (with respect to the plaintext) Key Encryption System.
## Usage:
  tnt2 decode [flags]

## Flags:
  -h, --help   help for decode

## Global Flags:
          --config string       config file (default is $HOME/.tnt2.yaml)
      -i, --inputFile string    Name of the plaintext file to encrypt/decrypt. (default "-")
      -o, --outputFile string   Name of the file containing the encrypted/decrypted plaintext.

# version
Display version and detailed build information for tnt2.
## Usage:
  tnt2 version [flags]

## Flags:
  -h, --help   help for version

## Global Flags:
          --config string         config file (default is $HOME/.tnt2.yaml)
      -i, --inputFile string      Name of the plaintext file to encrypt/decrypt. (default "-")
      -o, --outputFile string     Name of the file containing the encrypted/decrypted plaintext.
      -f, --proformafile string   the file name containing the proforma machine to use instead of the builtin proforma machine.

# Secret Key

The secret key that is used to encrypt/decrypt the data can be supplied 
in one (1) of three (3) ways, in order of security:

1. The program will prompt for the secret key (most secure)
2. The secret key is passed in via the tnt2Secret environment variable.
3. The secret key is passwd as arguments after all the valid options (least secure)

# COPYRIGHT
   Copyright © 2021 Billy G. Allie

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
