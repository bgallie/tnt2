/*
Copyright © 2021 Billy G. Allie <bill.allie@defiant.mug.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"bufio"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/bgallie/filters/ascii85"
	"github.com/bgallie/filters/flate"
	"github.com/bgallie/filters/lines"
	"github.com/bgallie/filters/pem"
	"github.com/bgallie/tnt2engine"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt plaintext using TNT2",
	Long:  `Encrypt plaintext using the TNT2 Infinite (with respect to the plaintext) Key Encryption System.`,
	Run: func(cmd *cobra.Command, args []string) {
		useBinary = !(useASCII85 || usePem)
		encrypt(args)
	},
}

// encodeCmd represents the encode command
var encodeCmd = &cobra.Command{
	Use:        "encode",
	Short:      "Encode plaintext using TNT2",
	Long:       `[DEPRECATED] Encode plaintext using the TNT2 Infinite (with respect to the plaintext) Key Encryption System.`,
	Deprecated: "use \"encrypt\" instead.",
	Run: func(cmd *cobra.Command, args []string) {
		useBinary = !(useASCII85 || usePem)
		encrypt(args)
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(encodeCmd)
	encryptCmd.Flags().BoolVarP(&useASCII85, "useASCII85", "a", false, "use ASCII85 encoding")
	encryptCmd.Flags().BoolVarP(&usePem, "usePem", "p", false, "use PEM encoding.")
	encryptCmd.Flags().BoolVarP(&compression, "compress", "c", false, "compress input file using flate")
	encryptCmd.Flags().StringVarP(&cnt, "count", "n", "", `initial block count
The inital block count can be given as a fraction (eg. 1/3 or 1/2) of the maximum blocks encrypted before the key repeats.
The inital block count is only effective on the first use of the secret key.`)
	encodeCmd.Flags().BoolVarP(&useASCII85, "useASCII85", "a", false, "use ASCII85 encoding")
	encodeCmd.Flags().BoolVarP(&usePem, "usePem", "p", false, "use PEM encoding.")
	encodeCmd.Flags().BoolVarP(&compression, "compress", "c", false, "compress input file using flate")
	encodeCmd.Flags().StringVarP(&cnt, "count", "n", "", `initial block count
The inital block count can be given as a fraction (eg. 1/3 or 1/2) of the maximum blocks encrypted before the key repeats.
The inital block count is only effective on the first use of the secret key.`)
}

func encrypt(args []string) {
	initEngine(args)
	// Get the starting block count.  cnt can be a number or a fraction such
	// as "1/2", "2/3", or "3/4".  If it is a fraction, then the starting block
	// count is calculated by multiplying the maximal states of the tnt2engine
	// by the fraction.
	if len(cnt) != 0 {
		var good bool
		flds := strings.Split(cnt, "/")
		if len(flds) == 1 {
			iCnt, good = new(big.Int).SetString(cnt, 10)
			if !good {
				cobra.CheckErr(fmt.Sprintf("Failed converting the count to a big.Int: [%s]\n", cnt))
			}
		} else if len(flds) == 2 {
			m := new(big.Int).Set(tnt2Machine.MaximalStates())
			a, good := new(big.Int).SetString(flds[0], 10)
			if !good {
				cobra.CheckErr(fmt.Sprintf("Failed converting the numerator to a big.Int: [%s]\n", flds[0]))
			}
			b, good := new(big.Int).SetString(flds[1], 10)
			if !good {
				cobra.CheckErr(fmt.Sprintf("Failed converting the denominator to a big.Int: [%s]\n", flds[1]))
			}
			iCnt = m.Div(m.Mul(m, a), b)
		} else {
			cobra.CheckErr(fmt.Sprintf("Incorrect initial count: [%s]\n", cnt))
		}
	} else {
		iCnt = new(big.Int).Set(tnt2engine.BigZero)
	}
	// Set the engine type and build the cipher machine.
	tnt2Machine.SetEngineType("E")
	tnt2Machine.BuildCipherMachine()
	// Read in the map of counts from the file which holds the counts and get
	// the count to use to encrypt the file.
	mKey = fmt.Sprintf("counters.%s", tnt2Machine.CounterKey())
	if viper.IsSet(mKey) {
		savedCnt := viper.GetString(mKey)
		_, ok := iCnt.SetString(savedCnt, 10)
		if !ok {
			cobra.CheckErr(fmt.Sprintf("Failed to convert the saved count to a big.Int:\n\t[%s]\n", savedCnt))
		}
		if cnt != "" {
			fmt.Fprintln(os.Stderr, "Ignoring the block count argument - using the value from the saved count.")
		}
	} else {
		viper.Set(mKey, tnt2Machine.Index().Text(10))
	}
	// Now we can set the index of the ciper machine.
	tnt2Machine.SetIndex(iCnt)
	var encIn *io.PipeReader
	fin, fout := getInputAndOutputFiles(true)
	var blck pem.Block
	if usePem { //useASCII85 || useBinary {
		blck.Headers = make(map[string]string)
		blck.Type = "TNT2 Encrypted Message"
		blck.Headers["Counter"] = fmt.Sprintf("%s", tnt2Machine.Index())
		if len(inputFileName) > 0 && inputFileName != "-" {
			blck.Headers["FileName"] = inputFileName
		}
		blck.Headers["Compression"] = fmt.Sprintf("%v", compression)
		blck.Headers["ApiLevel"] = strconv.Itoa(tnt2ApiLevel)
	} else {
		headerLine = fmt.Sprintf("+TNT2|%d|", tnt2ApiLevel)
		if len(inputFileName) > 0 && inputFileName != "-" {
			headerLine += inputFileName
		}
		if useASCII85 {
			headerLine += "|a"
		} else {
			headerLine += "|b"
		}
		headerLine += fmt.Sprintf("|%s|%s\n", fmt.Sprintf("%v", compression), tnt2Machine.Index())
		fout.WriteString(headerLine)
	}
	if compression {
		encIn = cipherHelper(flate.ToFlate(fin), tnt2Machine.Left(), tnt2Machine.Right())
	} else {
		encIn = cipherHelper(fin, tnt2Machine.Left(), tnt2Machine.Right())
	}
	defer fout.Close()
	var err error
	bRdr := bufio.NewReader(encIn)
	if useBinary {
		_, err = io.Copy(fout, bRdr)
	} else if useASCII85 {
		_, err = io.Copy(fout, lines.SplitToLines(ascii85.ToASCII85(encIn)))
	} else {
		_, err = io.Copy(fout, pem.ToPem(bRdr, blck))
	}
	checkError(err)
	wg.Wait()
	viper.Set(mKey, tnt2Machine.Index().Text(10))
	cobra.CheckErr(viper.WriteConfig())
}
