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
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	dbug "runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/bgallie/tnt2engine"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/spf13/viper"
)

var (
	cfgFile          string
	proFormaFileName string
	engineLayout     string
	tnt2Machine      tnt2engine.Tnt2Engine
	iCnt             *big.Int
	mKey             string
	inputFileName    string
	outputFileName   string
	useASCII85       bool
	usePem           bool
	useBinary        bool
	compression      bool
	cnt              string
	wg               sync.WaitGroup
	headerLine       string
	GitCommit        string = "not set"
	GitState         string = "not set"
	GitSummary       string = "not set"
	GitDate          string = "not set"
	BuildDate        string = "not set"
	Version          string = ""
)

const (
	tnt2ApiLevel        = 5
	defaultEngineLayout = "rrprrprr"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "tnt2",
	Short:   "An Infinite Key Encryption System",
	Long:    `tnt2 is a program the encrypts/decrypts files using an infinite (with respect to the plaintext) key.`,
	Version: Version,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "the config file to use")
	rootCmd.PersistentFlags().StringVarP(&proFormaFileName, "proformaFile", "f", "", "the file name containing the proforma machine to use instead of the builtin proforma machine.")
	rootCmd.PersistentFlags().StringVarP(&engineLayout, "engineLayout", "e", "", "the engineLayout to use for the encryption machine.")
	rootCmd.PersistentFlags().StringVarP(&inputFileName, "inputFile", "i", "-", "Name of the plaintext file to encrypt/decrypt.")
	rootCmd.PersistentFlags().StringVarP(&outputFileName, "outputFile", "o", "", "Name of the file containing the encrypted/decrypted plaintext.")
	// Extract version information from the stored build information.
	bi, ok := dbug.ReadBuildInfo()
	if ok {
		Version = bi.Main.Version
		rootCmd.Version = Version
		GitDate = getBuildSettings(bi.Settings, "vcs.time")
		GitCommit = getBuildSettings(bi.Settings, "vcs.revision")
		if len(GitCommit) > 1 {
			GitSummary = fmt.Sprintf("%s-1-%s", Version, GitCommit[0:7])
		}
		GitState = "clean"
		if getBuildSettings(bi.Settings, "vcs.modified") == "true" {
			GitState = "dirty"
		}
	}
	// Get the build date (as the modified date of the executable) if the build date
	// is not set.
	if BuildDate == "not set" {
		fpath, err := os.Executable()
		cobra.CheckErr(err)
		fpath, err = filepath.EvalSymlinks(fpath)
		cobra.CheckErr(err)
		fsys := os.DirFS(filepath.Dir(fpath))
		fInfo, err := fs.Stat(fsys, filepath.Base(fpath))
		cobra.CheckErr(err)
		BuildDate = fInfo.ModTime().UTC().Format(time.RFC3339)
	}
}

func getBuildSettings(settings []dbug.BuildSetting, key string) string {
	for _, v := range settings {
		if v.Key == key {
			return v.Value
		}
	}
	return ""
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	var confPath string
	var err error
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		confPath, err = os.UserConfigDir()
		cobra.CheckErr(err)
		confPath = filepath.Join(confPath, "tnt2")
		viper.AddConfigPath(confPath)
		viper.SetConfigName("config")
		viper.SetConfigType("ini")
	}
	viper.AutomaticEnv()                        // read in environment variables that match
	cobra.CheckErr(os.MkdirAll(confPath, 0750)) // ensure confPath exists
	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		// there was an error reading the config file.  If it did not exist,
		// the create a default config file with just the engineLayout in it.
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			viper.SetDefault("general.engineLayout", "rrprrprr")
			cobra.CheckErr(viper.SafeWriteConfig())
			cobra.CheckErr(viper.ReadInConfig())
		} else {
			cobra.CheckErr(err)
		}
	}
	// Use the engineLayout from the command line argument, if given.
	// Otherwise use the config value if it exists, otherwise use
	// 'rrprrprr' as a default.
	if len(engineLayout) > 0 {
		tnt2engine.EngineLayout = engineLayout
	} else if viper.InConfig("general.engineLayout") {
		tnt2engine.EngineLayout = viper.GetString("general.engineLayout")
	} else {
		tnt2engine.EngineLayout = defaultEngineLayout
	}
}

func initEngine(args []string) {
	// Obtain the passphrase used to encrypt the file from either:
	// 1. User input from the terminal (most secure)
	// 2. The 'TNT2_SECRET' environment variable (less secure)
	// 3. Arguments from the entered command line (least secure - not recommended)
	var secret string
	if len(args) == 0 {
		if viper.IsSet("TNT2_SECRET") {
			secret = viper.GetString("TNT2_SECRET")
		} else {
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprintf(os.Stderr, "Enter the passphrase: ")
				byteSecret, err := term.ReadPassword(int(os.Stdin.Fd()))
				cobra.CheckErr(err)
				fmt.Fprintln(os.Stderr, "")
				secret = string(byteSecret)
			}
		}
	} else {
		secret = strings.Join(args, " ")
	}
	if len(secret) == 0 {
		cobra.CheckErr("You must supply a password.")
	}
	// Initialize the tnt2engine with the secret key and the named proforma file.
	tnt2Machine.Init([]byte(secret), proFormaFileName)
}

/*
getInputAndOutputFiles will return the input and output files to use while
encrypting/decrypting data.  If input and/or output files names were given,
then those files will be opened.  Otherwise stdin and stdout are used.
*/
func getInputAndOutputFiles(encode bool) (*os.File, *os.File) {
	var fin *os.File
	var err error
	if len(inputFileName) > 0 {
		if inputFileName == "-" {
			fin = os.Stdin
		} else {
			fin, err = os.Open(inputFileName)
			cobra.CheckErr(err)
		}
	} else {
		fin = os.Stdin
	}
	var fout *os.File
	if len(outputFileName) > 0 {
		if outputFileName == "-" {
			fout = os.Stdout
		} else {
			fout, err = os.Create(outputFileName)
			cobra.CheckErr(err)
		}
	} else if inputFileName == "-" {
		fout = os.Stdout
	} else if encode {
		outputFileName = inputFileName + ".tnt2"
		fout, err = os.Create(outputFileName)
		cobra.CheckErr(err)
	} else {
		if strings.HasSuffix(inputFileName, ".tnt2") {
			outputFileName = inputFileName[:len(inputFileName)-5]
			fout, err = os.Create(outputFileName)
			cobra.CheckErr(err)
		} else {
			fout = os.Stdout
		}
	}
	return fin, fout
}

// cipherHelper is a filter that encrypts/decrypts the data from the input pipe.
// The (encrypted/decrypted) data can be read using the returned PipeReader.
func cipherHelper(rdr io.Reader, left, right chan tnt2engine.CipherBlock) *io.PipeReader {
	var cnt int
	var err error
	rRdr, rWrtr := io.Pipe()
	leftMost, rightMost := left, right
	data := []byte(nil)
	wg.Add(1)
	go func() {
		defer rWrtr.Close()
		defer wg.Done()
		err = nil
		blk := make(tnt2engine.CipherBlock, tnt2engine.CipherBlockBytes)
		for err != io.EOF {
			b := make([]byte, 2048)
			cnt, err = rdr.Read(b)
			checkError(err)
			if err != io.EOF {
				data = append(data, b[:cnt]...)
				for len(data) >= tnt2engine.CipherBlockBytes {
					cnt = copy(blk, data)
					leftMost <- blk[:cnt]
					blk = <-rightMost
					_, err1 := rWrtr.Write(blk)
					checkError(err1)
					data = data[len(blk):]
				}
			}
		}
		if len(data) > 0 {
			cnt = copy(blk, data)
			leftMost <- blk[:cnt]
			blk = <-rightMost
			cnt, err = rWrtr.Write(blk)
			_ = cnt
			checkError(err)
		}
	}()
	return rRdr
}

// checkFatal checks for error that are not io.EOF and io.ErrUnexpectedEOF and logs them.
func checkError(e error) {
	if e != io.EOF && e != io.ErrUnexpectedEOF {
		cobra.CheckErr(e)
	}
}
