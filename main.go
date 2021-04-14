// tnt2 project main.go
// tnt2 is an implementation of the "Infinite Key Ecryption" system from the
// Dr. Dobbs Journal artical.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"os/user"
	"strings"
	"sync"

	"github.com/bgallie/filters"
	"github.com/bgallie/tntEngine"
	"github.com/bgallie/utilities"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	tnt2CountFile = ".tnt2"
	usage         = "tnt2 [[-decode | -d] | [-encode | -e]] <inputfile >outputfile"
)

var (
	encode           bool // Flag: True to encode, False to decode
	decode           bool // Flag: True to decode, False to encode
	useASCII85       bool // Flag: True to using ascii85 encoding, False to use PEM encoding
	tntMachine       tntEngine.TntEngine
	iCnt             *big.Int
	logIt            bool
	cMap             map[string]*big.Int
	mKey             string
	cntrFileName     string
	inputFileName    string
	outputFileName   string
	logFileName      string
	proFormaFileName string
	proFormaFile     os.File
	perm             func(int) []byte
	intn             func(int) int
	inputFile        = os.Stdin
	outputFile       = os.Stdout
	checkFatal       = utilities.CheckFatal
	turnOffLogging   = utilities.TurnOffLogging
	turnOnLogging    = utilities.TurnOnLogging
	setLogFileName   = utilities.SetLogFileName
)

func init() {
	// Parse the command line arguments.
	var cnt = "-1"
	flag.StringVar(&cnt, "count", "0", "initial count")
	flag.StringVar(&cnt, "c", "0", "initial count (shorthand)")
	flag.StringVar(&inputFileName, "inputFile", "", "input file name")
	flag.StringVar(&inputFileName, "if", "", "input file name (shorthand)")
	flag.StringVar(&outputFileName, "outputFile", "", "output file name")
	flag.StringVar(&outputFileName, "of", "", "output file name (shorthand)")
	flag.StringVar(&logFileName, "logFile", "", "log file name [implies -log]")
	flag.StringVar(&logFileName, "lf", "", "log file name (shorthand) [implies -l]")
	flag.StringVar(&proFormaFileName, "proformaFile", "", "proForma file name")
	flag.StringVar(&proFormaFileName, "pf", "", "proForma file name (shorthand)")
	flag.BoolVar(&encode, "encode", false, "encrypt data")
	flag.BoolVar(&encode, "e", false, "encrypt data (shorthand)")
	flag.BoolVar(&decode, "decode", false, "decrypt data")
	flag.BoolVar(&decode, "d", false, "decrypt data (shorthand)")
	flag.BoolVar(&logIt, "log", false, "turn logging on")
	flag.BoolVar(&logIt, "l", false, "turn logging on (shorthand)")
	flag.BoolVar(&useASCII85, "a", false, "use ascii85 encodeing (shorthand)")
	flag.BoolVar(&useASCII85, "ascii85", false, "use ascii85 encoding")
	flag.Parse()

	if (encode && decode) || !(encode || decode) {
		fmt.Fprintln(os.Stderr, "You must select one of -encode or -decode")
		fmt.Fprintln(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(1)
	}
	// Obtain the passphrase used to encrypt the file from either:
	// 1. User input from the terminal
	// 2. The 'tnt2Secret' environment variable
	// 3. Arguments from the entered command line
	var secret string
	var exists bool
	if flag.NArg() == 0 {
		secret, exists = os.LookupEnv("tnt2Secret")
		if !exists {
			if terminal.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprintf(os.Stderr, "Enter the passphrase: ")
				byteSecret, err := terminal.ReadPassword(int(os.Stdin.Fd()))
				checkFatal(err)
				fmt.Fprintln(os.Stderr, "")
				secret = string(byteSecret)
			}
		}
	} else {
		secret = strings.Join(flag.Args(), " ")
	}

	if len(secret) == 0 {
		fmt.Fprintln(os.Stderr, "You must supply a password.")
		os.Exit(1)
	}

	if len(logFileName) != 0 {
		setLogFileName(logFileName)
		turnOnLogging() // Set the log file to the named log file.
	}

	if !logIt {
		turnOffLogging()
	}

	iCnt, good := new(big.Int).SetString(cnt, 10)
	if !good {
		log.Fatalf("Failed converting counter to a big.Int: [%s]\n", cnt)
	}

	tntMachine.Init([]byte(secret), proFormaFileName)
	if encode {
		tntMachine.SetEngineType("E")
	} else {
		tntMachine.SetEngineType("D")
	}
	// Now the the engine type is set, build the cipher machine.
	tntMachine.BuildCipherMachine()
	mKey = tntMachine.CounterKey()
	// Get the counter file name based on the current user.
	u, err := user.Current()
	checkFatal(err)
	cntrFileName = fmt.Sprintf("%s%c%s", u.HomeDir, os.PathSeparator, tnt2CountFile)
	// Read in the map of counts from the file which holds the counts and get
	// the count to use to encode the file.
	cMap = make(map[string]*big.Int)
	cMap = readCounterFile(cMap)
	if cMap[mKey] == nil {
		cMap[mKey] = iCnt
	} else {
		iCnt = cMap[mKey]
	}
	// Now we can set the index of the ciper machine.
	tntMachine.SetIndex(iCnt)
}

/*
	getInputAndOutputFiles will return the input and output files to use while
	encrypting/decrypting data.  If input and/or output files names were given,
	then those files will be opened.  Otherwise stdin and stdout are used.
*/
func getInputAndOutputFiles() (*os.File, *os.File) {
	var fin *os.File
	var err error

	if len(inputFileName) > 0 {
		if inputFileName == "-" {
			fin = os.Stdin
		} else {
			fin, err = os.Open(inputFileName)
			checkFatal(err)
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
			checkFatal(err)
		}
	} else {
		fout = os.Stdout
	}

	return fin, fout
}

/*
 */
func encrypt() {
	encIn, encOut := io.Pipe()
	leftMost, rightMost := tntMachine.Left(), tntMachine.Right()
	fin, fout := getInputAndOutputFiles()
	var blck filters.Block
	if useASCII85 {
		fout.WriteString(fmt.Sprintf("%s\n", tntMachine.Index()))
	} else {
		blck.Headers = make(map[string]string)
		blck.Type = "TNT2 Encoded Message"
		blck.Headers["Counter"] = fmt.Sprintf("%s", tntMachine.Index())
		if len(inputFileName) > 0 && inputFileName != "-" {
			blck.Headers["FileName"] = inputFileName
		}
	}

	// Go routine to read the output from the encIn, encrypt it and
	// sends it to the appropiate filter (ToPem or ToASCII85).
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer encOut.Close()
		flateIn := filters.ToFlate(fin)
		var err error
		var cnt int
		plainText := make([]byte, 0)

		for err != io.EOF {
			var blk tntEngine.CypherBlock
			b := make([]byte, 1024, 1024)
			cnt, err = flateIn.Read(b)
			checkFatal(err)

			if err != io.EOF {
				plainText = append(plainText, b[:cnt]...)

				for len(plainText) >= tntEngine.CypherBlockBytes {
					_ = copy(blk.CypherBlock[:], plainText)
					blk.Length = tntEngine.CypherBlockBytes
					leftMost <- blk
					blk = <-rightMost
					cnt, err = encOut.Write(blk.Marshall())
					checkFatal(err)
					pt := make([]byte, 0)
					pt = append(pt, plainText[tntEngine.CypherBlockBytes:]...)
					plainText = pt
				}
			} else if len(plainText) > 0 { // encrypt any remaining input.
				var e error
				blk.Length = int8(len(plainText))
				_ = copy(blk.CypherBlock[:], plainText[:blk.Length])
				blk.Length = int8(len(plainText))
				leftMost <- blk
				blk = <-rightMost
				cnt, e = encOut.Write((blk.Marshall()))
				checkFatal(e)
			}
		}

		// shutdown the encryption machine by processing a CypherBlock with zero
		// value length field.
		var blk tntEngine.CypherBlock
		leftMost <- blk
		_ = <-rightMost
	}()

	// Read the marshalled CyperBlock and send it to STDOUT.
	defer fout.Close()
	var err error
	if useASCII85 {
		_, err = io.Copy(fout, filters.SplitToLines(filters.ToASCII85(encIn)))
	} else {
		_, err = io.Copy(fout, filters.ToPem(encIn, blck))
	}
	checkFatal(err)
	wg.Wait()
}

func decrypt() {
	fin, fout := getInputAndOutputFiles()
	defer fout.Close()
	var bRdr *bufio.Reader
	var pRdr *io.PipeReader
	if useASCII85 {
		bRdr = bufio.NewReader(fin)
		line, err := bRdr.ReadString('\n')

		if err == nil {
			iCnt, _ = new(big.Int).SetString(line[:len(line)-1], 10)
		}
	} else {
		var blck filters.Block
		pRdr, blck = filters.FromPem(fin)
		iCnt, _ = new(big.Int).SetString(blck.Headers["Counter"], 10)
		if len(outputFileName) == 0 {
			fname, ok := blck.Headers["FileName"]
			if ok {
				var err error
				fout, err = os.Create(fname)
				checkFatal(err)
			}
		}
	}
	tntMachine.SetIndex(iCnt)
	leftMost, rightMost := tntMachine.Left(), tntMachine.Right()
	decRdr, decWrtr := io.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer decWrtr.Close()
		var err error = nil
		var cnt int
		encText := make([]byte, 0)
		var aRdr *io.PipeReader
		if useASCII85 {
			aRdr = filters.FromASCII85(filters.CombineLines(bRdr))
		} else {
			aRdr = pRdr
		}

		for err != io.EOF {
			b := make([]byte, 1024, 1024)
			cnt, err = aRdr.Read(b)
			checkFatal(err)

			if err != io.EOF {
				encText = append(encText, b[:cnt]...)

				for len(encText) >= tntEngine.CypherBlockBytes+1 {
					var blk tntEngine.CypherBlock
					blk = *blk.Unmarshall(encText[:tntEngine.CypherBlockBytes+1])
					leftMost <- blk
					blk = <-rightMost
					_, e := decWrtr.Write(blk.CypherBlock[:blk.Length])
					checkFatal(e)
					pt := make([]byte, 0)
					pt = append(pt, encText[tntEngine.CypherBlockBytes+1:]...)
					encText = pt
				}
			}
		}

		// shutdown the decryption machine by processing a CypherBlock with zero
		// value length field.
		var blk tntEngine.CypherBlock
		leftMost <- blk
		_ = <-rightMost
	}()

	_, err := io.Copy(fout, filters.FromFlate(decRdr))
	checkFatal(err)
	wg.Wait() // Wait for the decryption machine to finish it's clean up.
}

func readCounterFile(defaultMap map[string]*big.Int) map[string]*big.Int {
	f, err := os.OpenFile(cntrFileName, os.O_RDONLY, 0600)

	if err != nil {
		return defaultMap
	}

	defer f.Close()
	cmap := make(map[string]*big.Int)
	dec := json.NewDecoder(f)
	checkFatal(dec.Decode(&cmap))
	return cmap
}

func writeCounterFile(wMap map[string]*big.Int) error {
	f, err := os.OpenFile(cntrFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)

	if err != nil {
		return err
	}

	defer f.Close()
	e := json.NewEncoder(f)
	e.SetIndent("", "    ")
	return e.Encode(wMap)
}

func main() {
	if encode {
		encrypt()
		cMap[mKey] = tntMachine.Index()
		checkFatal(writeCounterFile(cMap))
	} else if decode {
		decrypt()
	}
}
