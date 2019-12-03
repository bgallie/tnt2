// tnt2 project main.go
// tnt2 is an implementation of the "Infinite Key Ecryption" system from the
// Dr. Dobbs Journal artical.

package main

import (
	"bufio"
	"encoding/ascii85"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/user"
	"sync"

	"github.com/bgallie/filters"
	"github.com/bgallie/jc1"
	"github.com/bgallie/tnt2/cryptors"
	"github.com/bgallie/tnt2/cryptors/permutator"
	"github.com/bgallie/tnt2/cryptors/rotor"
	"github.com/bgallie/utilities"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	Tnt2Comment   = "TNT2 Encrypted Data"
	Tnt2Name      = "os.Stdin"
	Tnt2CountFile = ".tnt2"
	usage         = "tnt2 [[-decode | -d] | [-encode | -e]] <inputfile >outputfile"
)

var (
	encode          bool // Flag: True to encode, False to decode
	decode          bool // Flag: True to decode, False to encode
	rotor1          *rotor.Rotor
	rotor2          *rotor.Rotor
	rotor3          *rotor.Rotor
	rotor4          *rotor.Rotor
	rotor5          *rotor.Rotor
	rotor6          *rotor.Rotor
	permutator1     *permutator.Permutator
	permutator2     *permutator.Permutator
	counter         *cryptors.Counter = new(cryptors.Counter)
	proFormaMachine []cryptors.Crypter
	tntMachine      []cryptors.Crypter
	rotorSizes      []int
	rotorSizesIndex int
	cycleSizes      []int
	cycleSizesIndex int
	key             *jc1.UberJc1
	mKey            string
	iCnt            *big.Int
	logIt           bool
	cMap            map[string]*big.Int
	nullFile        *os.File
	cntrFileName    string
	un              = utilities.Un
	trace           = utilities.Trace
	deferClose      = utilities.DeferClose
	checkFatal      = utilities.CheckFatal
	turnOffLogging  = utilities.TurnOffLogging
	turnOnLogging   = utilities.TurnOnLogging
)

func init() {
	// Parse the command line arguments.
	var cnt string
	flag.StringVar(&cnt, "count", "0", "initial count")
	flag.StringVar(&cnt, "c", "0", "initial count (shorthand)")
	flag.BoolVar(&encode, "encode", false, "encrypt data")
	flag.BoolVar(&encode, "e", false, "encrypt data (shorthand)")
	flag.BoolVar(&decode, "decode", false, "decrypt data")
	flag.BoolVar(&decode, "d", false, "decrypt data (shorthand)")
	flag.BoolVar(&logIt, "log", false, "turn logging on")
	flag.BoolVar(&logIt, "l", false, "turn logging on (shorthand)")
	flag.Parse()

	if (encode && decode) || !(encode || decode) {
		fmt.Fprintln(os.Stderr, "You must select one of -encode or -decode")
		fmt.Fprintln(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(1)
	}

	var secret string
	var exists bool
	if flag.NArg() == 0 {
		secret, exists = os.LookupEnv("tnt2Secret")
		if !exists {
			// fmt.Fprintf(os.Stderr, "IsTerminal: %s\n", terminal.IsTerminal(int(os.Stdin.Fd())))
			if terminal.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprintf(os.Stderr, "Enter the passphrase: ")
				byteSecret, err := terminal.ReadPassword(int(os.Stdin.Fd()))
				checkFatal(err)
				fmt.Fprintln(os.Stderr, "")
				secret = string(byteSecret)
				fmt.Fprintf(os.Stderr, "The entered password is \"%s\"\n", secret)
			} else {
				fmt.Fprintln(os.Stderr, "You must supply a password.")
				os.Exit(1)
			}
		}
	} else {
		secret = flag.Arg(0)
	}

	key = jc1.NewUberJc1([]byte(secret))

	if !logIt {
		turnOffLogging()
	}

	u, err := user.Current()
	checkFatal(err)
	cntrFileName = fmt.Sprintf("%s%c%s", u.HomeDir, os.PathSeparator, Tnt2CountFile)
	// Get a 'checksum' of the encryption key.  This is used as a key to store
	// the number of blocks encrypted during the last session.
	var cksum [cryptors.CypherBlockBytes]byte
	var eCksum [int((cryptors.CypherBlockBytes / 4.0) * 5)]byte
	ascii85.Encode(eCksum[:], key.XORKeyStream(cksum[:]))
	mKey = string(eCksum[:])
	// Read in the map of counts from the file which holds the counts and get the count to use to encode the file.
	cMap = make(map[string]*big.Int)
	cMap = readCounterFile(cMap)

	if cMap[mKey] == nil {
		iCnt, _ = new(big.Int).SetString(cnt, 10)
		cMap[mKey] = iCnt
	} else {
		iCnt = cMap[mKey]
	}

	// Define a random order of rotor sizes based on the key.
	rotorSizes = key.Perm(len(cryptors.RotorSizes))

	// Define a random order of cycle sizes based on the key.
	cycleSizes = key.Perm(len(cryptors.CycleSizes))
	cycleSizesIndex = int(key.Int32n(int32(len(cycleSizes))))

	// Create the proforma rotors and permentators used to create the actual rotors and permentators to use.
	rotor1 = rotor.New(1693, 186, 864, []byte{
		12, 143, 66, 37, 245, 233, 57, 38, 48, 237, 113, 175, 41, 48, 154, 172,
		181, 182, 147, 156, 214, 190, 205, 0, 217, 209, 127, 225, 143, 241, 249, 31,
		190, 181, 127, 50, 246, 163, 133, 228, 49, 96, 147, 142, 255, 42, 11, 36,
		75, 132, 59, 29, 185, 123, 103, 147, 220, 209, 204, 134, 114, 222, 101, 169,
		11, 71, 194, 166, 11, 42, 90, 211, 43, 232, 220, 71, 118, 103, 50, 159,
		108, 233, 147, 238, 156, 108, 113, 245, 81, 150, 42, 207, 121, 146, 144, 136,
		31, 155, 210, 43, 78, 40, 104, 138, 145, 50, 31, 152, 94, 80, 145, 39,
		196, 86, 40, 176, 20, 101, 59, 198, 66, 74, 170, 199, 16, 141, 140, 54,
		244, 167, 202, 171, 65, 194, 97, 82, 126, 195, 184, 70, 235, 83, 120, 146,
		194, 150, 227, 71, 53, 145, 102, 136, 160, 78, 60, 194, 25, 174, 211, 49,
		61, 22, 82, 81, 163, 229, 93, 60, 229, 123, 160, 40, 122, 104, 238, 140,
		84, 14, 61, 236, 248, 152, 29, 235, 118, 220, 0, 20, 39, 244, 205, 249,
		69, 149, 244, 196, 158, 64, 43, 99, 226, 172, 119, 97, 210, 154, 53, 176,
		11, 249, 243, 147, 225, 81, 168, 164, 62, 61, 199, 4, 166, 61, 238, 53,
		5, 70, 147, 181, 214, 118, 146, 211, 218, 183, 25, 32, 59, 250, 47, 252,
		49, 62, 255, 227})

	rotor2 = rotor.New(1697, 1241, 1484, []byte{
		2, 166, 210, 66, 84, 238, 64, 128, 168, 109, 17, 47, 43, 37, 140, 234,
		186, 43, 229, 52, 20, 154, 82, 155, 238, 28, 148, 58, 29, 93, 168, 227,
		50, 97, 246, 49, 148, 176, 11, 145, 133, 196, 154, 4, 138, 81, 78, 109,
		12, 215, 108, 103, 74, 255, 181, 27, 233, 226, 89, 148, 68, 26, 198, 235,
		20, 150, 220, 140, 181, 135, 222, 65, 93, 104, 181, 170, 150, 134, 92, 69,
		246, 111, 128, 115, 208, 148, 28, 162, 196, 201, 123, 32, 254, 109, 247, 79,
		255, 75, 44, 122, 255, 203, 186, 23, 163, 14, 207, 185, 114, 173, 116, 32,
		252, 52, 188, 184, 136, 252, 109, 59, 254, 136, 183, 17, 18, 13, 125, 5,
		178, 107, 246, 29, 61, 114, 109, 147, 119, 35, 201, 144, 134, 209, 159, 214,
		210, 203, 24, 169, 54, 185, 207, 61, 6, 15, 25, 0, 103, 122, 92, 142,
		165, 107, 217, 180, 143, 182, 167, 10, 87, 20, 171, 154, 57, 138, 26, 51,
		56, 35, 48, 112, 216, 164, 110, 183, 187, 22, 138, 255, 126, 177, 199, 47,
		118, 165, 78, 182, 106, 228, 11, 221, 25, 56, 71, 54, 45, 142, 240, 143,
		50, 112, 169, 183, 4, 76, 165, 133, 168, 220, 129, 0, 81, 219, 34, 94,
		86, 74, 24, 213, 117, 87, 202, 105, 40, 52, 165, 54, 221, 57, 40, 117,
		58, 186, 80, 199, 241})

	permutator1 = permutator.New([]int{47, 53, 73, 83}, []byte{
		123, 129, 80, 82, 14, 200, 95, 176, 10, 146, 153, 196, 220, 16, 236, 20,
		191, 39, 238, 190, 97, 186, 120, 158, 48, 154, 56, 188, 117, 147, 107, 113,
		150, 50, 203, 18, 57, 30, 189, 237, 239, 194, 29, 125, 229, 163, 17, 35,
		155, 31, 112, 15, 168, 116, 139, 234, 172, 205, 240, 197, 217, 160, 173, 216,
		37, 136, 12, 195, 102, 140, 60, 81, 218, 178, 246, 219, 47, 100, 209, 255,
		130, 8, 52, 253, 164, 225, 79, 174, 49, 251, 151, 43, 106, 215, 142, 73,
		247, 53, 96, 161, 152, 214, 122, 206, 74, 137, 32, 99, 51, 110, 22, 128,
		93, 204, 181, 167, 64, 27, 162, 24, 3, 21, 76, 169, 13, 87, 166, 119,
		159, 40, 143, 250, 241, 38, 68, 138, 59, 34, 85, 199, 86, 248, 65, 19,
		70, 227, 28, 141, 243, 223, 193, 211, 103, 187, 148, 33, 228, 111, 6, 11,
		171, 75, 69, 46, 23, 242, 83, 192, 58, 126, 245, 118, 5, 36, 212, 170,
		89, 1, 61, 26, 210, 72, 98, 78, 157, 244, 165, 185, 145, 2, 104, 134,
		135, 9, 7, 182, 45, 54, 127, 249, 252, 233, 144, 101, 77, 201, 94, 232,
		226, 202, 208, 179, 92, 132, 25, 207, 66, 235, 67, 62, 90, 213, 84, 184,
		221, 55, 105, 44, 175, 124, 131, 0, 231, 183, 198, 121, 156, 180, 108, 109,
		42, 4, 149, 115, 224, 114, 230, 91, 41, 222, 254, 88, 133, 63, 177, 71})

	rotor3 = rotor.New(1787, 6, 850, []byte{
		17, 160, 224, 130, 76, 15, 2, 221, 203, 248, 41, 104, 224, 144, 94, 181,
		74, 24, 118, 205, 14, 144, 171, 52, 170, 152, 250, 108, 95, 41, 219, 128,
		246, 214, 46, 85, 128, 255, 53, 42, 193, 178, 28, 72, 49, 3, 130, 249,
		129, 47, 171, 194, 44, 73, 22, 228, 39, 35, 21, 172, 22, 197, 10, 100,
		24, 234, 156, 10, 60, 169, 79, 58, 123, 28, 228, 157, 195, 250, 67, 46,
		36, 143, 70, 254, 177, 41, 153, 37, 248, 253, 155, 18, 252, 240, 155, 181,
		79, 107, 18, 37, 248, 22, 178, 111, 101, 26, 234, 40, 123, 147, 34, 158,
		240, 92, 172, 248, 162, 138, 66, 1, 249, 131, 125, 219, 99, 112, 84, 156,
		221, 201, 52, 81, 54, 156, 15, 81, 158, 21, 194, 177, 140, 161, 33, 226,
		173, 213, 128, 25, 240, 52, 65, 98, 152, 183, 208, 117, 16, 149, 165, 85,
		167, 37, 231, 23, 185, 134, 62, 252, 25, 213, 109, 63, 85, 224, 188, 9,
		83, 93, 206, 158, 206, 150, 139, 17, 143, 198, 191, 34, 223, 201, 129, 212,
		44, 158, 220, 87, 18, 140, 103, 144, 58, 101, 76, 154, 238, 159, 144, 202,
		214, 160, 208, 28, 16, 87, 24, 82, 63, 42, 170, 222, 181, 75, 32, 141,
		0, 5, 23, 100, 122, 16, 232, 94, 198, 79, 65, 3, 135, 244, 170, 85,
		194, 176, 107, 118, 128, 92, 165, 81, 197, 212, 103, 251, 74, 217, 6, 28})

	rotor4 = rotor.New(1753, 386, 1524, []byte{
		236, 36, 117, 233, 74, 186, 226, 200, 61, 130, 54, 32, 213, 142, 99, 128,
		88, 213, 152, 58, 255, 161, 204, 152, 194, 114, 35, 243, 204, 190, 77, 23,
		161, 242, 133, 37, 76, 56, 217, 123, 6, 247, 101, 85, 244, 165, 224, 33,
		42, 166, 224, 208, 100, 104, 29, 108, 97, 152, 51, 70, 60, 31, 186, 127,
		99, 99, 3, 6, 19, 49, 97, 16, 34, 31, 29, 24, 65, 157, 134, 142,
		72, 160, 18, 254, 159, 238, 165, 48, 58, 18, 135, 208, 126, 46, 213, 174,
		124, 237, 245, 1, 230, 227, 210, 50, 46, 37, 211, 92, 18, 129, 211, 203,
		56, 203, 249, 127, 193, 212, 208, 64, 176, 56, 158, 160, 243, 254, 221, 44,
		37, 228, 69, 54, 108, 21, 18, 197, 168, 55, 28, 142, 187, 128, 196, 229,
		61, 139, 153, 50, 232, 236, 199, 115, 201, 133, 153, 10, 241, 147, 11, 195,
		245, 121, 183, 62, 85, 208, 33, 89, 134, 239, 177, 148, 148, 74, 16, 198,
		213, 42, 226, 28, 227, 173, 173, 201, 191, 17, 89, 197, 81, 116, 65, 61,
		234, 221, 218, 228, 108, 231, 27, 65, 80, 84, 141, 62, 114, 70, 1, 157,
		153, 193, 21, 14, 215, 184, 249, 8, 59, 73, 5, 217, 73, 234, 210, 149,
		116, 197, 145, 123, 4, 109, 64, 170, 29, 199, 0, 177, 170, 49, 117, 254,
		67, 153, 49, 133, 229, 70, 230, 153, 125, 155, 46, 114})

	permutator2 = permutator.New([]int{61, 63, 65, 67}, []byte{
		110, 224, 121, 160, 200, 47, 197, 190, 228, 151, 249, 229, 214, 95, 99, 96,
		168, 60, 102, 166, 73, 58, 167, 171, 237, 183, 19, 153, 32, 114, 67, 129,
		12, 123, 109, 235, 132, 248, 78, 98, 120, 112, 230, 87, 253, 24, 72, 52,
		62, 124, 182, 10, 191, 71, 255, 14, 64, 36, 1, 207, 246, 170, 223, 161,
		17, 26, 215, 28, 37, 94, 193, 3, 140, 53, 15, 138, 38, 155, 154, 80,
		13, 243, 250, 76, 104, 204, 194, 227, 5, 225, 201, 254, 40, 217, 2, 91,
		188, 0, 49, 21, 20, 79, 82, 66, 177, 213, 212, 238, 252, 16, 173, 187,
		231, 185, 69, 100, 103, 115, 234, 241, 59, 169, 239, 18, 51, 50, 107, 142,
		111, 81, 219, 209, 218, 211, 45, 25, 30, 141, 41, 179, 22, 172, 8, 75,
		136, 245, 144, 127, 9, 139, 65, 4, 247, 210, 70, 68, 97, 128, 48, 137,
		33, 251, 163, 205, 147, 118, 42, 85, 6, 130, 34, 157, 133, 117, 198, 92,
		203, 148, 126, 108, 242, 175, 143, 56, 232, 131, 84, 174, 11, 93, 221, 89,
		43, 176, 74, 181, 23, 106, 145, 135, 7, 122, 195, 150, 55, 105, 196, 29,
		236, 220, 116, 146, 206, 159, 90, 39, 162, 184, 244, 186, 54, 86, 31, 165,
		180, 57, 149, 61, 233, 46, 44, 101, 156, 240, 27, 226, 192, 152, 119, 77,
		35, 164, 158, 208, 202, 125, 216, 222, 83, 134, 199, 88, 113, 63, 178, 189})

	rotor5 = rotor.New(1777, 1739, 523, []byte{
		220, 82, 51, 127, 98, 245, 59, 19, 60, 107, 129, 196, 69, 186, 94, 225,
		219, 48, 90, 227, 190, 202, 83, 154, 34, 9, 129, 105, 207, 252, 228, 26,
		25, 135, 126, 4, 182, 240, 124, 134, 157, 209, 31, 87, 35, 178, 11, 225,
		193, 230, 85, 123, 131, 232, 117, 188, 150, 91, 219, 174, 224, 101, 229, 252,
		254, 212, 71, 161, 47, 226, 237, 39, 143, 223, 149, 33, 23, 170, 86, 59,
		221, 111, 30, 247, 31, 241, 177, 2, 255, 87, 219, 20, 19, 129, 78, 171,
		224, 187, 246, 7, 60, 39, 169, 195, 9, 95, 55, 90, 6, 46, 211, 74,
		193, 26, 89, 132, 136, 46, 167, 159, 229, 46, 80, 67, 165, 102, 192, 33,
		82, 230, 246, 178, 150, 118, 167, 4, 44, 2, 23, 139, 57, 242, 228, 43,
		212, 145, 5, 206, 105, 35, 60, 39, 87, 140, 153, 148, 124, 160, 238, 58,
		235, 93, 17, 150, 169, 186, 245, 59, 226, 95, 177, 95, 245, 209, 125, 94,
		35, 113, 122, 229, 88, 210, 88, 230, 110, 219, 110, 167, 2, 23, 63, 248,
		80, 6, 166, 82, 88, 134, 156, 125, 75, 65, 28, 151, 56, 142, 127, 128,
		233, 89, 141, 96, 101, 249, 66, 75, 144, 126, 179, 239, 214, 31, 185, 165,
		102, 254, 196, 234, 119, 38, 120, 214, 2, 137, 139, 116, 189, 194, 183, 97,
		180, 198, 125, 149, 167, 52, 69, 18, 2, 211, 158, 249, 201, 53, 160})

	rotor6 = rotor.New(1789, 1395, 1128, []byte{
		126, 83, 85, 177, 94, 103, 241, 52, 239, 25, 172, 124, 246, 213, 70, 234,
		114, 33, 234, 128, 41, 248, 224, 121, 169, 251, 21, 184, 198, 40, 155, 229,
		13, 90, 167, 9, 253, 26, 232, 196, 193, 247, 215, 34, 100, 149, 240, 253,
		141, 199, 220, 226, 80, 140, 181, 155, 180, 141, 113, 35, 16, 120, 146, 58,
		205, 250, 205, 99, 220, 40, 10, 121, 190, 140, 120, 102, 61, 135, 61, 189,
		41, 222, 17, 212, 32, 130, 211, 122, 123, 215, 203, 194, 43, 37, 250, 33,
		40, 97, 180, 17, 15, 184, 16, 86, 12, 193, 42, 47, 155, 245, 17, 9,
		2, 233, 156, 64, 243, 172, 0, 51, 75, 49, 113, 72, 48, 170, 92, 180,
		90, 132, 174, 225, 91, 11, 216, 229, 13, 34, 195, 165, 136, 190, 224, 72,
		198, 141, 121, 134, 165, 203, 81, 45, 166, 176, 29, 50, 179, 79, 179, 177,
		223, 129, 119, 51, 249, 28, 25, 226, 120, 80, 119, 77, 220, 198, 174, 191,
		175, 105, 71, 224, 245, 109, 245, 231, 10, 9, 18, 219, 199, 149, 191, 69,
		11, 20, 179, 5, 86, 29, 220, 172, 69, 240, 177, 225, 67, 92, 34, 75,
		209, 14, 150, 76, 227, 68, 84, 141, 86, 218, 48, 12, 16, 252, 190, 202,
		111, 170, 42, 214, 235, 44, 158, 230, 61, 131, 149, 207, 190, 218, 72, 93,
		46, 68, 29, 48, 5, 31, 60, 47, 117, 191, 2, 215, 24, 101, 179, 92})

	// Create the proforma encryption machine.  The layout of the machine is:
	// 		rotor, rotor, permutator, rotor, rotor, permutator, rotor, rotor
	proFormaMachine = []cryptors.Crypter{rotor1, rotor2, permutator1, rotor3, rotor4, permutator2, rotor5, rotor6}
	leftMost, rightMost := cryptors.CreateEncryptMachine(cryptors.BigZero, proFormaMachine...)

	// Update the rotors and permutators in a very non-linear fashion.
	for _, machine := range proFormaMachine {
		switch v := machine.(type) {
		default:
			fmt.Fprintf(os.Stderr, "Unknown machine: %v\n", v)
		case *rotor.Rotor:
			updateRotor(machine.(*rotor.Rotor), leftMost, rightMost)
		case *permutator.Permutator:
			updatePermutator(machine.(*permutator.Permutator), leftMost, rightMost)
		case *cryptors.Counter:
			machine.(*cryptors.Counter).SetIndex(big.NewInt(0))
		}
	}

	// Update the tntMachine to change the order of rotors and permutators in a randon order.
	tntMachine = make([]cryptors.Crypter, 9, 9)
	// Scramble the order of the rotors and permutators
	tntOrder := key.Perm(8)

	for i, v := range tntOrder {
		tntMachine[i] = proFormaMachine[v]
	}

	tntMachine[8] = counter
}

func updateRotor(r *rotor.Rotor, left, right chan cryptors.CypherBlock) {
	var blk cryptors.CypherBlock
	blkSlice := blk.CypherBlock[:]
	copy(blkSlice, key.XORKeyStream(blkSlice))
	blk.Length = cryptors.CypherBlockBytes
	left <- blk
	blk = <-right
	rotorSize := cryptors.RotorSizes[rotorSizes[rotorSizesIndex]]
	rotorSizesIndex = (rotorSizesIndex + 1) % len(cryptors.RotorSizes)
	start := int(key.Int32n(int32(rotorSize)))
	step := int(key.Int32n(int32(rotorSize)))
	// var newRotor [cryptors.RotorSizeBytes]byte
	rotor := make([]byte, cryptors.RotorSizeBytes, cryptors.RotorSizeBytes) // newRotor[:0]
	blkCnt := cryptors.RotorSizeBytes / cryptors.CypherBlockBytes

	for i := 0; i < blkCnt; i++ {
		left <- blk
		blk = <-right
		rotor = append(rotor, blk.CypherBlock[:]...)
	}

	r.Update(rotorSize, start, step, rotor) // newRotor[:])
}

func updatePermutator(p *permutator.Permutator, left, right chan cryptors.CypherBlock) {
	var randp [cryptors.CypherBlockSize]byte
	var blk cryptors.CypherBlock
	blkSlice := blk.CypherBlock[:]
	copy(blkSlice, key.XORKeyStream(blkSlice))
	blk.Length = cryptors.CypherBlockBytes
	left <- blk
	blk = <-right

	// Create a table of byte values [0...255] in a random order
	randi := key.Perm(cryptors.CypherBlockSize)

	for idx, val := range randi {
		randp[idx] = byte(val)
	}

	// Chose a cryptors.CycleSizes and randomize order of the values
	length := len(cryptors.CycleSizes[cycleSizesIndex])
	cycles := make([]int, length, length)
	randi = key.Perm(length)

	for idx, val := range randi {
		cycles[idx] = cryptors.CycleSizes[cycleSizesIndex][val]
	}

	p.Update(cycles, randp[:])
	cycleSizesIndex = (cycleSizesIndex + 1) % len(cryptors.CycleSizes)
}

func encodeCypherBlock(blk cryptors.CypherBlock) []byte {
	b := make([]byte, 0, 0)
	b = append(b, byte(blk.Length))
	b = append(b, blk.CypherBlock[:]...)
	return b
}

func decodeCypherBlock(bytes []byte) *cryptors.CypherBlock {
	blk := new(cryptors.CypherBlock)
	blk.Length = int8(bytes[0])
	_ = copy(blk.CypherBlock[:], bytes[1:])
	return blk
}

func encrypt() {
	defer un(trace("encrypt"))
	encIn, encOut := io.Pipe()
	leftMost, rightMost := cryptors.CreateEncryptMachine(iCnt, tntMachine...)
	fin := os.Stdin
	fout := os.Stdout
	var wg sync.WaitGroup
	fout.WriteString(fmt.Sprintf("%s\n", iCnt))

	// Go routine to read the output from the encIn, encrypt it and
	// sends it to the ascii85.NewEncoder.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer deferClose("Closing encOut.", encOut.Close)
		defer un(trace("Go encIn -> encrypt -> ascii85.newEncoder"))
		flateIn := filters.ToFlate(fin)
		var err error
		var cnt int
		plainText := make([]byte, 0)

		for err != io.EOF {
			var blk cryptors.CypherBlock
			b := make([]byte, 1024, 1024)
			cnt, err = flateIn.Read(b)
			checkFatal(err)

			if err != io.EOF {
				plainText = append(plainText, b[:cnt]...)

				for len(plainText) >= cryptors.CypherBlockBytes {
					_ = copy(blk.CypherBlock[:], plainText)
					blk.Length = cryptors.CypherBlockBytes
					leftMost <- blk
					blk = <-rightMost
					cnt, err = encOut.Write([]byte(encodeCypherBlock(blk)))
					checkFatal(err)
					pt := make([]byte, 0)
					pt = append(pt, plainText[cryptors.CypherBlockBytes:]...)
					plainText = pt
				}
			} else if len(plainText) > 0 { // encrypt any remaining input.
				var e error
				blk.Length = int8(len(plainText))
				_ = copy(blk.CypherBlock[:], plainText[:blk.Length])
				blk.Length = int8(len(plainText))
				leftMost <- blk
				blk = <-rightMost
				cnt, e = encOut.Write([]byte(encodeCypherBlock(blk)))
				checkFatal(e)
			}
		}

		// shutdown the encryption machine.
		var blk cryptors.CypherBlock
		leftMost <- blk
		_ = <-rightMost
	}()

	// Read the output of encodeCypherBlock and send it to STDOUT.
	defer deferClose("Closing STDOUT", fout.Close)
	_, err := io.Copy(fout, filters.SplitToLines(filters.ToAscii85(encIn)))
	checkFatal(err)
	wg.Wait()
}

func decrypt() {
	defer un(trace("decrypt"))
	fin := os.Stdin
	fout := os.Stdout
	defer deferClose("decrypt -> Closing STDOUT", fout.Close)
	bRdr := bufio.NewReader(fin)
	line, err := bRdr.ReadString('\n')

	if err == nil {
		iCnt, _ = new(big.Int).SetString(line[:len(line)-1], 10)
	}

	leftMost, rightMost := cryptors.CreateDecryptMachine(iCnt, tntMachine...)
	decRdr, decWrtr := io.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer un(trace("decrypt -> CombineLines -> Ascii85Reader -> decryptEngine -> descOut"))
		defer deferClose("decrypt -> closing decWrtr", decWrtr.Close)
		var err error = nil
		var cnt int
		var blk cryptors.CypherBlock
		encText := make([]byte, 0)
		aRdr := filters.FromAscii85(filters.CombineLines(bRdr))

		for err != io.EOF {
			b := make([]byte, 1024, 1024)
			cnt, err = aRdr.Read(b)
			checkFatal(err)

			if err != io.EOF {
				encText = append(encText, b[:cnt]...)

				for len(encText) >= cryptors.CypherBlockBytes+1 {
					blk = *decodeCypherBlock(encText[:cryptors.CypherBlockBytes+1])
					leftMost <- blk
					blk = <-rightMost
					_, e := decWrtr.Write(blk.CypherBlock[:blk.Length])
					checkFatal(e)
					pt := make([]byte, 0)
					pt = append(pt, encText[cryptors.CypherBlockBytes+1:]...)
					encText = pt
				}
			}
		}
	}()

	_, err = io.Copy(fout, filters.FromFlate(decRdr))
	wg.Wait()
}

func readCounterFile(defaultMap map[string]*big.Int) map[string]*big.Int {
	defer un(trace("readCounterFile"))
	f, err := os.OpenFile(cntrFileName, os.O_RDONLY, 0600)

	if err != nil {
		return defaultMap
	}

	defer deferClose("Closing tnt2 map file", f.Close)
	cmap := make(map[string]*big.Int)
	dec := json.NewDecoder(f)
	checkFatal(dec.Decode(&cmap))
	return cmap
}

func writeCounterFile(wMap map[string]*big.Int) error {
	defer un(trace("writeCounterFile"))
	f, err := os.OpenFile(cntrFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)

	if err != nil {
		return err
	}

	defer deferClose("Closing tnt2 map file", f.Close)
	e := json.NewEncoder(f)
	e.SetIndent("", "    ")
	return e.Encode(wMap)
}

func main() {
	if encode {
		encrypt()
		cMap[mKey] = tntMachine[len(tntMachine)-1].Index()
		checkFatal(writeCounterFile(cMap))
	} else if decode {
		decrypt()
	}
}
