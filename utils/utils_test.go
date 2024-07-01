package utils_test

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NethermindEth/juno/core/felt"
	"github.com/metacube-games/starknetid.go/constants"
	"github.com/metacube-games/starknetid.go/utils"
)

func generateString(length int, characters []rune) string {
	randGen := rand.New(rand.NewSource(time.Now().UnixNano()))
	var result strings.Builder
	charactersLength := len(characters)
	for i := 0; i < length; i++ {
		result.WriteRune(characters[randGen.Intn(charactersLength)])
	}
	return result.String()
}

func TestEncodeDecodeDomain(t *testing.T) {
	for i := 0; i < 2500; i++ {
		randomString := generateString(10, constants.TOTAL_ALPHABET)
		encoded, err := utils.EncodeDomain(randomString)
		if err != nil {
			t.Errorf("Failed to encode domain %s: %s", randomString, err)
		}
		decoded := utils.DecodeDomain(encoded)
		if decoded != randomString+".stark" {
			t.Errorf("Expected %s.stark but got %s", randomString, decoded)
		}
	}

	for i := 0; i < 2500; i++ {
		decoded := utils.DecodeDomain(
			[]*felt.Felt{(&felt.Felt{}).SetUint64(uint64(i))},
		)
		encoded, err := utils.EncodeDomain(decoded)
		if err != nil {
			t.Errorf("Failed to encode domain %s: %s", decoded, err)
		}
		if encoded[0].Text(10) != strconv.Itoa(i) {
			t.Errorf("Expected %d but got %s", i, encoded[0].Text(10))
		}
	}

	for i := 0; i < 2500; i++ {
		randomString := generateString(10, constants.TOTAL_ALPHABET)
		encoded, err := utils.EncodeDomain(randomString)
		if err != nil {
			t.Errorf("Failed to encode domain %s: %s", randomString, err)
		}
		decoded := utils.DecodeDomain(encoded)
		if decoded != randomString+".stark" {
			t.Errorf("Expected %s.stark but got %s", randomString, decoded)
		}
	}

	for i := 0; i < 2500; i++ {
		randomString := generateString(10, constants.TOTAL_ALPHABET)
		encoded, err := utils.EncodeDomain(randomString + ".stark")
		if err != nil {
			t.Errorf("Failed to encode domain %s: %s", randomString, err)
		}
		decoded := utils.DecodeDomain(encoded)
		if decoded != randomString+".stark" {
			t.Errorf("Expected %s.stark but got %s", randomString, decoded)
		}
	}

	for i := 0; i < 2500; i++ {
		randomString1 := generateString(10, constants.TOTAL_ALPHABET)
		randomString2 := generateString(10, constants.TOTAL_ALPHABET)
		encoded, err := utils.EncodeDomain(randomString1 + "." + randomString2)
		if err != nil {
			t.Errorf(
				"Failed to encode domain %s.%s: %s",
				randomString1,
				randomString2,
				err,
			)
		}
		decoded := utils.DecodeDomain(encoded)
		if decoded != randomString1+"."+randomString2+".stark" {
			t.Errorf(
				"Expected %s.%s.stark but got %s",
				randomString1,
				randomString2,
				decoded,
			)
		}
	}

	for i := 0; i < 2500; i++ {
		randomString1 := generateString(10, constants.TOTAL_ALPHABET)
		randomString2 := generateString(10, constants.TOTAL_ALPHABET)
		encoded, err := utils.EncodeDomain(
			randomString1 +
				"." +
				randomString2 +
				".stark",
		)
		if err != nil {
			t.Errorf(
				"Failed to encode domain %s.%s.stark: %s",
				randomString1,
				randomString2,
				err,
			)
		}
		decoded := utils.DecodeDomain(encoded)
		if decoded != randomString1+"."+randomString2+".stark" {
			t.Errorf(
				"Expected %s.%s.stark but got %s",
				randomString1,
				randomString2,
				decoded,
			)
		}
	}

	for i := 0; i < 2500; i++ {
		decoded := utils.DecodeDomain(
			[]*felt.Felt{(&felt.Felt{}).SetUint64(uint64(i))},
		)
		if strings.Compare(decoded, "") == 0 {
			decoded = ".stark"
		}
		encoded, err := utils.EncodeDomain(decoded[:len(decoded)-6])
		if err != nil {
			t.Errorf("Failed to encode domain %s: %s", decoded, err)
		}
		if encoded[0].Text(10) != strconv.Itoa(i) {
			t.Errorf("Expected %d but got %s", i, encoded[0].Text(10))
		}
	}
}

func TestSpecialCases(t *testing.T) {
	decoded := utils.DecodeDomain([]*felt.Felt{
		(&felt.Felt{}).SetUint64(1499554868251),
		(&felt.Felt{}).SetUint64(18925),
	})
	if decoded != "fricoben.ben.stark" {
		t.Errorf("Expected fricoben.ben.stark but got %s", decoded)
	}
	encoded, err := utils.EncodeDomain("")
	if err != nil {
		t.Errorf("Failed to encode domain %s", err)
	}
	if utils.DecodeDomain(encoded) != "" {
		t.Errorf(
			"Expected empty string but got %s",
			utils.DecodeDomain(encoded),
		)
	}
	decoded = utils.DecodeDomain(nil)
	if decoded != "" {
		t.Errorf("Expected empty string but got %s", decoded)
	}
}

func TestIsStarkDomain(t *testing.T) {
	for i := 0; i < 2500; i++ {
		randomString1 := generateString(10, constants.BASIC_ALPHABET)
		randomString2 := generateString(10, constants.BASIC_ALPHABET)
		randomString3 := generateString(10, constants.BASIC_ALPHABET)
		randomString4 := generateString(10, constants.BASIC_ALPHABET)
		if !utils.IsStarkDomain(
			randomString1 + "." +
				randomString2 + "." +
				randomString3 + "." +
				randomString4 + ".stark",
		) {
			t.Errorf(
				"Expected true but got false for %s.%s.%s.%s.stark",
				randomString1,
				randomString2,
				randomString3,
				randomString4,
			)
		}
	}

	for i := 0; i < 500; i++ {
		randomString := generateString(10, constants.BASIC_ALPHABET)
		if !utils.IsStarkDomain(randomString + ".stark") {
			t.Errorf("Expected true but got false for %s.stark", randomString)
		}
	}

	invalidDomains := []string{
		"test.starkqsd",
		"test_.stark",
		"test..stark",
		".test..stark",
		"..test.stark",
	}

	for _, domain := range invalidDomains {
		if utils.IsStarkDomain(domain) {
			t.Errorf("Expected false but got true for %s", domain)
		}
	}
}

func TestIsStarkRootDomain(t *testing.T) {
	for i := 0; i < 2500; i++ {
		randomString := generateString(10, constants.BASIC_ALPHABET)
		if !utils.IsStarkRootDomain(randomString + ".stark") {
			t.Errorf("Expected true but got false for %s.stark", randomString)
		}
	}

	if utils.IsStarkRootDomain("test.star") {
		t.Errorf("Expected false but got true for test.star")
	}

	invalidStrings := []string{
		"test)ben.stark", "test,ben.stark", "qsd12$)ben.stark",
		"_.stark", "test.ben.stark", "..stark", "..starkq",
	}

	for _, s := range invalidStrings {
		if utils.IsStarkRootDomain(s) {
			t.Errorf("Expected false but got true for %s", s)
		}
	}
}

func TestIsSubdomain(t *testing.T) {
	if utils.IsSubdomain("1232575.stark") {
		t.Errorf("Expected false but got true for 1232575.stark")
	}

	if utils.IsSubdomain("") {
		t.Errorf("Expected false but got true for empty string")
	}

	if !utils.IsSubdomain("1232575.ben.stark") {
		t.Errorf("Expected true but got false for 1232575.ben.stark")
	}

	if !utils.IsSubdomain("qsdqsdqsd.fricoben.stark") {
		t.Errorf("Expected true but got false for qsdqsdqsd.fricoben.stark")
	}
}

func TestIsBraavosSubdomain(t *testing.T) {
	validDomains := []string{
		"ben.braavos.stark",
		"john.braavos.stark",
		"jeremy.braavos.stark",
		"johnny.braavos.stark",
	}

	for _, domain := range validDomains {
		if !utils.IsBraavosSubdomain(domain) {
			t.Errorf("Expected true but got false for %s", domain)
		}
	}

	invalidDomains := []string{
		"arya.braavoos.stark",
		"braavos.stark",
		"winterf.ell.braavos.stark",
		"johén.braavos.stark",
		"",
	}

	for _, domain := range invalidDomains {
		if utils.IsBraavosSubdomain(domain) {
			t.Errorf("Expected false but got true for %s", domain)
		}
	}
}

func TestIsXplorerSubdomain(t *testing.T) {
	validDomains := []string{
		"ben.xplorer.stark",
		"john.xplorer.stark",
		"jeremy.xplorer.stark",
		"johnny.xplorer.stark",
	}

	for _, domain := range validDomains {
		if !utils.IsXplorerSubdomain(domain) {
			t.Errorf("Expected true but got false for %s", domain)
		}
	}

	invalidDomains := []string{
		"arya.xploreer.stark",
		"xplorer.stark",
		"winterf.ell.xplorer.stark",
		"johén.xplorer.stark",
		"",
	}

	for _, domain := range invalidDomains {
		if utils.IsXplorerSubdomain(domain) {
			t.Errorf("Expected false but got true for %s", domain)
		}
	}
}

func TestFmtFeltArrayCallData(t *testing.T) {
	formatted := utils.FmtFeltArrayCallData([]*felt.Felt{})
	if len(formatted) != 1 {
		t.Errorf("Expected 1 but got %d", len(formatted))
	}
	if formatted[0].Text(10) != "0" {
		t.Errorf("Expected 0 but got %s", formatted[0].Text(10))
	}

	for i := 0; i < 2500; i++ {
		size := rand.Intn(99) + 1
		feltArray := make([]*felt.Felt, size)
		for j := 0; j < size; j++ {
			feltArray[j] = (&felt.Felt{}).SetUint64(uint64(j))
		}
		formatted := utils.FmtFeltArrayCallData(feltArray)
		if len(formatted) != size+1 {
			t.Errorf("Expected %d but got %d", size, len(formatted))
		}
		if formatted[0].Text(10) != strconv.Itoa(size) {
			t.Errorf("Expected %d but got %s", size, formatted[0].Text(10))
		}
		for j := 0; j < size; j++ {
			if formatted[j+1].Text(10) != strconv.Itoa(j) {
				t.Errorf("Expected %d but got %s", j, formatted[j+1].Text(10))
			}
		}
	}
}

func TestIsASCII(t *testing.T) {
	asciiStrings := []string{
		"hello",
		"world",
		"123456",
		"!@#$%^",
	}
	for _, s := range asciiStrings {
		if !utils.IsASCII(s) {
			t.Errorf("Expected true but got false for %s", s)
		}
	}

	nonASCIIStrings := []string{
		"你好",
		"世界",
		"こんにちは",
		"안녕하세요",
	}
	for _, s := range nonASCIIStrings {
		if utils.IsASCII(s) {
			t.Errorf("Expected false but got true for %s", s)
		}
	}
}

func TestIsShortString(t *testing.T) {
	shortStrings := []string{
		"hello",
		"world",
		"123456",
		"!@#$%^",
	}
	for _, s := range shortStrings {
		if !utils.IsShortString(s) {
			t.Errorf("Expected true but got false for %s", s)
		}
	}

	longStrings := []string{
		"abcdefghijklmnopqrstuvwxyz1234567890",
		"0987654321zyxwvutsrqponmlkjihgfedcba",
	}
	for _, s := range longStrings {
		if utils.IsShortString(s) {
			t.Errorf("Expected false but got true for %s", s)
		}
	}
}

func TestAddHexPrefix(t *testing.T) {
	hexStrings := []string{
		"0x123456",
		"0xabcdef",
		"0xABCDEF",
	}
	for _, s := range hexStrings {
		if utils.AddHexPrefix(s) != s {
			t.Errorf("Expected %s but got %s", s, utils.AddHexPrefix(s))
		}
	}

	nonHexStrings := []string{
		"123456",
		"abcdef",
		"ABCDEF",
	}
	for _, s := range nonHexStrings {
		if utils.AddHexPrefix(s) != "0x"+s {
			t.Errorf("Expected 0x%s but got %s", s, utils.AddHexPrefix(s))
		}
	}
}

func TestEncodeShortString(t *testing.T) {
	shortStrings := []string{
		"hello",
		"world",
		"123456",
		"!@#$%^",
	}
	expected := []string{
		"0x68656c6c6f",
		"0x776f726c64",
		"0x313233343536",
		"0x21402324255e",
	}
	for i, s := range shortStrings {
		encoded, err := utils.EncodeShortString(s)
		if err != nil {
			t.Errorf("Failed to encode short string %s: %s", s, err)
		}
		if encoded.String() != expected[i] {
			t.Errorf("Expected %s but got %s", expected[i], encoded)
		}
	}
}
