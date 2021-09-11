package cracker

import (
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"strings"
)

func readPasswords() []string {
	b, err := ioutil.ReadFile("./top-10000-passwords.txt")
	if err != nil {
		fmt.Println(err)
	}
	str := string(b)
	return strings.Split(str, "\n")
}

func readSalts() []string {
	b, err := ioutil.ReadFile("./known-salts.txt")
	if err != nil {
		fmt.Println(err)
	}
	str := string(b)
	return strings.Split(str, "\n")
}

var rainbowHashes []string
var passwords []string
var salts []string
var mod int

func init() {
	//fmt.Println("INIT")
	//fmt.Println(time.Now().Format(time.StampMilli))
	salts = readSalts()
	passwords = readPasswords()
	for _, pass := range passwords {
		rainbowHashes = append(rainbowHashes, hashString(pass))
		for _, salt := range salts {
			rainbowHashes = append(rainbowHashes, hashString(salt+pass))
			rainbowHashes = append(rainbowHashes, hashString(pass+salt))
		}
	}
	mod = len(salts)*2 + 1

	//fmt.Println("INIT done")
	//fmt.Println(time.Now().Format(time.StampMilli))
}

func hashString(str string) string {
	bs := sha1.Sum([]byte(str))
	return fmt.Sprintf("%x", bs)

}

func FasterCrackSHA1Hash(str string) string {
	for i, hash := range rainbowHashes {
		if hash == str {
			//fmt.Printf("i:%v", i)
			return passwords[i/mod]
		}
	}
	return "PASSWORD NOT IN DATABASE"
}

func CrackSHA1Hash(str string, useSalt bool) string {
	if useSalt {
		for _, salt := range salts {
			for _, pass := range passwords {
				if hashString(salt+pass) == str {
					return pass
				}
				if hashString(pass+salt) == str {
					return pass
				}
			}
		}
	} else {
		for _, pass := range passwords {
			if hashString(pass) == str {
				return pass
			}
		}
	}
	return "PASSWORD NOT IN DATABASE"
}
