package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

type HashType int

const (
	MD5 HashType = iota
	SHA1
	SHA224
	SHA256
	SHA384
	SHA512
	NTLM
)

type Result struct {
	Hash     string
	Password string
	Found    bool
}

func ntlmHash(password string) string {
	// NTLM uses UTF-16LE encoding
	utf16le := utf16.Encode([]rune(password))
	data := make([]byte, len(utf16le)*2)
	for i, v := range utf16le {
		data[i*2] = byte(v)
		data[i*2+1] = byte(v >> 8)
	}
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

func hashString(input string, hashType HashType) string {
	var hasher []byte
	switch hashType {
	case MD5:
		h := md5.Sum([]byte(input))
		hasher = h[:]
	case SHA1:
		h := sha1.Sum([]byte(input))
		hasher = h[:]
	case SHA224:
		h := sha256.Sum224([]byte(input))
		hasher = h[:]
	case SHA256:
		h := sha256.Sum256([]byte(input))
		hasher = h[:]
	case SHA384:
		h := sha512.Sum384([]byte(input))
		hasher = h[:]
	case SHA512:
		h := sha512.Sum512([]byte(input))
		hasher = h[:]
	case NTLM:
		return ntlmHash(input)
	}
	return hex.EncodeToString(hasher)
}

func detectHashType(hash string) HashType {
	switch len(hash) {
	case 32:
		return MD5 // veya NTLM
	case 40:
		return SHA1
	case 56:
		return SHA224
	case 64:
		return SHA256
	case 96:
		return SHA384
	case 128:
		return SHA512
	default:
		return MD5
	}
}

func crackHash(targetHash string, wordlist []string, hashType HashType, workers int) (*Result, int) {
	targetHash = strings.ToLower(strings.TrimSpace(targetHash))

	wordChan := make(chan string, 1000)
	resultChan := make(chan *Result, 1)
	var wg sync.WaitGroup

	// Worker'ları başlat
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range wordChan {
				select {
				case <-resultChan:
					return
				default:
					hashed := hashString(word, hashType)
					if hashed == targetHash {
						resultChan <- &Result{
							Hash:     targetHash,
							Password: word,
							Found:    true,
						}
						return
					}
				}
			}
		}()
	}

	// Wordlist'i kanala gönder
	go func() {
		for _, word := range wordlist {
			select {
			case <-resultChan:
				close(wordChan)
				return
			default:
				wordChan <- word
			}
		}
		close(wordChan)
	}()

	// Worker'ların bitmesini bekle
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Sonuç bekle
	if result := <-resultChan; result != nil {
		return result, len(wordlist)
	}

	return &Result{Hash: targetHash, Found: false}, len(wordlist)
}

func loadWordlist(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return words, nil
}

func loadHashFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hashes []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hash := strings.TrimSpace(scanner.Text())
		if hash != "" && !strings.HasPrefix(hash, "#") {
			hashes = append(hashes, hash)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return hashes, nil
}

func generateBruteforce(charset string, maxLength int) []string {
	var words []string
	var generate func(string, int)

	generate = func(prefix string, length int) {
		if length == 0 {
			words = append(words, prefix)
			return
		}
		for _, c := range charset {
			generate(prefix+string(c), length-1)
		}
	}

	for i := 1; i <= maxLength; i++ {
		generate("", i)
	}

	return words
}

func printBanner() {
	banner := `
 ▄████▄   ██▀███   ▄▄▄       ▄████▄   ██ ▄█▀    ███▄ ▄███▓▓█████ 
▒██▀ ▀█  ▓██ ▒ ██▒▒████▄    ▒██▀ ▀█   ██▄█▒     ▓██▒▀█▀ ██▒▓█   ▀ 
▒▓█    ▄ ▓██ ░▄█ ▒▒██  ▀█▄  ▒▓█    ▄ ▓███▄░     ▓██    ▓██░▒███   
▒▓▓▄ ▄██▒▒██▀▀█▄  ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄     ▒██    ▒██ ▒▓█  ▄ 
▒ ▓███▀ ░░██▓ ▒██▒ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄    ▒██▒   ░██▒░▒████▒
░ ░▒ ▒  ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒    ░ ▒░   ░  ░░░ ▒░ ░
  ░  ▒     ░▒ ░ ▒░  ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░    ░  ░      ░ ░ ░  ░
░          ░░   ░   ░   ▒   ░        ░ ░░ ░     ░      ░      ░   
░ ░         ░           ░  ░░ ░      ░  ░              ░      ░  ░
░                           ░                                     
              Advanced Hash Cracking Tool v2.0
          Supports: MD5 | SHA1 | SHA256 | SHA512 | NTLM
		  Made by: Lokidres
`
	fmt.Println(banner)
}

func main() {
	printBanner()

	hashPtr := flag.String("hash", "", "Kırılacak hash değeri")
	hashFilePtr := flag.String("hashfile", "", "Hash dosyası (her satırda bir hash)")
	wordlistPtr := flag.String("wordlist", "", "Wordlist dosyası yolu")
	typePtr := flag.String("type", "auto", "Hash tipi (md5, sha1, sha224, sha256, sha384, sha512, ntlm, auto)")
	brutePtr := flag.Bool("brute", false, "Brute force modu")
	charsetPtr := flag.String("charset", "abcdefghijklmnopqrstuvwxyz0123456789", "Brute force charset")
	maxLenPtr := flag.Int("maxlen", 4, "Brute force max uzunluk")
	workersPtr := flag.Int("workers", 0, "Paralel worker sayısı (0 = CPU çekirdeği)")

	flag.Parse()

	// Hash veya hashfile kontrolü
	var targetHashes []string
	if *hashPtr != "" && *hashFilePtr != "" {
		fmt.Println("[!] -hash ve -hashfile aynı anda kullanılamaz")
		os.Exit(1)
	} else if *hashPtr != "" {
		targetHashes = []string{*hashPtr}
	} else if *hashFilePtr != "" {
		var err error
		targetHashes, err = loadHashFile(*hashFilePtr)
		if err != nil {
			fmt.Printf("[!] Hash dosyası okunamadı: %v\n", err)
			os.Exit(1)
		}
		if len(targetHashes) == 0 {
			fmt.Println("[!] Hash dosyası boş")
			os.Exit(1)
		}
	} else {
		fmt.Println("[!] Hash değeri veya hash dosyası gerekli. Kullanım:")
		fmt.Println("    ./crackme -hash <hash> -wordlist <dosya>")
		fmt.Println("    ./crackme -hashfile <dosya> -wordlist <dosya>")
		fmt.Println("    ./crackme -hash <hash> -brute -maxlen 4")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Worker sayısını belirle
	workers := *workersPtr
	if workers == 0 {
		workers = runtime.NumCPU()
	}

	// Hash tipini belirle
	var hashType HashType
	switch strings.ToLower(*typePtr) {
	case "md5":
		hashType = MD5
	case "sha1":
		hashType = SHA1
	case "sha224":
		hashType = SHA224
	case "sha256":
		hashType = SHA256
	case "sha384":
		hashType = SHA384
	case "sha512":
		hashType = SHA512
	case "ntlm":
		hashType = NTLM
	default:
		hashType = detectHashType(targetHashes[0])
		fmt.Printf("[*] Otomatik tespit: Hash uzunluğu %d karakter\n", len(targetHashes[0]))
	}

	hashTypeName := map[HashType]string{
		MD5:    "MD5",
		SHA1:   "SHA1",
		SHA224: "SHA224",
		SHA256: "SHA256",
		SHA384: "SHA384",
		SHA512: "SHA512",
		NTLM:   "NTLM",
	}

	fmt.Printf("[*] Hash Tipi      : %s\n", hashTypeName[hashType])
	fmt.Printf("[*] Worker Sayısı  : %d\n", workers)
	fmt.Printf("[*] Hedef Sayısı   : %d\n", len(targetHashes))

	var wordlist []string
	var err error

	if *brutePtr {
		fmt.Printf("[*] Mod            : Brute Force\n")
		fmt.Printf("[*] Charset        : %s\n", *charsetPtr)
		fmt.Printf("[*] Max Uzunluk    : %d\n", *maxLenPtr)
		fmt.Println("[*] Wordlist oluşturuluyor...")
		wordlist = generateBruteforce(*charsetPtr, *maxLenPtr)
		fmt.Printf("[*] %d kombinasyon oluşturuldu\n", len(wordlist))
	} else if *wordlistPtr != "" {
		fmt.Printf("[*] Mod            : Wordlist\n")
		fmt.Printf("[*] Wordlist       : %s\n", *wordlistPtr)
		fmt.Println("[*] Wordlist yükleniyor...")
		wordlist, err = loadWordlist(*wordlistPtr)
		if err != nil {
			fmt.Printf("[!] Hata: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] %d kelime yüklendi\n", len(wordlist))
	} else {
		fmt.Println("[!] Wordlist dosyası veya -brute parametresi gerekli")
		os.Exit(1)
	}

	fmt.Println("\n[*] Hash kırma işlemi başlıyor...")
	startTime := time.Now()

	var cracked, failed int
	results := make([]Result, 0, len(targetHashes))

	for i, hash := range targetHashes {
		fmt.Printf("\n[%d/%d] İşleniyor: %s\n", i+1, len(targetHashes), hash)
		result, _ := crackHash(hash, wordlist, hashType, workers)
		results = append(results, *result)

		if result.Found {
			cracked++
			fmt.Printf("      ✓ Bulundu: %s\n", result.Password)
		} else {
			failed++
			fmt.Printf("      ✗ Bulunamadı\n")
		}
	}

	elapsed := time.Since(startTime)
	totalTried := len(wordlist) * len(targetHashes)
	hashesPerSec := float64(totalTried) / elapsed.Seconds()

	// Sonuç özeti
	fmt.Println("\n" + strings.Repeat("═", 70))
	fmt.Println("                         SONUÇ ÖZETİ")
	fmt.Println(strings.Repeat("═", 70))

	for i, result := range results {
		fmt.Printf("[%d] ", i+1)
		if result.Found {
			fmt.Printf("✓ %s -> %s\n", result.Hash, result.Password)
		} else {
			fmt.Printf("✗ %s -> Bulunamadı\n", result.Hash)
		}
	}

	fmt.Println(strings.Repeat("═", 70))
	fmt.Printf("Toplam Hash      : %d\n", len(targetHashes))
	fmt.Printf("Kırılan         : %d\n", cracked)
	fmt.Printf("Kırılamayan     : %d\n", failed)
	fmt.Printf("Başarı Oranı    : %.1f%%\n", float64(cracked)/float64(len(targetHashes))*100)
	fmt.Printf("Toplam Süre     : %s\n", elapsed)
	fmt.Printf("Hız             : %.2f hash/saniye\n", hashesPerSec)
	fmt.Println(strings.Repeat("═", 70))
}
