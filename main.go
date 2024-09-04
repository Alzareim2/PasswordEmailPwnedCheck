package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

func loadProxies(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxies = append(proxies, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	fmt.Println("Proxies chargés avec succès.")
	return proxies, nil
}

func loadItems(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var items []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		items = append(items, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	fmt.Printf("Données de %s chargées avec succès.\n", filename)
	return items, nil
}

func sha1Hash(password string) string {
	hash := sha1.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

func createHttpClient(proxy string) *http.Client {
	proxyURLParts := strings.Split(proxy, ":")
	proxyIP := proxyURLParts[0] + ":" + proxyURLParts[1]
	proxyUsername := proxyURLParts[2]
	proxyPassword := proxyURLParts[3]

	proxyURL, _ := url.Parse("http://" + proxyIP)
	auth := base64.StdEncoding.EncodeToString([]byte(proxyUsername + ":" + proxyPassword))
	proxyAuthHeader := "Basic " + auth

	tlsConfig := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}

	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout:   20 * time.Second,
			KeepAlive: 20 * time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * 30,
	}

	transport.ProxyConnectHeader = http.Header{}
	transport.ProxyConnectHeader.Add("Proxy-Authorization", proxyAuthHeader)

	return client
}

func checkPwnedPassword(password string, proxies []string, rng *rand.Rand, wg *sync.WaitGroup, goodPasswords, badPasswords, badRequests chan<- string) {
	defer wg.Done()

	hash := sha1Hash(password)
	prefix := hash[:5]
	suffix := strings.ToUpper(hash[5:])

	proxy := proxies[rng.Intn(len(proxies))]

	client := createHttpClient(proxy)
	if client == nil {
		fmt.Println("Erreur lors de la création du client HTTP")
		return
	}

	url := "https://api.pwnedpasswords.com/range/" + prefix
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Erreur lors de la requête pour le mot de passe %s : %v\n", password, err)
		badRequests <- fmt.Sprintf("Password: %s, Error: %v", password, err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Mot de passe: %s, Statut HTTP: %d\n", password, resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Erreur : reçu le code HTTP %d pour le mot de passe %s\n", resp.StatusCode, password)
		badRequests <- fmt.Sprintf("Password: %s, Status: %d", password, resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Erreur lors de la lecture de la réponse pour le mot de passe %s : %v\n", password, err)
		badRequests <- fmt.Sprintf("Password: %s, Error: %v", password, err)
		return
	}

	lines := strings.Split(string(body), "\n")
	compromised := false
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) == 2 && parts[0] == suffix {
			compromised = true
			badPasswords <- password
			fmt.Printf("Mot de passe compromis : %s\n", password)
			break
		}
	}

	if !compromised {
		goodPasswords <- password
		fmt.Printf("Mot de passe sécurisé : %s\n", password)
	}
}

func checkPwnedEmail(email string, proxies []string, rng *rand.Rand, wg *sync.WaitGroup, results, badRequests chan<- string) {
	defer wg.Done()

	proxy := proxies[rng.Intn(len(proxies))]

	client := createHttpClient(proxy)
	if client == nil {
		fmt.Println("Erreur lors de la création du client HTTP")
		return
	}

	url := "https://haveibeenpwned.com/api/v2/unifiedsearch/" + url.QueryEscape(email)
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Erreur lors de la requête pour l'email %s : %v\n", email, err)
		badRequests <- fmt.Sprintf("Email: %s, Error: %v", email, err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Email: %s, Statut HTTP: %d\n", email, resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		badRequests <- fmt.Sprintf("Email: %s, Status: %d", email, resp.StatusCode)
		return
	}

	results <- email + " : Compromis"
}

func writeToFile(filename string, data <-chan string, done chan<- bool) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Erreur lors de la création du fichier %s : %v\n", filename, err)
		done <- false
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for line := range data {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			fmt.Printf("Erreur lors de l'écriture dans le fichier %s : %v\n", filename, err)
		}
	}

	writer.Flush()
	fmt.Printf("Fichier %s écrit avec succès.\n", filename)

	done <- true
}

func main() {
	proxies, err := loadProxies("proxies.txt")
	if err != nil {
		fmt.Println("Erreur lors de la lecture du fichier proxies.txt:", err)
		return
	}

	var passwords, emails, both []string
	filesToCheck := 0

	if _, err := os.Stat("emails.txt"); err == nil {
		emails, _ = loadItems("emails.txt")
		filesToCheck++
	}

	if _, err := os.Stat("passwords.txt"); err == nil {
		passwords, _ = loadItems("passwords.txt")
		filesToCheck++
	}

	if _, err := os.Stat("both.txt"); err == nil {
		both, _ = loadItems("both.txt")
		filesToCheck++
	}

	if filesToCheck == 0 {
		fmt.Println("Erreur : Aucun fichier (emails.txt, passwords.txt, both.txt) trouvé.")
		return
	}

	var wg sync.WaitGroup
	goodPasswords := make(chan string, len(passwords))
	badPasswords := make(chan string, len(passwords))
	emailResults := make(chan string, len(emails))
	bothResults := make(chan string, len(both))
	badRequests := make(chan string, len(passwords)+len(emails)+len(both))
	doneGood := make(chan bool)
	doneBad := make(chan bool)
	doneEmails := make(chan bool)
	doneBoth := make(chan bool)
	doneBadRequests := make(chan bool)

	go writeToFile("bad_requests.txt", badRequests, doneBadRequests)

	if len(passwords) > 0 {
		go writeToFile("good_passwords.txt", goodPasswords, doneGood)
		go writeToFile("bad_passwords.txt", badPasswords, doneBad)
	}

	if len(emails) > 0 {
		go writeToFile("email_results.txt", emailResults, doneEmails)
	}

	if len(both) > 0 {
		go writeToFile("both_results.txt", bothResults, doneBoth)
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for _, password := range passwords {
		wg.Add(1)
		go checkPwnedPassword(password, proxies, rng, &wg, goodPasswords, badPasswords, badRequests)
	}

	for _, email := range emails {
		wg.Add(1)
		go checkPwnedEmail(email, proxies, rng, &wg, emailResults, badRequests)
	}

	for _, item := range both {
		wg.Add(1)
		go checkPwnedEmail(item, proxies, rng, &wg, bothResults, badRequests)
		wg.Add(1)
		go checkPwnedPassword(item, proxies, rng, &wg, goodPasswords, badPasswords, badRequests)
	}

	wg.Wait()

	if len(passwords) > 0 {
		close(goodPasswords)
		close(badPasswords)
		if <-doneGood && <-doneBad {
			fmt.Println("Fichiers good_passwords.txt et bad_passwords.txt écrits avec succès.")
		}
	}

	if len(emails) > 0 {
		close(emailResults)
		if <-doneEmails {
			fmt.Println("Fichier email_results.txt écrit avec succès.")
		}
	}

	if len(both) > 0 {
		close(bothResults)
		if <-doneBoth {
			fmt.Println("Fichier both_results.txt écrit avec succès.")
		}
	}

	close(badRequests)
	if <-doneBadRequests {
		fmt.Println("Fichier bad_requests.txt écrit avec succès.")
	}
}
