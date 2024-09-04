# Password and Email Compromise Checker

## English Version

This Go application checks if passwords or email addresses have been compromised using the [Have I Been Pwned](https://haveibeenpwned.com) API. It supports multiple proxy configurations to ensure anonymous and reliable checking.

### Features

- **Password Security Check:** Verifies if a password has been exposed in any known data breaches.
- **Email Breach Check:** Verifies if an email has been compromised using the Have I Been Pwned API.
- **Proxy Support:** Use proxies for all API requests to ensure privacy and prevent IP blocking.
- **Parallel Processing:** Leverages Go's goroutines for concurrent checks on large datasets.
- **Error Handling:** Captures and logs bad requests or failed checks into a separate file.

### Files Used
- `emails.txt`: List of email addresses to check.
- `passwords.txt`: List of passwords to verify.
- `both.txt`: A list of entries containing both emails and passwords.
- `proxies.txt`: A list of proxies in the format `IP:PORT:USERNAME:PASSWORD`.

### Output Files
- `good_passwords.txt`: Contains passwords that are not found in any breaches.
- `bad_passwords.txt`: Contains passwords that are compromised.
- `email_results.txt`: Lists emails that have been compromised.
- `both_results.txt`: Contains both compromised emails and passwords.
- `bad_requests.txt`: Logs failed API requests or other errors.

### Usage

1. **Install Go** on your system from [golang.org](https://golang.org/dl/).
2. Create the following files:
   - `emails.txt`, `passwords.txt`, `both.txt`, and `proxies.txt`.
3. Run the program:
   ```bash
   go run main.go or go run .
   ```

4. Results will be written to the corresponding output files in the same directory.

### Proxy Recommendations

For the best performance and reliability, I recommend using high-quality proxies from [NSTProxy](https://www.nstproxy.com). Their services ensure fast and anonymous requests with high uptime, perfect for this kind of application.

![NST Proxy](https://media.discordapp.net/attachments/578191434411278346/1214530808283398204/Capture_decran_2024-03-05_a_12.11.15.png?ex=66d991f5&is=66d84075&hm=8993f1241f1806bb22b9e8c71d9aa37bba77e57655ce31a8783a2cb3958aa9f8&format=webp&quality=lossless&width=2566&height=206&)

---

## Version Française

Cette application Go permet de vérifier si des mots de passe ou des adresses email ont été compromis en utilisant l'API [Have I Been Pwned](https://haveibeenpwned.com). Elle prend en charge plusieurs configurations de proxy pour garantir une vérification anonyme et fiable.

### Fonctionnalités

- **Vérification de Sécurité des Mots de Passe:** Vérifie si un mot de passe a été exposé dans des fuites de données connues.
- **Vérification de Compromission des Emails:** Vérifie si une adresse email a été compromise en utilisant l'API Have I Been Pwned.
- **Support des Proxies:** Utilise des proxies pour toutes les requêtes API afin d'assurer la confidentialité et éviter les blocages d'IP.
- **Traitement Parallèle:** Utilise les goroutines de Go pour effectuer des vérifications simultanées sur de grandes quantités de données.
- **Gestion des Erreurs:** Capture et journalise les requêtes échouées ou les erreurs dans un fichier séparé.

### Fichiers Utilisés

- `emails.txt` : Liste des adresses email à vérifier.
- `passwords.txt` : Liste des mots de passe à vérifier.
- `both.txt` : Liste contenant à la fois des emails et des mots de passe.
- `proxies.txt` : Liste des proxies au format `IP:PORT:UTILISATEUR:MOTDEPASSE`.

### Fichiers de Sortie

- `good_passwords.txt` : Contient les mots de passe qui ne sont pas trouvés dans les fuites.
- `bad_passwords.txt` : Contient les mots de passe compromis.
- `email_results.txt` : Liste des emails compromis.
- `both_results.txt` : Contient à la fois des emails et des mots de passe compromis.
- `bad_requests.txt` : Journal des requêtes API échouées ou des erreurs.

### Utilisation

1. **Installez Go** sur votre système depuis [golang.org](https://golang.org/dl/).
2. Créez les fichiers suivants :
   - `emails.txt`, `passwords.txt`, `both.txt` et `proxies.txt`.
3. Exécutez le programme :
   ```bash
   go run main.go ou go run .
   ```

4. Les résultats seront écrits dans les fichiers de sortie correspondants dans le même répertoire.

### Recommandation de Proxy

Pour de meilleures performances et une fiabilité accrue, je recommande d'utiliser des proxies de haute qualité provenant de [NSTProxy](https://www.nstproxy.com). Leurs services assurent des requêtes rapides et anonymes avec une disponibilité élevée, parfait pour ce type d'application.

![NST Proxy](https://media.discordapp.net/attachments/578191434411278346/1214530808283398204/Capture_decran_2024-03-05_a_12.11.15.png?ex=66d991f5&is=66d84075&hm=8993f1241f1806bb22b9e8c71d9aa37bba77e57655ce31a8783a2cb3958aa9f8&format=webp&quality=lossless&width=2566&height=206&)