Dit is een kleine Python applicatie waarmee je tekst en bestanden kunt versleutelen en weer ontsleutelen. dezelfde sleutel wordt gebruikt voor encryptie en decryptie. De tool is bedoeld als een veilige manier om te werken met encryptie.


# Hoe werkt de applicatie?

# De applicatie wordt gestart via de command-line. Je kunt kiezen om:

- tekst te versleutelen
- tekst te ontsleutelen
- bestanden te versleutelen of ontsleutelen
- een keyfile te maken
Zelfs als iemand de werking van de applicatie en de gebruikte methodes kent, heb je wel de sleutel nodig om het te laten werken. Dit voldoet aan Kerckhoffs’s Principe.

Voorbeelden:

# Dit zijn de commands die je kan gebruiken
python app.py encrypt --text "geheim bericht"
python app.py decrypt --text "HIER_DE_BASE64"
python app.py encrypt --infile input.txt --outfile input.txt.enc
python app.py decrypt --infile input.txt.enc --outfile output.txt
python app.py generate-key --out key.bin

# ik heb met deze opdracht gebruik gemaakt van stackoverflow aangezien ik best veel bugs had. het is nu opgelost.

# Ik heb gebruik gemaakt van de commandline interface en heb gebruik gemaakt van AES-256
AES-256 is een moderne en veilige methode die openbaar bekend is, maar toch veilig blijft zolang de sleutel geheim is (zegt het Kerckhoffs’s Principe).