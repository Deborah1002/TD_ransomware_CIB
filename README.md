CHIFFREMENT

1- L'algorithme de chiffrement utilisé dans le code fourni est le chiffrement par ou exclusif (XOR).
Cet algorithme est relativement simple et rapide, mais il n'est pas considéré comme robuste pour une utilisation en sécurité informatique, car il est vulnérable aux attaques de cryptanalyse. Il est souvent utilisé pour des tâches simples de masquage de données, mais pas pour le chiffrement de données sensibles.

Génération des secrets

2-l n'est pas recommandé de hacher le sel et la clé directement, car cela peut réduire l'entropie (c'est-à-dire le niveau de désordre et d'imprévisibilité) des valeurs hachées, rendant ainsi les clés dérivées moins sécurisées. De plus, l'utilisation d'un algorithme de dérivation de clé, tel que PBKDF2, offre une protection supplémentaire contre les attaques par force brute en augmentant le coût en temps et en ressources pour générer des clés dérivées.

Utiliser un HMAC (Hash-based Message Authentication Code) pour hacher le sel et la clé pourrait également être envisagé, mais cela ne fournirait pas les avantages supplémentaires offerts par PBKDF2. En effet, PBKDF2 permet de ralentir les attaques par force brute en répétant le processus de hachage plusieurs fois et en ajustant la longueur de la clé dérivée.


Setup

3-Il est préférable de vérifier si un fichier token.bin n'est pas déjà présent pour les raisons suivantes:

Éviter les conflits: Si un fichier token.bin existe déjà, cela signifie que l'ordinateur a peut-être déjà été infecté par le ransomware. Dans ce cas, il est préférable de ne pas écraser les anciennes données cryptographiques pour éviter de causer des problèmes supplémentaires pour la victime. Par exemple, si un utilisateur essaie de récupérer ses fichiers en payant la rançon, écraser les données cryptographiques existantes pourrait rendre la récupération des fichiers impossible.

Économiser des ressources: La vérification de l'existence d'un fichier token.bin permet d'économiser des ressources en évitant d'exécuter le processus de création et d'envoi des éléments cryptographiques inutilement. Cela peut également aider à réduire la charge sur le serveur CNC.

Améliorer la discrétion: Si le ransomware vérifie d'abord l'existence d'un fichier token.bin, il peut éviter de se révéler inutilement à la victime et aux outils de détection en évitant d'exécuter des actions inutiles.


Verifer et utiliser la clef

4-La méthode check_key utilise HMAC avec l'algorithme de hachage SHA256 et le sel comme clé pour vérifier l'intégrité et l'authenticité de la clé candidate. La méthode set_key décode d'abord la clé candidate en base64, puis vérifie si elle est correcte en utilisant la méthode check_key. Si la clé est correcte, elle est définie comme self._key. Sinon, une exception est levée.


