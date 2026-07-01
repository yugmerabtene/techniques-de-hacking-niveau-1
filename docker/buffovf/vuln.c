/**
 * =====================================================================
 * vuln.c — Programme C volontairement vulnérable à un buffer overflow
 * =====================================================================
 * Ce programme lit une entrée utilisateur et la copie dans un tampon
 * de taille fixe sans vérification de longueur. Il est conçu pour
 * l'apprentissage de l'exploitation de dépassement de tampon en pile.
 *
 * Compilation recommandée (volontairement sans protections) :
 *   gcc -fno-stack-protector -z execstack -no-pie -g -o vuln vuln.c
 * =====================================================================
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/**
 * Fonction vulnérable : copie l'entrée utilisateur dans un tampon
 * local de 64 octets SANS vérifier la longueur de la source.
 *
 * @param input  Chaîne provenant de l'entrée standard (stdin)
 *
 * Disposition de la pile (stack layout) pour x86/x86_64 :
 *   [buffer (64 octets)] [saved EBP/RBP (4/8 octets)] [adresse de retour]
 * Si l'entrée dépasse 64 octets, elle écrase le saved base pointer
 * puis l'adresse de retour, permettant de rediriger l'exécution.
 */
void vulnerable_function(char *input) {
    char buffer[64];                // Tampon local de 64 octets sur la pile
    strcpy(buffer, input);          // VULNÉRABLE : strcpy() ne vérifie pas
                                    // la taille de destination. Si input
                                    // fait > 64 octets, on écrase la pile.
    printf("Input received: %s\n", buffer);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);  // Désactive le buffering stdout (socat + fork ne flush pas sinon)
    char input[256];                // Tampon source de 256 octets — peut
                                    // largement dépasser les 64 du buffer

    // fgets lit au maximum sizeof(input)-1 caractères depuis stdin.
    // Retourne NULL si EOF ou erreur (ex: entrée vide).
    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("Usage: echo <input> | %s\n", "vuln");
        return 1;
    }

    // strcspn retourne la position du premier '\n' dans input.
    // On le remplace par '\0' pour supprimer le saut de ligne
    // que fgets conserve en fin de chaîne.
    input[strcspn(input, "\n")] = 0;

    // Appel de la fonction vulnérable avec l'entrée utilisateur.
    // C'est ici que l'overflow se produit si len(input) > 64.
    vulnerable_function(input);

    return 0;
}
