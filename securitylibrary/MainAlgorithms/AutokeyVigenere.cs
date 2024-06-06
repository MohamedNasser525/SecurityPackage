using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();

            string key = "";
            int keyIndex = 0;

            // Iterate over each character in the plaintext to recover the key
            for (int i = 0; i < plainText.Length; i++)
            {
                // Calculate the difference between the ASCII values of the corresponding characters in the plaintext and ciphertext to recover the key character
                int x = (cipherText[i] - plainText[i] + 26) % 26;
                x += 'A';
                char keyChar = (char)(x);

                // Add the key character to the key if the key is not yet as long as the plaintext
                if (keyIndex < plainText.Length)
                {
                    key += keyChar;
                    keyIndex++;
                }
            }

            // Initialize a temporary key with the first character of the recovered key
            string temp_key = "";
            temp_key += key[0];

            // Iterate over the remaining characters in the recovered key to try to guess the full key
            for (int i = 1; i < key.Length; i++)
            {
                // If the encrypted plaintext matches the actual ciphertext with the current key, return the current key
                if (cipherText.Equals(Encrypt(plainText, temp_key)))
                    return temp_key;

                temp_key += key[i];
            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();

            string plainText = "";
            int j = 0;

            // Iterate over each character in the ciphertext to decrypt it using the key
            for (int i = 0; i < cipherText.Length; i++)
            {
                // Calculate the ASCII value of the decrypted character using the ASCII values of the corresponding characters in the ciphertext and the key
                int c = (cipherText[i] - key[j] + 26) % 26 + 'a';

                // Add the decrypted character to the plaintext
                plainText += (char)c;

                // Add the current plaintext character to the key for use in decrypting the next ciphertext character
                key += plainText[j];

                j++;
            }

            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {

            plainText = plainText.ToLower();
            key = key.ToLower();

            string cipherText = "";
            int keyIndex = 0;

            // Loop through each character in the plaintext to encrypt it using the key
            for (int i = 0; i < plainText.Length; i++)
            {
                // Calculate the ASCII value of the encrypted character by adding the ASCII values of the corresponding plaintext and key characters
                // Subtract 2 times the ASCII value of 'a' to shift the range of the resulting values to be between 0 and 25
                // Take the result modulo 26 to wrap the value around to the beginning of the alphabet if necessary
                // Add the ASCII value of 'a' to shift the range back to the ASCII values for lowercase letters
                int encryptedChar = (plainText[i] + key[keyIndex] - 2 * 'a') % 26 + 'a';

                // Add the encrypted character to the ciphertext string
                cipherText += (char)encryptedChar;

                // Add the current plaintext character to the key for use in encrypting the next plaintext character
                key += plainText[i];

                keyIndex++;
            }

            return cipherText;
        }
    }
}