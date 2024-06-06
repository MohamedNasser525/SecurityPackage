using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();

            // Get the length of the ciphertext
            int clength = cipherText.Length;

            string alphabet = "abcdefghijklmnopqrstuvwxyz";

            string key = "";
            string temp = "";

            // Iterate over each character in the ciphertext to recover the key
            for (int i = 0; i < clength; i++)
            {
                // Calculate the key character by subtracting the index of the plainText character from the index of the cipherText character, then adding 26 and taking the modulus of 26 to wrap around to the end of the alphabet if necessary
                key += alphabet[((alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(plainText[i])) + 26) % 26];
            }

            // Initialize a temporary key with the first character of the recovered key
            temp += key[0];

            // Get the length of the recovered key
            int klength = key.Length;

            // Iterate over the remaining characters in the recovered key to try to guess the full key
            for (int i = 1; i < klength; i++)
            {
                // If the encrypted plaintext matches the actual ciphertext with the current key, return the current key
                if (cipherText.Equals(Encrypt(plainText, temp)))
                {
                    return temp;
                }

                // Add the next character of the recovered key to the temporary key
                temp += key[i];
            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();

            int clength = cipherText.Length;

            string plaintext = "";

            string alphabet = "abcdefghijklmnopqrstuvwxyz";

            int temp = 0;

            // If the key length is not equal to the ciphertext length, repeat the key until it matches the length of the ciphertext
            while (key.Length != clength)
            {
                key += key[temp];
                temp++;
            }

            // Iterate over each character in the ciphertext to decrypt it using the key
            for (int i = 0; i < clength; i++)
            {
                // Calculate the index of the decrypted character by subtracting the index of the key character from the index of the ciphertext character, then adding 26 and taking the modulus of 26 to wrap around to the end of the alphabet if necessary
                plaintext += alphabet[((alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(key[i])) + 26) % 26];
            }

            return plaintext;
        }

        public string Encrypt(string plainText, string key)
        {
            string alpha = "abcdefghijklmnopqrstuvwxyz";

            plainText = plainText.ToLower();

            string cipherText = "";
            int temp = 0;

            // If the key length is not equal to the plaintext length, repeat the key until it matches the length of the plaintext
            while (key.Length != plainText.Length)
            {
                key = key + key[temp];
                temp++;
            }

            int indxOfKey, indxOfPlain;

            // Loop through each character in the plaintext to encrypt it using the key
            for (int i = 0; i < plainText.Length; i++)
            {
                // Get the index of the current character in the key and the plaintext
                indxOfKey = alpha.IndexOf(key[i]);
                indxOfPlain = alpha.IndexOf(plainText[i]);

                // Calculate the index of the encrypted character by adding the indexes of the key and plaintext characters, then taking the modulus of 26 to wrap around to the beginning of the alphabet if necessary
                int encryptedChar = (indxOfKey + indxOfPlain) % 26;

                // Add the encrypted character to the ciphertext string
                cipherText += alpha[encryptedChar];
            }

            return cipherText;
        }
    }
}