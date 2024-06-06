using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        private const string alphabets = "abcdefghijklmnopqrstuvwxyz";
        // Alphabit = A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z
        // Plain Txt= M,E,E,T,M,E,A,F,T,E,R,T,H,E,T,O,G,A,P,A,R,T,Y
        // CipherTxt= P,H,H,W,P,H,D,I,W,H,U,W,K,H,W,R,J,D,S,D,U,W,B
        // Main Key = D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,A,B,C
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            //string alphabets = "abcdefghijklmnopqrstuvwxyz";
            string key = "";
            string unusedChars = "";
            char alphabetLetter;
            int letterIndex = 0;
            while (letterIndex < alphabets.Length)
            {
                alphabetLetter = alphabets[letterIndex];
                if (!cipherText.Contains(alphabetLetter))
                {
                    unusedChars += alphabetLetter;
                }
                letterIndex++;
            }
            int unusedCharsIndex = 0;
            int indexOfLetterInPlainText = 0;
            while (indexOfLetterInPlainText < alphabets.Length)
            {
                alphabetLetter = alphabets[indexOfLetterInPlainText];
                int indexInPlainText = plainText.IndexOf(alphabetLetter);
                if (indexInPlainText != -1)
                {
                    key += cipherText[indexInPlainText];
                }
                else
                {
                    key += unusedChars[unusedCharsIndex];
                    unusedCharsIndex++;
                }
                indexOfLetterInPlainText++;
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            //string alphabets = "abcdefghijklmnopqrstuvwxyz";
            string plainText = "";
            int cipherLetterIndex = 0;
            while (cipherLetterIndex < cipherText.Length)
            {
                char cipherLetter = cipherText[cipherLetterIndex];
                int indexOfLetterInKey = key.IndexOf(cipherLetter);
                plainText += alphabets[indexOfLetterInKey];
                cipherLetterIndex++;
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            key = key.ToLower();
            //string alphabets = "abcdefghijklmnopqrstuvwxyz";
            string cipherText = "";
            int plainCharIndex = 0;
            while (plainCharIndex < plainText.Length)
            {
                char plainChar = plainText[plainCharIndex];
                int indexOfLetterInAlphabets = alphabets.IndexOf(plainChar);
                cipherText += key[indexOfLetterInAlphabets];
                plainCharIndex++;
            }
            return cipherText;
        }


        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();
            //string alphabets = "abcdefghijklmnopqrstuvwxyz";
            cipher = cipher.ToLower();
            List<double> sizes = new List<double>();
            List<int> index = new List<int>();
            string freqOrder = "";
            string targetFreq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            int currentCharIndex = 0;
            while (currentCharIndex < alphabets.Length)
            {
                char currentChar = alphabets[currentCharIndex];
                int count = cipher.Count(c => c == currentChar);
                sizes.Add(count * 100.0 / cipher.Length);
                index.Add(currentCharIndex);
                currentCharIndex++;
            }
            index.Sort((a, b) => sizes[b].CompareTo(sizes[a]));
            int i = 0;
            while (i < index.Count)
            {
                freqOrder += alphabets[index[i]];
                i++;
            }
            string key = this.Analyse(targetFreq.ToLower(), freqOrder);
            return this.Decrypt(cipher, key);
        }
    }
}