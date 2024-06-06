using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class PlayFair : ICryptographicTechnique<string, string>
    {
        private const string Characters = "abcdefghiklmnopqrstuvwxyz";
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }



        private char[,] GKM(string kWord)
        {
            char[,] mx2d = new char[5, 5];
            int row = 0, column = 0;
            string remindedAlphabitic = new string(Characters.Where(c => !kWord.Contains(c)).ToArray());
            string mx2d_input = kWord + remindedAlphabitic;

            foreach (char element in mx2d_input)
            {
                mx2d[row, column] = element;
                column++;
                if (column == 5)
                {
                    column = 0;
                    row++;
                }
            }
            return mx2d;
        }


        private string AdjustmentPT(string pT)
        {
            string newPT = pT;
            int hasDuplicate = 0;
            for (int j = 1; j < pT.Length && hasDuplicate == 0; j++)
            {
                if (newPT[j - 1] == newPT[j])
                {
                    hasDuplicate = 1;
                }
            }

            if (hasDuplicate == 1)
            {
                for (int i = 0; i < pT.Length; i += 2)
                {
                    if (newPT[i] == newPT[i + 1])
                    {
                        newPT = newPT.Insert(i + 1, "x");
                    }
                }
            }

            if (newPT.Length % 2 == 1)
            {
                newPT += "x";
            }
            return newPT;
        }

        private (int, int) GetCharacterP(char element, char[,] mx2d)
        {
            int sizeElement = mx2d.GetLength(0);

            for (int i = 0; i < sizeElement * sizeElement; i++)
            {
                int row = i / sizeElement;
                int column = i % sizeElement;

                if (mx2d[row, column] == element)
                {
                    return (row, column);
                }
            }

            return (0, 0);
        }



        private string DivideEncryptIntoPair(char element1, char element2, char[,] mx2d)
        {
            string encryptpairs = "";
            (int elemntRow1, int elementColumn1) = GetCharacterP(element1, mx2d);
            (int elemntRow2, int elementColumn2) = GetCharacterP(element2, mx2d);

            switch (0)
            {
                case int _ when elemntRow1 == elemntRow2:
                    elementColumn1 = (elementColumn1 + 1) % 5;
                    elementColumn2 = (elementColumn2 + 1) % 5;
                    break;
                case int _ when elementColumn1 == elementColumn2:
                    elemntRow1 = (elemntRow1 + 1) % 5;
                    elemntRow2 = (elemntRow2 + 1) % 5;
                    break;
                default:
                    (elementColumn1, elementColumn2) = (elementColumn2, elementColumn1);
                    break;
            }

            encryptpairs += mx2d[elemntRow1, elementColumn1];
            encryptpairs += mx2d[elemntRow2, elementColumn2];

            return encryptpairs;
        }

        private string DivideDecryptptIntoPair(char a, char b, char[,] mx2d)
        {
            string decryptPair = "";
            (int elemntRow1, int elemntColumn1) = GetCharacterP(a, mx2d);
            (int elemntRow2, int elemntColumn2) = GetCharacterP(b, mx2d);

            switch (0)
            {
                case int _ when elemntRow1 == elemntRow2:
                    elemntColumn1 = (elemntColumn1 + 4) % 5;
                    elemntColumn2 = (elemntColumn2 + 4) % 5;
                    break;
                case int _ when elemntColumn1 == elemntColumn2:
                    elemntRow1 = (elemntRow1 + 4) % 5;
                    elemntRow2 = (elemntRow2 + 4) % 5;
                    break;
                default:
                    (elemntColumn1, elemntColumn2) = (elemntColumn2, elemntColumn1);
                    break;
            }

            decryptPair += mx2d[elemntRow1, elemntColumn1];
            decryptPair += mx2d[elemntRow2, elemntColumn2];

            return decryptPair;
        }



        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string PT = "";
            string result = new string(key.Distinct().ToArray());
            key = result.Replace("j", "i");


            char[,] mx2d = GKM(key);
            foreach (var pair in SplitIntoPairs(cipherText))
            {
                PT += DivideDecryptptIntoPair(pair.Item1, pair.Item2, mx2d);
            }


            PT = PT.ToLower();
            StringBuilder originalData = new StringBuilder(PT);

            for (int i = 0; i < originalData.Length - 2; i += 2)
            {
                if (originalData[i] == originalData[i + 2] && originalData[i + 1] == 'x')
                {
                    originalData.Remove(i + 1, 1);
                    i--;
                }
            }

            if (originalData[originalData.Length - 1] == 'x')
            {
                originalData.Remove(originalData.Length - 1, 1);
            }
            PT = originalData.ToString();

            return PT;
        }

        public string Encrypt(string plainText, string key)
        {
            string CT = "";
            string result = new string(key.Distinct().ToArray());
            key = result.Replace("j", "i");

            plainText = AdjustmentPT(plainText);
            char[,] mx2d = GKM(key);
            foreach (var pair in SplitIntoPairs(plainText))
            {
                CT += DivideEncryptIntoPair(pair.Item1, pair.Item2, mx2d);
            }


            return CT;
        }
        private IEnumerable<(char, char)> SplitIntoPairs(string text)
        {
            for (int i = 0; i < text.Length; i += 2)
            {
                yield return (text[i], i + 1 < text.Length ? text[i + 1] : 'X');
            }
        }





    }
}
