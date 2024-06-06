using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();

            int key = 0;
            for (int i = 1; i <= plainText.Length; i++)
            {

                if (string.Compare(Encrypt(plainText, i), cipherText) == 0)
                {
                    key = i;
                   
                }

            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            // throw new NotImplementedException();

            cipherText = cipherText.ToUpper();
            double len = cipherText.Length;
            double noOfcol = (len / key);
            int column = Convert.ToInt32(Math.Ceiling(noOfcol));
            char[,] table = new char[key, column];
            int count = 0;
            string plaintext = "";

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    if (count < cipherText.Length)
                    {
                        table[i, j] = cipherText[count];
                        count++;
                    }
                }

            }

            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < key; j++)
                {

                    plaintext +=table[j, i];

                }
            }

            return plaintext;
        }


        public string Encrypt(string plainText, int key)
        {
            //   throw new NotImplementedException();

            plainText = plainText.ToUpper();
            double len = plainText.Length;
            double noOfcol = (len / key);
            int column = Convert.ToInt32(Math.Ceiling(noOfcol));
            char[,] table = new char[key, column];
            int count = 0;
            string ciphertext = "";

            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (count < plainText.Length)
                    {
                        table[j, i] = plainText[count];
                        count++;
                    }
                }

            }
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < column; j++)
                {

                    ciphertext +=table[i, j];

                }
            }
            return ciphertext;
        }
    }
}
