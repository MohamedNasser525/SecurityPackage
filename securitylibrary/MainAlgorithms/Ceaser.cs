using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            // throw new NotImplementedException();

            string cipherText = "";
            int cipherText_indx = 0;
            plainText = plainText.ToUpper();
          
            for (int i = 0; i < plainText.Length; i++)
            {

                cipherText_indx = ((int)((plainText[i] + key) - 'A') % 26 + 'A');
                cipherText += (char)cipherText_indx;
               
            }


            return cipherText;

        }

        public string Decrypt(string cipherText, int key)
        {
            // throw new NotImplementedException();

            string plainText = "";
            cipherText = cipherText.ToUpper();

            for (int i = 0; i < cipherText.Length; i++)
            {

                int plainText_indx = (int)cipherText[i] - key;

                if (plainText_indx >= (int)'A')
                {
                    plainText += (char)plainText_indx;
                }
                else
                {
                    plainText += (char)(plainText_indx + 26);
                }

            }
            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();

            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();

            int plainTsxt_index = plainText[0];
            int cipherText_index = cipherText[0];

            int key = (cipherText_index - plainTsxt_index) % 26;

            for(int i=0; i<=plainText.Length; i++)
            {

                if (key < 0)
                {
                    key += 26;
                }     
            }

            return key;
        }
    }
}
