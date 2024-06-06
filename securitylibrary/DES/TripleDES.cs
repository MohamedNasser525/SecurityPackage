using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        DES des = new DES();
        public string Decrypt(string cipherText, List<string> key)
        {
            //throw new NotImplementedException();
            string plainText;
            string cipherText2;
            string plainText2;
            plainText = des.Decrypt(cipherText, key[0]);
            cipherText2 = des.Encrypt(plainText, key[1]);
            plainText2 = des.Decrypt(cipherText2, key[0]);
            return plainText2;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            //throw new NotImplementedException();
            string cipherText;
            string plainText2;
            string cipherText2;
            cipherText = des.Encrypt(plainText, key[0]);
            plainText2 = des.Decrypt(cipherText, key[1]);
            cipherText2 = des.Encrypt(plainText2, key[0]);
            return cipherText2;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
