using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {

        public int Encrypt(int firstP, int secondP, int Msg, int e)
        {
            int modulus_n = firstP * secondP;

            // Calculate Euler's totient function φ(n) for the modulus n
            int phay_n = (firstP - 1) * (secondP - 1);

            int cipherTxt = 1;

            // Calculate the plaintext message modulo n and store the result in the ciphertext variable c
            cipherTxt = Msg % modulus_n;

            // Perform modular exponentiation to encrypt the message using the public exponent e
            for (int i = 1; i < e; i++)
            {
                // Update the ciphertext by multiplying it with Message and taking the result modulo n
                cipherTxt = (cipherTxt * Msg) % modulus_n;
            }
            return cipherTxt;
        }

        public int Decrypt(int firstP, int secondP, int cipheredTxt, int e)
        {
            int modulus_n = firstP * secondP;
            int phay_n = (firstP - 1) * (secondP - 1);
            int ptivateKey, Msg = 1;

            // Find the private key by iterating through possible values and checking if d * e % φ(n) equals 1
            for (ptivateKey = 0; ptivateKey < modulus_n; ptivateKey++)
                if (ptivateKey * e % phay_n == 1)
                    break;

            // Extract the ciphertext C from the encrypted message and store it in M
            Msg = cipheredTxt % modulus_n;

            // Decrypt the message using the private key by performing modular exponentiation
            for (int i = 1; i < ptivateKey; i++)
            {
                Msg = (Msg * cipheredTxt) % modulus_n;
            }
            return Msg;
        }
    }
}