using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public int MyPow(int ALPHAorY, int X, int Q)
        {
            int z = 1;
            for (int i = 0; i < X; i++)
            {
                z = (z * ALPHAorY) % Q;
            }
            return z;

        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
           
            List<int> result = new List<int>();
            // q is prime number
            // alpha is primitive root of q
           int Ya = MyPow(alpha, xa, q) % q; //public key of a , ya = alpkha pow xa mod q
           int Yb = MyPow(alpha, xb, q) % q;//public key of b ,yb = alpkha pow xb mod q
           int Ka = MyPow(Yb, xa, q) % q; //secret key of a, Ka = yb pow xa mod q
           int Kb = MyPow(Ya, xb, q) % q; //secret key of b, Ka = yb pow xa mod q
            
            result.Add(Ka);
            result.Add(Kb);
            return result;
        }

    }
}