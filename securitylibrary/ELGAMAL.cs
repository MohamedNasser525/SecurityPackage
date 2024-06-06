/*using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {

            throw new NotImplementedException();

        }
     
        public int Decrypt(int c1, int c2, int x, int q)
        {

            throw new NotImplementedException();

        }
    }
}
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public int MyPow(int ALPHAorY, int X, int Q)
        {
            int z = 1;
            for (int i = 0; i < X; i++)
            {
                z = (z * ALPHAorY) % Q;
            }
            return z;

        }
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> result = new List<long>();
            int bigK = MyPow(y, k, q) % q;
            int c1 = MyPow(alpha, k, q) % q;
            int c2 = (bigK * m) % q;
            result.Add(c1);
            result.Add(c2);
            return result;
        }

        public int Decrypt(int c1, int c2, int x, int q)
        {
            int K = (int)MyPow(c1, x, q) % q;

            int inverseK = 0, z = 0;
            for (int i = 0; i < q; i++)
            {
                z = (K * i) % q;
                if (z == 1)
                {
                    inverseK = i;
                }
            }

            return (c2 * inverseK) % q;
        }
    }
}