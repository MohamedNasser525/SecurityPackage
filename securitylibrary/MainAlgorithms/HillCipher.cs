using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<List<int>> PT = new List<List<int>>();
            List<List<int>> CT = new List<List<int>>();

            // Initialize PT and CT matrices
            int idx = 0;
            for (int i = 0; i < 2; ++i)
            {
                PT.Add(new List<int>());
                CT.Add(new List<int>());
                for (int j = 0; j < 2; ++j)
                {
                    PT[i].Add(plainText[idx]);
                    CT[i].Add(cipherText[idx]);
                    idx++;
                }
            }

            // Iterate through all possible keys
            foreach (int r1c1 in Enumerable.Range(0, 26))
            {
                foreach (int r1c2 in Enumerable.Range(0, 26))
                {
                    foreach (int r2c1 in Enumerable.Range(0, 26))
                    {
                        foreach (int r2c2 in Enumerable.Range(0, 26))
                        {
                            List<List<int>> Key = new List<List<int>>();
                            Key.Add(new List<int> { r1c1, r1c2 });
                            Key.Add(new List<int> { r2c1, r2c2 });

                            if (IsCorrectKey(plainText, cipherText, Key))
                            {
                                List<int> flattenedMatrix = new List<int>();
                                foreach (var row in Key)
                                {
                                    foreach (var element in row)
                                    {
                                        flattenedMatrix.Add(element);
                                    }
                                }
                                return flattenedMatrix;
                            }
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();

        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int keysize = (int)Math.Sqrt(key.Count);
            List<int> result = new List<int>();
            List<List<int>> Key = CreateMatrixByKey(key);

            if (!IsCorrect(Key))
                throw new InvalidAnlysisException();

            List<List<int>> nkey = GetMatrix(Key);

            int i = 0;
            while (i < cipherText.Count)
            {
                List<List<int>> CT = initializeMatrix(keysize, 1);
                for (int j = i; j < Math.Min(i + keysize, cipherText.Count); j++)
                {
                    CT[j - i][0] = cipherText[j];
                }

                List<List<int>> PT = MultipleMatrix(nkey, CT);


                List<int> flattenedMatrixPT = new List<int>();
                foreach (var row in PT)
                {
                    foreach (var element in row)
                    {
                        flattenedMatrixPT.Add(element);
                    }
                }
                foreach (int c in flattenedMatrixPT)
                {
                    result.Add(c);
                }

                i += keysize;
            }

            return result;

        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {

            int len = (int)Math.Sqrt(key.Count);
            List<int> result = new List<int>();
            List<List<int>> K = CreateMatrixByKey(key);

            if (!IsCorrect(K))
                throw new InvalidAnlysisException();

            int i = 0;
            while (i < plainText.Count)
            {
                List<List<int>> PT = initializeMatrix(len, 1);
                for (int j = i; j < Math.Min(i + len, plainText.Count); ++j)
                {
                    PT[j - i][0] = plainText[j];
                }

                List<List<int>> CT = MultipleMatrix(K, PT);


                List<int> flattenedMatrix = new List<int>();
                foreach (var row in CT)
                {
                    foreach (var element in row)
                    {
                        flattenedMatrix.Add(element);
                    }
                }

                foreach (int c in flattenedMatrix)
                {
                    result.Add(c);
                }

                i += len;
            }

            return result;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {

            List<List<int>> PT = initializeMatrix(3, 3);
            List<List<int>> CT = initializeMatrix(3, 3);

            int idx = 0;
            int i = 0;
            while (i < 3)
            {
                int j = 0;
                while (j < 3)
                {
                    PT[j][i] = plainText[idx];
                    CT[j][i] = cipherText[idx];
                    idx++;
                    j++;
                }
                i++;
            }

            List<List<int>> InvPT = GetMatrix(PT);
            List<List<int>> Key = MultipleMatrix(CT, InvPT);

            if (!IsCorrect(Key))
                throw new InvalidAnlysisException();


            List<int> flattenedMatrix = new List<int>();
            foreach (var row in Key)
            {
                foreach (var element in row)
                {
                    flattenedMatrix.Add(element);
                }
            }
            return flattenedMatrix;

        }

        // Strings 
        public string Analyse(string plainText, string cipherText)
        {
            List<int> PT = StringToList(plainText.ToUpper());
            List<int> CT = StringToList(cipherText.ToUpper());
            List<int> Key = Analyse(PT, CT);
            string txtKey = ListToString(Key);
            return txtKey;
        }


        public string Decrypt(string cipherText, string key)
        {
            List<int> CT = StringToList(cipherText.ToUpper());
            List<int> Key = StringToList(key.ToUpper());
            List<int> PT = Decrypt(CT, Key);
            string txtPT = ListToString(PT);
            return txtPT;
        }



        public string Encrypt(string plainText, string key)
        {
            List<int> PT = StringToList(plainText.ToUpper());
            List<int> Key = StringToList(key.ToUpper());
            List<int> CT = Encrypt(PT, Key);
            string txtCT = ListToString(CT);
            return txtCT;
        }



        public string Analyse3By3Key(string plainText, string cipherText)
        {
            List<int> PT = StringToList(plainText.ToUpper());
            List<int> CT = StringToList(cipherText.ToUpper());
            List<int> Key = Analyse3By3Key(PT, CT);
            string txtKey = ListToString(Key);
            return txtKey;
        }

        bool IsCorrectKey(List<int> plainText, List<int> cipherText, List<List<int>> Key)
        {

            if (!IsCorrect(Key))
                return false;
            List<int> result = new List<int>();
            int len = 2;

            for (int i = 0; i < plainText.Count; i += len)
            {
                List<List<int>> PT = initializeMatrix(len, 1);
                for (int j = i; j < i + len; ++j)
                    PT[j - i][0] = plainText[j];

                List<List<int>> CT = MultipleMatrix(Key, PT);


                List<int> flattenedMatrix = new List<int>();
                foreach (var row in CT)
                {
                    foreach (var element in row)
                    {
                        flattenedMatrix.Add(element);
                    }
                }

                foreach (int c in flattenedMatrix)
                    result.Add(c);

            }
            return (result.SequenceEqual(cipherText));
        }

        private List<List<int>> CreateMatrixByKey(List<int> key)
        {
            int len = (int)Math.Sqrt(key.Count);

            List<List<int>> result = new List<List<int>>();
            List<int> row = new List<int>();

            for (int i = 0; i < key.Count; ++i)
            {
                row.Add(key[i]);
                if ((i + 1) % len == 0)
                {
                    result.Add(row);
                    row = new List<int>();
                }
            }
            return result;
        }
        private List<List<int>> MultipleMatrix(List<List<int>> K, List<List<int>> PT)
        {
            List<List<int>> result = initializeMatrix(K[0].Count, PT[0].Count);

            int i = 0;
            while (i < K.Count)
            {
                int j = 0;
                while (j < PT[0].Count)
                {
                    int u = 0;
                    while (u < K.Count)
                    {
                        result[i][j] = add(result[i][j], multiple(K[i][u], PT[u][j]));
                        u++;
                    }
                    j++;
                }
                i++;
            }

            return result;
        }
        private int GetMatrixdet(List<List<int>> Key)
        {
            int det = 0;
            if (Key.Count == 2)
            {
                det = subtract(multiple(Key[0][0], Key[1][1]), multiple(Key[0][1], Key[1][0]));
            }
            else
            {
                int d1 = subtract(multiple(Key[1][1], Key[2][2]), multiple(Key[2][1], Key[1][2]));
                int d2 = subtract(multiple(Key[1][0], Key[2][2]), multiple(Key[2][0], Key[1][2]));
                int d3 = subtract(multiple(Key[1][0], Key[2][1]), multiple(Key[2][0], Key[1][1]));
                det = subtract(add(Key[0][0] * d1, Key[0][2] * d3), Key[0][1] * d2);


            }
            return det;
        }
        private List<List<int>> GetMatrix(List<List<int>> Key)
        {
            int keysize = Key.Count;

            List<List<int>> nkey = initializeMatrix(keysize, keysize);

            if (keysize == 2)
            {
                int det = GetMatrixdet(Key);
                int multipleiv = Gmultiplediv(det);
                // Apply the modular multiplication to each element of the key matrix

                for (int i = 0; i < keysize; ++i)
                {
                    for (int j = 0; j < keysize; ++j)
                    {
                        nkey[i][j] = multiple(multipleiv, Key[i][j]);
                    }
                }

            }
            else
            {
                // Apply the modular multiplication to each element of the key matrix

                int multipleiv = Gmultiplediv(GetMatrixdet(Key));
                for (int i = 0; i < keysize; ++i)
                {
                    for (int j = 0; j < keysize; ++j)
                    {
                        List<int> vals = new List<int>();
                        // Extract the submatrix by removing the ith row and jth column

                        for (int a = 0; a < Key.Count; ++a)
                        {
                            if (a == i) continue;
                            for (int b = 0; b < Key.Count; ++b)
                            {
                                if (b == j) continue;
                                vals.Add(Key[a][b]);
                            }
                        }
                        List<List<int>> newmatrix = CreateMatrixByKey(vals);
                        int newdet = subtract(multiple(newmatrix[0][0], newmatrix[1][1]), multiple(newmatrix[0][1], newmatrix[1][0]));

                        nkey[i][j] = multiple(multiple(multipleiv, (int)Math.Pow(-1, i + j)), newdet);
                        nkey[i][j] = (nkey[i][j] + 26) % 26;

                    }
                }

            }

            List<List<int>> result = initializeMatrix(nkey.Count, nkey.Count);
            if (nkey.Count == 2)
            {
                result[1][0] = ((nkey[1][0] * -1) + 26) % 26;
                result[0][1] = ((nkey[0][1] * -1) + 26) % 26;
                result[0][0] = nkey[1][1];
                result[1][1] = nkey[0][0];

            }
            else
            {
                for (int i = 0; i < nkey.Count; ++i)
                {
                    for (int j = 0; j < nkey.Count; ++j)
                    {
                        result[j][i] = nkey[i][j];
                    }
                }
            }

            return result;


        }

        private int Gmultiplediv(int det)
        {
            int result = -1;
            int i = 1;
            while (i < 26)
            {
                if ((i * det) % 26 == 1)
                {
                    result = i;
                    break;
                }
                i++;
            }

            return result;
        }
        private bool IsCorrect(List<List<int>> Key)
        {

            int i = 0;
            while (i < Key.Count)
            {
                int j = 0;
                while (j < Key.Count)
                {
                    if (Key[i][j] >= 26 || Key[i][j] < 0)
                    {
                        return false;
                    }
                    j++;
                }
                i++;
            }
            int GMD = GetMatrixdet(Key);
            if (GMD == 0 || GCD(GMD, 26) != 1 || Gmultiplediv(GMD) == -1)
                return false;

            return true;
        }

        private List<List<int>> initializeMatrix(int row, int collom)
        {
            List<List<int>> result = new List<List<int>>();
            int i = 0;
            while (i < row)
            {
                result.Add(new List<int>());

                int j = 0;
                while (j < collom)
                {
                    result[i].Add(0);
                    j++;
                }

                i++;
            }

            return result;
        }
        private List<int> StringToList(string text)
        {
            List<int> result = new List<int>();
            foreach (char element in text)
            {
                result.Add((int)(element - 'A'));
            }
            return result;
        }
        private string ListToString(List<int> list)
        {
            string result = "";
            foreach (int element in list)
            {

                result += Convert.ToChar('A' + element);
            }
            return result;
        }

        private int GCD(int m, int n)
        {
            return n == 0 ? m : GCD(n, m % n);
        }

        private int multiple(int m, int n)
        {
            return (((m * n) % 26) + 26) % 26;
        }
        private int add(int m, int n)
        {
            return (n + m + 26) % 26;
        }
        private int subtract(int m, int n)
        {
            return ((m - n) % 26 + 26) % 26;
        }
    }
}
